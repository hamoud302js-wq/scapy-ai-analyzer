# Architecture

## Design rule

Each stage is an independent module. Packet capture never calls the AI layer,
and AI output never replaces packet analysis. The AI receives a summary that the
deterministic stages already produced and returns an interpretation that is
validated before it is stored.

```
Capture -> Parsing -> Normalization -> Flow Analysis -> Statistics
  -> Rule Engine -> Evidence Store -> AI Analysis -> Reports
```

Every stage after normalization works on the same data shapes, so any stage can
be tested in isolation without the ones around it.

## Module responsibilities

| Module | Responsibility |
| --- | --- |
| `capture` | Read PCAP/PCAPNG files incrementally, or sniff a live interface passively |
| `parsing` | Extract protocol fields with Scapy and normalize them into `PacketRecord` |
| `analysis` | Flows, statistics, and the deterministic rule engine |
| `ai` | Build the request, call the configured provider, validate the response |
| `evidence` | Index packets, flows, and alerts so any reference can be resolved |
| `reports` | Render JSON and HTML reports |
| `models` | Shared data types |
| `pipeline` | Wire the stages together and emit progress |
| `cli` | Parse arguments and format output |

## Data flow

### 1. Capture (`capture/`)

`file_reader.iter_packet_batches` reads a capture in batches and yields
`(batch, stats)`. It detects the format from the file header rather than the
extension, so a `.pcap` file that is really pcapng is still read correctly. It
validates the file first and raises `CaptureFileError` with a specific message
for an empty file, a missing file, or an unrecognized format.

`live_capture.LiveCapture` wraps Scapy's `AsyncSniffer`. It requires explicit
confirmation, a named interface, and a bound (duration or packet count).
Because `AsyncSniffer` opens its socket in a worker thread, a failure there
would otherwise look like a successful empty capture; `_wait_for_sniffer_start`
inspects the thread state and surfaces the real error.

### 2. Parsing and normalization (`parsing/`)

`packet_parser.parse_packet` walks the Scapy layer stack and fills a
`PacketRecord`. Each field is read through a guarded accessor, so a missing or
malformed layer yields an empty field and a recorded warning rather than an
exception. Optional fields stay `None`; nothing is filled with a guessed value.

`normalizer` applies privacy redaction and produces the serializable form used
by reports.

### 3. Flow analysis (`analysis/flow_analyzer.py`)

Packets are grouped by a direction-independent flow key of
`(ip_a, port_a, ip_b, port_b, protocol)`, with the lower endpoint first. A
reused key after an idle timeout starts a new flow, so long captures do not
merge unrelated sessions. Each flow records per-direction packet and byte
counts, TCP flag counts, and the contributing packet identifiers.

### 4. Statistics (`analysis/statistics.py`)

Counts protocols, transports, ports, talkers, DNS activity, parse status, and
per-host volume. Host volume outliers use a z-score against the other hosts in
the same capture, with a minimum host count so the test is meaningful. This
compares hosts within one capture, not against a historical baseline.

### 5. Rule engine (`analysis/rule_engine.py`)

Each rule is an object with a `RuleDefinition` (identifier, name, severity,
description, limitations) and an `evaluate(context)` method. A rule that raises
is contained: it produces one `info` alert naming the failure and the other
rules still run.

Rules separate the observation from the conclusion. R001 reports "one source
contacted N distinct destination ports within a window" and states that this
alone does not establish intent.

### 6. Evidence store (`evidence/evidence_store.py`)

Holds packets, flows, and alerts by identifier and resolves references of the
form `packet-<n>`, `flow-<n>`, `alert-<n>`. Identifiers remain valid even when
full packet detail is dropped past a size cap, so validation stays honest while
memory stays bounded.

### 7. AI analysis (`ai/`)

`prompt_builder` assembles a bounded summary: session metadata, counts, flow
summaries, alerts, and a limited set of packet fields. Raw payloads are
excluded. The payload is fenced in an explicit untrusted-data block.

`service.AIService` calls the provider, then `schema.validate_response` checks
the reply:

- the root must be a JSON object,
- required fields must be present and of the right type,
- `severity` must be one of the known values,
- `confidence`, when present, must be a number in `[0, 1]`,
- every evidence reference must resolve in the store; unresolvable ones are
  removed and the removal is recorded as a warning.

Anything that fails validation becomes a rejected finding. The deterministic
results are never discarded because the AI layer failed.

Providers implement `ai/base.AIProvider`. `mock_provider` is deterministic and
offline; `openai_provider` targets any OpenAI-compatible endpoint.

### 8. Reports (`reports/`)

`json_report` writes the machine-readable result, including a
`provenance_legend` that labels observed data, rule output, AI interpretation,
and human-verification items.

`html_report` escapes all interpolated text, so packet-derived strings cannot
inject markup, and renders the four categories with distinct visual tags.

## Why the AI layer is validated this way

A language model can produce a plausible finding that cites evidence which does
not exist. The pipeline therefore treats model output as untrusted input:

- references are resolved against the session and dropped when unknown,
- confidence is reported as a self-reported estimate, not a calibrated
  probability,
- packet-derived text is passed as data inside a fenced block, never as
  instructions,
- a response that does not validate becomes an explicit rejected finding.

## Extending the project

- **Add a rule**: implement `RuleDefinition` plus `evaluate`, then append it to
  `ALL_RULES`. Stated limitations are required.
- **Add a provider**: subclass `AIProvider` and register it in
  `ai/service.py`.
- **Add a report format**: add a module under `reports/` and register the format
  name in `config.py` validation.
