# Scapy AI Analyzer

Evidence-based network packet analysis. Scapy reads the packets, a deterministic
rule engine derives indicators, and an optional AI layer interprets the results
while citing evidence that actually exists in the capture.

```
Capture Packets -> Extract Fields -> Normalize Data -> Analyze Flows
  -> Detect Indicators -> AI Analysis -> Evidence-Based Reports
```

The AI is an interpretation layer, not the analyser. Every deterministic stage
runs and produces a complete report even when AI is disabled, unavailable, or
returns something invalid.

## What this tool is not

This is a passive analysis and monitoring tool. It does not exploit
vulnerabilities, send or modify packets, block traffic, act as an IPS, decrypt
TLS, or send raw packet payloads to an AI provider by default.

## Requirements

- Python 3.10 or newer
- Scapy 2.5 or newer (tested against 2.8.0)
- PyYAML 6.0 or newer

Live capture additionally needs root or the `CAP_NET_RAW`/`CAP_NET_ADMIN`
capabilities. File analysis needs no special privileges.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

For development, including the test suite:

```bash
pip install -e ".[dev]"
```

To use the OpenAI-compatible provider you also need the optional HTTP client:

```bash
pip install -e ".[openai]"
```

## Quick start

Analyse a capture file. The report is written to a new session directory:

```bash
scapy-ai analyze capture.pcap --output results/
```

Run without AI, producing the same deterministic analysis and report:

```bash
scapy-ai analyze capture.pcap --no-ai --output results/
```

Inspect the results of a completed session:

```bash
scapy-ai inspect results/<session-id>/ --summary
scapy-ai inspect results/<session-id>/ --alert alert-0001
scapy-ai inspect results/<session-id>/ --packet 42
```

Regenerate reports from a stored session:

```bash
scapy-ai report results/<session-id>/ --output rebuilt/ --formats json,html
```

Live capture, which requires explicit confirmation:

```bash
scapy-ai capture --list-interfaces
scapy-ai capture --interface eth0 --duration 60 --yes --output results/
```

## Commands

| Command | Purpose |
| --- | --- |
| `analyze <file>` | Analyze a PCAP/PCAPNG file through the full pipeline |
| `capture` | Passive live capture on an interface |
| `inspect <session>` | Show a summary, alert, flow, or packet from a stored session |
| `report <session>` | Rebuild JSON/HTML reports from a stored session |
| `rules list` | List the detection rules and their stated limitations |
| `doctor` | Check the environment, libraries, privileges, and AI settings |
| `version` | Print the version |

Exit codes: `0` success, `2` usage or configuration error, `3` environment
error such as missing privileges or an unreadable capture.

## Pipeline stages

1. **Capture** reads a PCAP/PCAPNG file incrementally, or sniffs a live
   interface passively. Each packet keeps its source and frame number.
2. **Parsing** extracts protocol fields with Scapy and normalizes them into a
   single `PacketRecord` shape. Missing fields stay empty; nothing is invented.
3. **Flow analysis** groups related packets into bidirectional flows and
   computes per-direction counts and byte totals.
4. **Statistics** summarises protocols, ports, talkers, DNS activity, and
   per-host volume.
5. **Rule engine** turns the deterministic analysis into alerts. Each alert
   carries an identifier, the triggering reason, the evidence references, and
   the limits of what it can conclude.
6. **AI analysis** (optional) receives a bounded, structured summary and returns
   a validated finding. Every evidence reference it returns is checked against
   the session; invented references are removed.
7. **Reports** write a JSON report for tooling and an HTML report for reading,
   with observed data, rule alerts, AI interpretation, and human-verification
   items visually separated.

## Detection rules

| ID | Name | Severity |
| --- | --- | --- |
| R001 | Multiple destination ports contacted in a short window | medium |
| R002 | High connection fan-out to distinct destinations | medium |
| R003 | High DNS query rate from a single source | low |
| R004 | Elevated NXDOMAIN response ratio | low |
| R005 | Incomplete TCP handshakes | low |
| R006 | Malformed or unparsable packets | info |
| R007 | Host traffic volume outlier | info |
| R008 | Elevated TCP reset rate from one source | low |
| R009 | ICMP diagnostic message burst | low |

Thresholds are configurable; run `scapy-ai rules list` to see the full
definitions and limitations.

An alert states what was observed. It is an indicator for review, not a verdict.
For example, "one source contacted many destination ports" is supported by the
capture, while "this is a confirmed port scan" needs context the capture alone
does not provide.

## Configuration

Defaults live in `config/default.yaml`. Every value can be overridden from the
command line or with a `--config` file.

```yaml
capture:
  batch_size: 5000       # packets processed per batch
  max_packets: null      # optional cap on packets read
  duration: null         # live capture duration in seconds
  interface: null

ai:
  enabled: true
  provider: mock         # mock or openai_compatible
  model: null
  language: en           # en or ar
  timeout_seconds: 30
  max_retries: 2
  max_prompt_bytes: 200000
  max_evidence_packets: 25

privacy:
  redact_private_ips: false
  redact_mac_addresses: false

report:
  formats: [json, html]
  output_dir: results
```

## AI providers

The AI layer sits behind one interface, so the rest of the pipeline never
depends on a specific vendor.

- `mock` is the default. It is deterministic, offline, and returns a
  schema-valid response built only from the supplied summary. It is used by the
  test suite and is useful for verifying the pipeline without network access.
- `openai_compatible` calls any OpenAI-compatible chat completions endpoint.

```bash
export SCAPY_AI_API_KEY="..."
scapy-ai analyze capture.pcap --provider openai_compatible --model gpt-4o-mini
```

The API key is read from the `SCAPY_AI_API_KEY` environment variable. It is
never written to a report, a log, or the repository.

### What is sent to a provider

Only a structured summary is sent: session metadata, packet and protocol counts,
flow summaries, rule alerts, and a small bounded set of selected packet fields.
Raw payload bytes are not included by default. The request is capped by
`ai.max_prompt_bytes`, and the model is instructed to treat all packet-derived
data as untrusted data rather than instructions.

See `docs/ai-privacy.md` for the full description.

## Output

Each run creates its own session directory, so a new analysis never overwrites a
previous one:

```
results/<session-id>/
  report.json     # structured results for tooling
  report.html     # readable report
```

The JSON report includes a `provenance_legend` marking which sections are
observed data, rule output, AI interpretation, or items needing human review.

## Testing

```bash
python3 -m pytest
```

The suite runs entirely offline with the mock provider and needs no API key. It
generates its own small capture fixtures. Live capture tests are skipped unless
the tests run as root.

Generate the test captures explicitly:

```bash
python3 tools/generate_test_pcaps.py
```

## Documentation

- `docs/architecture.md` — module responsibilities and data flow
- `docs/installation.md` — setup and verification
- `docs/usage.md` — command reference and worked examples
- `docs/ai-privacy.md` — what leaves the machine and what never does
- `docs/limitations.md` — what the tool cannot conclude, and why

## License

MIT. See `LICENSE`.
