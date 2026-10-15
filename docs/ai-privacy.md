# AI privacy

This document describes exactly what leaves the machine when AI analysis is
enabled, what never leaves it, and how to turn the feature off.

## AI is optional and off-switchable

```bash
scapy-ai analyze capture.pcap --no-ai
```

With `--no-ai`, no network request is made at all. The provider object is never
called. Field extraction, flow analysis, statistics, rules, and both reports run
exactly as they do otherwise.

AI is also skipped when the provider is unconfigured or unavailable. In every
case the deterministic results are kept and the report states that AI did not
produce a validated finding.

## What is sent

The request contains a structured summary only:

| Included | Description |
| --- | --- |
| Session metadata | Session identifier, source name, source type, capture format, timestamps |
| Packet totals | Packet count, byte count, duration, rate, parse status counts |
| Protocol and transport counts | Counts per protocol and per transport |
| Top talkers and ports | Most frequent source/destination addresses and ports |
| TCP flag totals | Aggregate counts per flag |
| DNS summary | Query count, response count, NXDOMAIN count, most frequent query names |
| Host volume outliers | Hosts whose byte volume is a statistical outlier within the capture |
| Flow summaries | Per-flow endpoints, protocol, packet and byte counts, duration, flag counts |
| Rule alerts | Identifier, rule, severity, description, reason, metrics, limitations |
| Selected packet fields | A bounded sample of normalized fields such as addresses, ports, flags, and protocol names |

## What is never sent

- **Raw packet payloads.** The payload bytes are not included, even when the
  capture contains cleartext HTTP or DNS.
- **Credentials.** API keys, tokens, and passwords are never part of the request.
- **Whole captures.** Packets are never uploaded; only the bounded summary above.
- **Any packet beyond the sample cap.** `ai.max_evidence_packets` bounds how many
  packets contribute fields.

The request records `raw_payloads_included: false`, and the test suite asserts
that payload content does not appear in the request.

## Size limits

`ai.max_prompt_bytes` caps the entire request. When the summary is too large,
the builder drops evidence samples progressively, then reduces the statistics
detail, and records that the request was truncated. The limit is enforced before
the request is sent, and a violation is logged rather than sent anyway.

## Untrusted data handling

Packet-derived text can contain anything, including text shaped like
instructions. The request therefore:

- wraps all packet-derived data in an explicit untrusted-data block,
- states in the system prompt that this block is data and never instructions,
- instructs the model to ignore any instructions found inside it.

The response is treated as untrusted in turn. If model output contains
instruction-like text, the finding is flagged with
`possible_prompt_injection_in_output`. If the model returns an evidence
reference that does not exist in the session, the reference is removed and the
removal is recorded.

## Credentials

The API key is read from the `SCAPY_AI_API_KEY` environment variable. It is:

- never written to a report,
- never written to a log, where a redaction filter masks common credential
  shapes,
- never written back out when configuration is serialized; only
  `api_key_set: true` appears.

## Reducing exposure further

- Use `--redact-ips` and `--redact-macs` to mask private addresses and device
  MAC parts before the summary is built.
- Lower `ai.max_evidence_packets` and `ai.max_prompt_bytes` to send less.
- Use a local or self-hosted OpenAI-compatible endpoint by setting
  `SCAPY_AI_BASE_URL`, so nothing leaves your network.
- Use `--no-ai` when interpretation is not needed.

## Provider disclosure

The report records the provider name, the model name, and the relevant analysis
settings, so a result can be reproduced. It never records the credential.
