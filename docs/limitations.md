# Limitations

This project reports what a capture shows. It is deliberately conservative about
what can be concluded, and this document records those limits.

## The central limitation

An indicator is not a verdict. Every rule alert states what was observed and
then states why that observation alone is insufficient. For example:

- **Observed**: one source contacted 15 distinct destination ports within 60
  seconds.
- **Not concluded**: this is a port scan.

The same pattern is produced by monitoring systems, load balancers, proxies,
vulnerability scanners, and ordinary application behaviour. Distinguishing them
requires context this tool does not have: the expected baseline for the network,
the identity of the source, and whether the connections succeeded.

## Capture scope

- Analysis covers only the packets present in the capture. Activity before or
  after the window is invisible.
- A capture that began mid-session is missing earlier packets. A handshake may
  appear incomplete simply because its start was not recorded.
- Packet loss during live capture can create apparent anomalies, such as
  incomplete handshakes or unusual retransmission patterns.
- Encrypted payloads are not inspected. Only metadata is analysed, so the
  content of TLS traffic is unknown to this tool.

## Flow analysis

- Flows are keyed by endpoints, ports, and transport protocol, with an idle
  timeout. Two genuinely separate sessions that reuse the same key within the
  timeout are merged into one flow.
- Packets without transport-layer ports, such as some ICMP and non-TCP/UDP IP
  traffic, are not assigned to a flow. They are still counted in statistics and
  are reported as unassigned rather than silently dropped.
- Byte counts reflect captured length, not necessarily the full frame length if
  a snaplen was applied.

## Statistics

- Host volume outliers are computed within a single capture, comparing hosts to
  each other. This is not a comparison against a historical baseline.
- The z-score test has a mathematical ceiling: for `n` observations the maximum
  attainable z-score is `sqrt(n-1)`. The test is skipped entirely below four
  hosts, and even at ten hosts a z-score of 3.0 is only just reachable, so small
  captures will rarely report an outlier.
- Rate calculations depend on capture timestamps. A capture assembled from
  multiple sources or with irregular timestamps will produce misleading rates.

## Rule engine

- Rules are threshold-based. A threshold that suits one network will produce
  false positives or false negatives on another. Thresholds are configurable for
  this reason.
- Rules evaluate only what the deterministic stages produced. If flow grouping
  or parsing was wrong, the rules inherit that error.
- A rule that raises an exception is contained and reported as an `info` alert
  naming the failure. That alert is a software fault report, not a security
  indicator.
- Severity reflects how much attention the pattern warrants, not how likely it
  is to be malicious.

## AI interpretation

- Model output is a language-model interpretation of a summary, not an
  independent analysis of the packets. It cannot know anything the summary does
  not contain.
- Confidence values are self-reported by the model. They are not calibrated
  probabilities and must not be read as such. The report labels them
  accordingly.
- Evidence references are validated: the model cannot cite a packet, flow, or
  alert that does not exist in the session. References that do not resolve are
  removed, and the removal is recorded as a warning.
- A model can still be wrong while citing valid evidence. The interpretation
  requires human verification, and the report marks it as such.
- When the model does not return valid output, the finding is rejected and the
  deterministic results stand. The report states that AI did not produce a
  validated finding.
- The same capture analysed twice may produce different AI wording. The
  deterministic stages are reproducible; the model's phrasing is not.

## What this tool does not do

- It does not exploit vulnerabilities.
- It does not send, modify, or block packets.
- It does not act as an intrusion prevention system.
- It does not decrypt TLS without keys and authorization.
- It does not determine intent, attribution, or whether an incident occurred.

## Appropriate use

Use the output to decide where to look next, and to have a defensible,
evidence-linked record of what the capture showed. Do not use a rule alert, and
especially not an AI finding, as a standalone basis for accusing a host or a
person of malicious activity.
