# Usage

## Analyzing a capture file

```bash
scapy-ai analyze capture.pcap --output results/
```

Each run writes to its own session directory:

```
results/20261015T151847Z-007a8916/
  report.json
  report.html
```

The command prints the packet count, byte count, flow count, alert count, the AI
status, and the report paths. Exit code `0` means the deterministic analysis
completed, whether or not the AI layer produced a finding.

## Disabling AI

```bash
scapy-ai analyze capture.pcap --no-ai --output results/
```

The field extraction, flow analysis, statistics, rules, and both reports are
identical. The report records that AI was disabled and that the deterministic
results remain valid.

## Selecting a provider

```bash
export SCAPY_AI_API_KEY="..."
scapy-ai analyze capture.pcap --provider openai_compatible --model gpt-4o-mini
```

The default provider is `mock`, which is deterministic, offline, and returns a
schema-valid response built only from the supplied summary.

## Limiting a run

```bash
scapy-ai analyze large.pcap --max-packets 5000 --batch-size 250
```

`--max-packets` caps how many packets are read; the session records that the
capture was truncated. `--batch-size` controls how many packets are processed at
a time.

## Arabic output

```bash
scapy-ai analyze capture.pcap --language ar
```

This changes the language the model is asked to write its summary in. It does
not translate the deterministic output.

## Inspecting a stored session

```bash
scapy-ai inspect results/<session-id>/ --summary
```

```
Session summary
  session_id: 20261015T151847Z-007a8916
  source: tests/fixtures/port_scan.pcap
  packet_count: 70
  packets_failed: 0
  flow_count: 70
  alert_count: 5
  statistics: {"packets": 70, "bytes": 3780, "duration_seconds": 3.45, ...}
  ai: {"enabled": true, "succeeded": true, "provider": "mock",
       "finding_type": "rule_indicator_review"}
```

An alert, including the reason it fired and the limits of what it shows:

```bash
scapy-ai inspect results/<session-id>/ --alert alert-0001
```

```
Alert alert-0001 (R001)
  rule:        Multiple destination ports contacted in a short window
  severity:    medium
  description: Source 192.0.2.10 contacted 15 distinct destination ports within 60 seconds.
  reason:      Observed 15 connection attempts from 192.0.2.10 across 15 distinct
               destination ports in a 60s window (threshold: 15 ports, 15 attempts).
  metrics:     {"distinct_dst_ports": 15, "attempts_in_window": 15, ...}
  evidence:    packet-1, packet-2, packet-3, ...
  limitations:
    - Distinct ports alone do not establish intent; load balancers, proxies, and
      monitoring tools produce the same pattern.
    - If the capture began mid-session, earlier packets from this source are absent.
    - UDP and TCP fan-out are evaluated separately and are not combined.
```

A single packet:

```bash
scapy-ai inspect results/<session-id>/ --packet 1
```

A flow:

```bash
scapy-ai inspect results/<session-id>/ --flow flow-0001
```

## Rebuilding reports

```bash
scapy-ai report results/<session-id>/ --output rebuilt/ --formats json,html
```

## Live capture

List interfaces:

```bash
scapy-ai capture --list-interfaces
```

Capture for 60 seconds, or until 5000 packets have been seen:

```bash
sudo scapy-ai capture --interface eth0 --duration 60 --yes --output results/
sudo scapy-ai capture --interface eth0 --max-packets 5000 --yes --output results/
```

`--yes` confirms that you are authorized to monitor the network. Without it the
command refuses to start. Without a duration or a packet limit the command also
refuses, so a capture cannot run unbounded.

A capture can be stopped at any time with Ctrl+C. The session is still written.

Apply a BPF filter to reduce noise:

```bash
sudo scapy-ai capture --interface eth0 --duration 30 --bpf "tcp port 443" --yes
```

## Listing rules

```bash
scapy-ai rules list
```

Prints every rule with its identifier, name, severity, description, and stated
limitations.

## Configuration

Use a configuration file:

```bash
scapy-ai analyze capture.pcap --config my-config.yaml
```

Or override individual values on the command line:

```bash
scapy-ai analyze capture.pcap --max-packets 1000 --provider mock --log-level DEBUG
```

Precedence is: command-line arguments, then environment variables, then the
configuration file, then built-in defaults.

## Privacy options

Redact private addresses and MAC addresses before they reach a report or an AI
provider:

```bash
scapy-ai analyze capture.pcap --redact-ips --redact-macs
```

Private IP addresses keep their last octet so flows stay distinguishable.
MAC addresses keep their vendor prefix. Both are marked in the report.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The analysis completed |
| 2 | Usage or configuration error |
| 3 | Environment error: missing privileges, unreadable capture, capture failure |
