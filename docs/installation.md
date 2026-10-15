# Installation

## Requirements

- Python 3.10 or newer
- Scapy 2.5 or newer. This project is developed and tested against Scapy 2.8.0.
- PyYAML 6.0 or newer

Live capture additionally requires root or the `CAP_NET_RAW`/`CAP_NET_ADMIN`
capabilities. File analysis needs no special privileges and no network access.

## Install from the repository

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

For the test suite:

```bash
pip install -e ".[dev]"
```

For the OpenAI-compatible provider:

```bash
pip install -e ".[openai]"
```

## Verify the installation

```bash
scapy-ai version
scapy-ai doctor
```

`doctor` reports the Python version, Scapy and PyYAML availability, the resolved
configuration, whether the AI provider is reachable, whether capture privileges
are present, the interfaces it can see, and whether the output directory is
writable. It exits non-zero only when a blocking problem is found.

Example output on a machine without capture privileges:

```
Environment check

[OK  ] python: 3.13.15
[OK  ] scapy: 2.8.0
[OK  ] pyyaml: available
[OK  ] config: provider=mock ai_enabled=True output_dir=results
[OK  ] ai_provider: {"provider": "mock", "model": "mock-deterministic-v1", "available": true}
[WARN] capture_privileges: Not running as root. Raw capture usually requires root
       or CAP_NET_RAW/CAP_NET_ADMIN. On Linux you can grant the capability with
       setcap, or run the capture under sudo.
[OK  ] interfaces: lo, eth0
[OK  ] output_writable: /path/to/results

No blocking problems found.
```

## Running the tests

```bash
python3 -m pytest
```

The suite runs offline. It uses the deterministic mock provider and generates
its own capture fixtures, so no API key and no internet connection are needed.
Live capture tests are skipped unless the tests run as root.

To run the privileged tests:

```bash
sudo -E python3 -m pytest tests/unit/test_live_capture.py
```

## Live capture privileges

On Linux, grant the capability to the Python interpreter instead of running
everything as root:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(which python3)")"
```

Note that this affects every program using that interpreter, and the capability
is lost when the interpreter is upgraded. Running the capture step under `sudo`
is the more predictable option.

## Troubleshooting

**`Capture on <iface> could not start: PermissionError`**
The process cannot open a raw socket. Run under `sudo`, or grant the capability
as shown above.

**`Capture finished: 0 packets`**
The interface was idle during the window, or the capture filter excluded
everything. Confirm the interface with `scapy-ai capture --list-interfaces` and
check any `--bpf` filter.

**`Unrecognized capture format`**
The file is not PCAP or PCAPNG. The reader inspects the file header, so a file
with a `.pcap` extension but different contents is still rejected.

**`AI provider could not be initialized`**
The provider name is unknown or its optional dependency is missing. The
deterministic analysis still runs and the report is still written.

**`provider_not_configured`**
The selected provider is unavailable, most often because `SCAPY_AI_API_KEY` is
unset for `openai_compatible`.
