"""Shared test fixtures.

All captures used by the tests are generated locally by
``tools/generate_test_pcaps.py`` into a temporary directory. Tests never depend
on network access, an API key, or a checked-in capture file.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "tools"))

from generate_test_pcaps import (  # noqa: E402
    build_basic_tcp_udp_dns,
    build_clean_capture,
    build_dns_burst,
    build_injection_attempt,
    build_port_scan,
)
from scapy.utils import wrpcap  # noqa: E402


@pytest.fixture(scope="session")
def fixture_dir(tmp_path_factory) -> Path:
    """Generate every synthetic capture once per test session."""
    directory = tmp_path_factory.mktemp("pcaps")
    builders = {
        "basic.pcap": build_basic_tcp_udp_dns,
        "port_scan.pcap": build_port_scan,
        "dns_burst.pcap": build_dns_burst,
        "clean.pcap": build_clean_capture,
        "injection.pcap": build_injection_attempt,
    }
    for name, builder in builders.items():
        wrpcap(str(directory / name), builder())
    return directory


@pytest.fixture(scope="session")
def basic_pcap(fixture_dir: Path) -> Path:
    return fixture_dir / "basic.pcap"


@pytest.fixture(scope="session")
def scan_pcap(fixture_dir: Path) -> Path:
    return fixture_dir / "port_scan.pcap"


@pytest.fixture(scope="session")
def dns_pcap(fixture_dir: Path) -> Path:
    return fixture_dir / "dns_burst.pcap"


@pytest.fixture(scope="session")
def clean_pcap(fixture_dir: Path) -> Path:
    return fixture_dir / "clean.pcap"


@pytest.fixture(scope="session")
def injection_pcap(fixture_dir: Path) -> Path:
    return fixture_dir / "injection.pcap"


@pytest.fixture()
def default_config(tmp_path: Path):
    """An AppConfig pointed at a temporary output directory."""
    from scapy_ai_analyzer.config import AppConfig

    config = AppConfig()
    config.report.output_dir = str(tmp_path / "results")
    return config
