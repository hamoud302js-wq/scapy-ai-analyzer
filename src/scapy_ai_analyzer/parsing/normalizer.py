"""Normalization and privacy redaction for packet records.

Normalization guarantees that every downstream module sees records with the same
field semantics. Redaction is applied here, before records reach the AI layer or
a report, so raw payloads and sensitive fields cannot leak by accident.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, Iterator, Optional

from ..config import PrivacyConfig
from ..models.packet import PacketRecord, normalize_ip

# Ports whose DNS payload is very likely to carry sensitive names.
PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


def is_private_ip(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if address.is_loopback or address.is_link_local:
        return True
    return any(address in network for network in PRIVATE_NETWORKS)


def redact_ip(value: Optional[str]) -> Optional[str]:
    """Replace a private IP with a stable placeholder that preserves structure."""
    if not value:
        return value
    if not is_private_ip(value):
        return value
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    if address.version == 4:
        return f"10.x.x.{int(str(address).split('.')[-1])}"
    return "fd00::x"


def redact_mac(value: Optional[str]) -> Optional[str]:
    """Keep the OUI, mask the device-specific part."""
    if not value:
        return value
    parts = value.split(":")
    if len(parts) != 6:
        return "xx:xx:xx:xx:xx:xx"
    return ":".join(parts[:3] + ["xx", "xx", "xx"])


def normalize_record(record: PacketRecord) -> PacketRecord:
    """Apply canonical formatting and consistency fixes to one record."""
    record.src_ip = normalize_ip(record.src_ip)
    record.dst_ip = normalize_ip(record.dst_ip)
    if record.src_port is not None:
        record.src_port = int(record.src_port)
    if record.dst_port is not None:
        record.dst_port = int(record.dst_port)

    if record.src_ip and record.dst_ip:
        src_v6 = ":" in record.src_ip
        dst_v6 = ":" in record.dst_ip
        if src_v6 != dst_v6:
            # Mixed families indicate a malformed frame; flag it instead of guessing.
            record.parse_warnings.append("mixed_ip_families")
            if record.parse_status == "ok":
                record.parse_status = "partial"

    # De-duplicate protocol names while preserving encapsulation order.
    seen: set[str] = set()
    ordered: list[str] = []
    for name in record.protocols:
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    record.protocols = ordered
    return record


def apply_privacy(record: PacketRecord, privacy: PrivacyConfig) -> PacketRecord:
    """Redact fields according to the privacy configuration."""
    if privacy.redact_private_ips:
        record.src_ip = redact_ip(record.src_ip)
        record.dst_ip = redact_ip(record.dst_ip)
        record.arp_psrc = redact_ip(record.arp_psrc)
        record.arp_pdst = redact_ip(record.arp_pdst)
    if privacy.redact_mac_addresses:
        record.eth_src = redact_mac(record.eth_src)
        record.eth_dst = redact_mac(record.eth_dst)
    return record


def normalize_records(
    records: Iterable[PacketRecord],
    privacy: Optional[PrivacyConfig] = None,
) -> Iterator[PacketRecord]:
    """Stream-normalize records, optionally applying privacy redaction."""
    for record in records:
        normalized = normalize_record(record)
        if privacy is not None:
            normalized = apply_privacy(normalized, privacy)
        yield normalized
