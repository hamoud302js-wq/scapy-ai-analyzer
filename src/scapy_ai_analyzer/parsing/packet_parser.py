"""Packet field extraction using Scapy.

This module converts a Scapy packet into a :class:`PacketRecord`. It never
assumes a protocol is present: every lookup is guarded, and anything that is
absent stays ``None``.

The extraction is intentionally conservative. It records what the bytes say and
adds a warning when something is malformed, rather than raising and aborting the
whole capture.
"""

from __future__ import annotations

from typing import Any, Optional

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.packet import Packet, Raw

from ..models.packet import (
    PARSE_FAILED,
    PARSE_OK,
    PARSE_PARTIAL,
    PacketRecord,
    normalize_ip,
)

# TCP flag bit values, mirrored from the wire format.
TCP_FLAG_BITS = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
]

DNS_TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    255: "ANY",
    257: "CAA",
}

DNS_RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

IP_PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
}

# ICMP types that indicate an unreachable/diagnostic response.
ICMP_DIAGNOSTIC_TYPES = {3, 5, 8, 11}

HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")


def _safe_get(packet: Packet, attribute: str, default: Any = None) -> Any:
    """Read a Scapy field without raising on malformed packets."""
    try:
        return getattr(packet, attribute, default)
    except (AttributeError, IndexError, ValueError, TypeError):
        return default


def decode_tcp_flags(flags: Any) -> tuple[Optional[str], Optional[int]]:
    """Return ``(names, integer)`` for a TCP flags field.

    Scapy's ``FlagValue`` stringifies to the short form (``"SA"``), so the
    integer value is decoded directly rather than parsed from the string.
    """
    if flags is None:
        return None, None
    try:
        value = int(flags)
    except (TypeError, ValueError):
        return str(flags), None
    names = [name for bit, name in TCP_FLAG_BITS if value & bit]
    return ",".join(names), value


def _as_layer_list(value: Any) -> list:
    """Normalize a Scapy field that may be a list or a chained packet.

    Scapy 2.8 changed the DNS question/answer fields (``qd``, ``an``) to
    ``PacketListField``, while earlier versions exposed a single packet whose
    ``payload`` chained to the next. Both shapes are handled here.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return [item for item in value if item is not None]
    # Legacy shape: a packet chained through ``payload``.
    items: list = []
    current = value
    while current is not None and len(items) < 64:
        items.append(current)
        current = _safe_get(current, "payload")
    return items


def _extract_dns(record: PacketRecord, dns: DNS) -> None:
    """Fill DNS fields from a DNS layer."""
    try:
        record.dns_id = _safe_get(dns, "id")
        qr = _safe_get(dns, "qr")
        record.dns_is_response = bool(qr) if qr is not None else None

        rcode = _safe_get(dns, "rcode")
        if rcode is not None:
            record.dns_rcode = DNS_RCODE_NAMES.get(int(rcode), f"RCODE{int(rcode)}")

        questions = _as_layer_list(_safe_get(dns, "qd"))
        if questions:
            question = questions[0]
            qname = _safe_get(question, "qname")
            if qname is not None:
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="replace")
                record.dns_query = str(qname).rstrip(".")
            qtype = _safe_get(question, "qtype")
            if qtype is not None:
                record.dns_query_type = DNS_TYPE_NAMES.get(int(qtype), f"TYPE{int(qtype)}")

        if record.dns_is_response:
            record.dns_answers = _collect_dns_answers(dns)
    except Exception as exc:  # noqa: BLE001 - malformed DNS must not abort the run
        record.parse_warnings.append(f"dns_parse_error: {exc.__class__.__name__}")
        record.parse_status = PARSE_PARTIAL


def _collect_dns_answers(dns: DNS, max_answers: int = 32) -> list[str]:
    """Extract answer records as readable strings."""
    answers: list[str] = []
    for rr in _as_layer_list(_safe_get(dns, "an"))[:max_answers]:
        try:
            if not isinstance(rr, DNSRR):
                continue
            rrname = _safe_get(rr, "rrname")
            rdata = _safe_get(rr, "rdata")
            rtype = _safe_get(rr, "type")
            if isinstance(rrname, bytes):
                rrname = rrname.decode("utf-8", errors="replace")
            if isinstance(rdata, bytes):
                rdata = rdata.decode("utf-8", errors="replace")
            type_name = DNS_TYPE_NAMES.get(int(rtype), f"TYPE{int(rtype)}") if rtype is not None else "?"
            answers.append(f"{str(rrname).rstrip('.')} {type_name} {rdata}")
        except Exception:  # noqa: BLE001 - skip an unreadable answer record
            continue
    return answers


def _extract_http(record: PacketRecord, raw: Raw) -> None:
    """Extract request-line metadata from a cleartext HTTP payload.

    Only the first line and a few headers are read. Bodies are never stored.
    """
    try:
        data = bytes(raw.load)
    except Exception:  # noqa: BLE001
        return
    if not data:
        return

    first_line_end = data.find(b"\r\n")
    if first_line_end == -1:
        return
    first_line = data[:first_line_end]

    if any(first_line.startswith(method) for method in HTTP_METHODS):
        try:
            parts = first_line.split(b" ")
            record.http_method = parts[0].decode("ascii", errors="replace")
            if len(parts) > 1:
                record.http_uri = parts[1].decode("utf-8", errors="replace")[:512]
        except Exception:  # noqa: BLE001
            return
    elif first_line.startswith(b"HTTP/"):
        try:
            parts = first_line.split(b" ")
            if len(parts) > 1:
                record.http_status = int(parts[1])
        except (ValueError, IndexError):
            return
    else:
        return

    header_block = data[: min(len(data), 4096)].split(b"\r\n\r\n", 1)[0]
    for line in header_block.split(b"\r\n")[1:]:
        lowered = line.lower()
        if lowered.startswith(b"host:"):
            record.http_host = line[5:].strip().decode("utf-8", errors="replace")[:256]
        elif lowered.startswith(b"user-agent:"):
            record.http_user_agent = line[11:].strip().decode("utf-8", errors="replace")[:256]


def _extract_tls(record: PacketRecord, packet: Packet) -> None:
    """Read TLS handshake metadata (SNI, version) without any decryption."""
    try:
        from scapy.layers.tls.handshake import (  # imported lazily: optional extra
            TLSClientHello,
            TLSHandshake,
        )
    except Exception:  # noqa: BLE001 - TLS layer support is optional
        return

    try:
        layer = packet.getlayer(TLSClientHello)
        if layer is not None:
            record.tls_handshake_type = "ClientHello"
            server_names = _safe_get(layer, "ext")
            sni = None
            if server_names is not None:
                for ext in server_names:
                    ext_type = _safe_get(ext, "type")
                    if ext_type == 0:  # server_name extension
                        names = _safe_get(ext, "servernames")
                        if names:
                            sni = _safe_get(names[0], "servername")
                            break
            if sni:
                if isinstance(sni, bytes):
                    sni = sni.decode("utf-8", errors="replace")
                record.tls_sni = str(sni)[:256]
            version = _safe_get(layer, "version")
            if version is not None:
                record.tls_version = str(version)
            return

        handshake = packet.getlayer(TLSHandshake)
        if handshake is not None:
            htype = _safe_get(handshake, "type")
            record.tls_handshake_type = {1: "ClientHello", 2: "ServerHello"}.get(
                htype, f"type_{htype}"
            )
    except Exception:  # noqa: BLE001
        record.parse_warnings.append("tls_parse_error")


def parse_packet(
    packet: Packet,
    packet_id: int,
    source_type: str,
    source_ref: Optional[str] = None,
    frame_number: Optional[int] = None,
) -> PacketRecord:
    """Convert one Scapy packet into a normalized :class:`PacketRecord`.

    Malformed packets yield a record with ``parse_status='failed'`` and a
    warning instead of an exception, so one bad frame cannot abort a capture.
    """
    try:
        timestamp = float(packet.time)
    except (AttributeError, TypeError, ValueError):
        timestamp = 0.0

    try:
        captured_length = int(len(packet))
    except Exception:  # noqa: BLE001
        captured_length = 0

    record = PacketRecord(
        packet_id=packet_id,
        timestamp=timestamp,
        source_type=source_type,
        source_ref=source_ref,
        frame_number=frame_number if frame_number is not None else packet_id,
        captured_length=captured_length,
        original_length=_safe_get(packet, "wirelen"),
    )

    try:
        _extract_layers(record, packet)
    except Exception as exc:  # noqa: BLE001 - one bad packet must not stop analysis
        record.parse_status = PARSE_FAILED
        record.parse_warnings.append(f"parse_failure: {exc.__class__.__name__}: {exc}")

    if record.parse_status == PARSE_OK and record.parse_warnings:
        record.parse_status = PARSE_PARTIAL

    return record


def _extract_layers(record: PacketRecord, packet: Packet) -> None:
    """Populate protocol fields layer by layer, in encapsulation order."""
    _extract_ethernet(record, packet)
    _extract_network(record, packet)
    _extract_transport(record, packet)
    _extract_application(record, packet)


def _extract_ethernet(record: PacketRecord, packet: Packet) -> None:
    eth = packet.getlayer(Ether)
    if eth is None:
        return
    record.protocols.append("Ethernet")
    record.eth_src = _safe_get(eth, "src")
    record.eth_dst = _safe_get(eth, "dst")
    etype = _safe_get(eth, "type")
    record.eth_type = int(etype) if etype is not None else None

    vlan = packet.getlayer(Dot1Q)
    if vlan is not None:
        record.protocols.append("VLAN")
        vlan_id = _safe_get(vlan, "vlan")
        priority = _safe_get(vlan, "prio")
        record.vlan_id = int(vlan_id) if vlan_id is not None else None
        record.vlan_priority = int(priority) if priority is not None else None


def _extract_network(record: PacketRecord, packet: Packet) -> None:
    ipv4 = packet.getlayer(IP)
    ipv6 = packet.getlayer(IPv6)

    if ipv4 is not None:
        record.network_layer = "IPv4"
        record.ip_version = 4
        record.protocols.append("IPv4")
        record.src_ip = normalize_ip(_safe_get(ipv4, "src"))
        record.dst_ip = normalize_ip(_safe_get(ipv4, "dst"))
        ttl = _safe_get(ipv4, "ttl")
        record.ttl = int(ttl) if ttl is not None else None
        proto = _safe_get(ipv4, "proto")
        record.ip_protocol = int(proto) if proto is not None else None
        record.ip_protocol_name = IP_PROTOCOL_NAMES.get(record.ip_protocol, f"proto_{record.ip_protocol}")
        length = _safe_get(ipv4, "len")
        record.ip_length = int(length) if length is not None else None
        record.ip_flags = str(_safe_get(ipv4, "flags")) if _safe_get(ipv4, "flags") is not None else None
    elif ipv6 is not None:
        record.network_layer = "IPv6"
        record.ip_version = 6
        record.protocols.append("IPv6")
        record.src_ip = normalize_ip(_safe_get(ipv6, "src"))
        record.dst_ip = normalize_ip(_safe_get(ipv6, "dst"))
        hlim = _safe_get(ipv6, "hlim")
        record.ttl = int(hlim) if hlim is not None else None
        nh = _safe_get(ipv6, "nh")
        record.ip_protocol = int(nh) if nh is not None else None
        record.ip_protocol_name = IP_PROTOCOL_NAMES.get(record.ip_protocol, f"proto_{record.ip_protocol}")
        plen = _safe_get(ipv6, "plen")
        record.ip_length = int(plen) if plen is not None else None
    else:
        arp = packet.getlayer(ARP)
        if arp is not None:
            record.network_layer = "ARP"
            record.protocols.append("ARP")
            record.arp_op = _safe_get(arp, "op")
            record.arp_psrc = normalize_ip(_safe_get(arp, "psrc"))
            record.arp_pdst = normalize_ip(_safe_get(arp, "pdst"))
            record.src_ip = record.arp_psrc
            record.dst_ip = record.arp_pdst
        else:
            record.parse_warnings.append("no_network_layer")


def _extract_transport(record: PacketRecord, packet: Packet) -> None:
    tcp = packet.getlayer(TCP)
    udp = packet.getlayer(UDP)
    icmp = packet.getlayer(ICMP)

    if tcp is not None:
        record.transport_protocol = "TCP"
        record.protocols.append("TCP")
        record.src_port = _safe_get(tcp, "sport")
        record.dst_port = _safe_get(tcp, "dport")
        flags = _safe_get(tcp, "flags")
        names, value = decode_tcp_flags(flags)
        record.tcp_flags = names
        record.tcp_flags_int = value
        record.tcp_seq = _safe_get(tcp, "seq")
        record.tcp_ack = _safe_get(tcp, "ack")
        record.tcp_window = _safe_get(tcp, "window")
        payload = _safe_get(tcp, "payload")
        if payload is not None:
            try:
                record.payload_length = len(bytes(payload))
            except Exception:  # noqa: BLE001
                record.payload_length = None
    elif udp is not None:
        record.transport_protocol = "UDP"
        record.protocols.append("UDP")
        record.src_port = _safe_get(udp, "sport")
        record.dst_port = _safe_get(udp, "dport")
        ulen = _safe_get(udp, "len")
        if ulen is None:
            # Scapy only fills the length field when it is set explicitly or
            # parsed from the wire; recompute it from the actual payload size.
            try:
                ulen = 8 + len(bytes(_safe_get(udp, "payload")))
            except Exception:  # noqa: BLE001
                ulen = None
        record.udp_length = int(ulen) if ulen is not None else None
    elif icmp is not None:
        record.transport_protocol = "ICMP"
        record.protocols.append("ICMP")
        record.icmp_type = _safe_get(icmp, "type")
        record.icmp_code = _safe_get(icmp, "code")
        record.icmp_id = _safe_get(icmp, "id")
        record.icmp_seq = _safe_get(icmp, "seq")
    elif record.network_layer in ("IPv4", "IPv6"):
        # ARP and other non-IP frames legitimately have no transport layer.
        record.parse_warnings.append("no_transport_layer")


def _extract_application(record: PacketRecord, packet: Packet) -> None:
    dns = packet.getlayer(DNS)
    if dns is not None:
        record.protocols.append("DNS")
        _extract_dns(record, dns)

    raw = packet.getlayer(Raw)
    if raw is None:
        return

    if record.transport_protocol != "TCP":
        return

    http_ports = (80, 8080)
    if record.src_port in http_ports or record.dst_port in http_ports:
        _extract_http(record, raw)
        if record.http_method or record.http_status:
            record.protocols.append("HTTP")
    elif record.dst_port == 443:
        _extract_tls(record, packet)
        if record.tls_sni:
            record.protocols.append("TLS")
