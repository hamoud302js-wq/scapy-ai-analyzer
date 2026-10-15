"""Packet field extraction tests.

Covers the protocol matrix required by the spec: TCP, UDP, DNS, IPv4, IPv6,
optional layers that are absent, and packets that cannot be parsed.
"""

from __future__ import annotations

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.packet import Raw

from scapy_ai_analyzer.models.packet import PARSE_FAILED, PARSE_OK, PARSE_PARTIAL
from scapy_ai_analyzer.parsing.packet_parser import decode_tcp_flags, parse_packet


def _parse(packet, packet_id=1):
    return parse_packet(packet, packet_id=packet_id, source_type="file", source_ref="test")


class TestTcpExtraction:
    def test_tcp_syn_fields(self):
        packet = (
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
            / IP(src="192.0.2.1", dst="198.51.100.2", ttl=64)
            / TCP(sport=1234, dport=443, flags="S", seq=1000)
        )
        record = _parse(packet)

        assert record.parse_status == PARSE_OK
        assert record.transport_protocol == "TCP"
        assert record.src_ip == "192.0.2.1"
        assert record.dst_ip == "198.51.100.2"
        assert record.src_port == 1234
        assert record.dst_port == 443
        assert record.tcp_flags == "SYN"
        assert record.tcp_seq == 1000
        assert record.ttl == 64
        assert record.eth_src == "00:11:22:33:44:55"
        assert "Ethernet" in record.protocols
        assert "IPv4" in record.protocols
        assert "TCP" in record.protocols

    def test_tcp_flags_combinations(self):
        names, value = decode_tcp_flags(0x12)
        assert "SYN" in names and "ACK" in names
        assert value is not None and value & 0x02 and value & 0x10

        record = _parse(
            Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / TCP(flags=0x04)
        )
        assert record.tcp_flags == "RST"

    def test_udp_fields(self):
        packet = (
            Ether()
            / IP(src="192.0.2.1", dst="198.51.100.2")
            / UDP(sport=51000, dport=53)
            / Raw(load=b"data")
        )
        record = _parse(packet)
        assert record.transport_protocol == "UDP"
        assert record.src_port == 51000
        assert record.dst_port == 53
        assert record.udp_length is not None
        assert record.tcp_flags is None


class TestDnsExtraction:
    def test_dns_query(self):
        packet = (
            Ether()
            / IP(src="192.0.2.1", dst="198.51.100.2")
            / UDP(sport=51000, dport=53)
            / DNS(id=1, rd=1, qd=DNSQR(qname="example.test", qtype="A"))
        )
        record = _parse(packet)
        assert record.dns_query == "example.test"
        assert record.dns_query_type == "A"
        assert record.dns_is_response is False
        assert "DNS" in record.protocols

    def test_dns_response_with_answer(self):
        from scapy.layers.dns import DNSRR

        packet = (
            Ether()
            / IP(src="198.51.100.2", dst="192.0.2.1")
            / UDP(sport=53, dport=51000)
            / DNS(
                id=1,
                qr=1,
                qd=DNSQR(qname="example.test", qtype="A"),
                an=DNSRR(rrname="example.test", type="A", rdata="203.0.113.5"),
            )
        )
        record = _parse(packet)
        assert record.dns_is_response is True
        assert record.dns_answers
        assert "203.0.113.5" in record.dns_answers[0]
        assert record.dns_rcode == "NOERROR"

    def test_nxdomain_rcode(self):
        packet = (
            Ether()
            / IP(src="198.51.100.2", dst="192.0.2.1")
            / UDP(sport=53, dport=51000)
            / DNS(id=1, qr=1, rcode=3, qd=DNSQR(qname="missing.test"))
        )
        record = _parse(packet)
        assert record.dns_rcode == "NXDOMAIN"


class TestIpVersions:
    def test_ipv4_and_ipv6_are_not_conflated(self):
        v4 = _parse(Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / TCP(sport=1, dport=2))
        v6 = _parse(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=1, dport=2))

        assert v4.ip_version == 4
        assert v6.ip_version == 6
        assert v4.network_layer == "IPv4"
        assert v6.network_layer == "IPv6"
        assert ":" not in (v4.src_ip or "")
        assert ":" in (v6.src_ip or "")
        assert v6.is_ipv6 is True
        assert v4.is_ipv6 is False

    def test_ipv6_hop_limit_maps_to_ttl(self):
        record = _parse(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=42) / TCP())
        assert record.ttl == 42


class TestMissingLayers:
    def test_ethernet_only_packet(self):
        """A frame with no IP layer must not raise or invent values."""
        record = _parse(Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb", type=0x9000))
        assert record.src_ip is None
        assert record.dst_ip is None
        assert record.transport_protocol is None
        assert record.src_port is None
        assert "no_network_layer" in record.parse_warnings
        assert record.parse_status == PARSE_PARTIAL

    def test_ip_without_transport(self):
        record = _parse(Ether() / IP(src="192.0.2.1", dst="198.51.100.2", proto=47))
        assert record.transport_protocol is None
        assert "no_transport_layer" in record.parse_warnings
        assert record.src_ip == "192.0.2.1"

    def test_arp_has_no_transport_warning(self):
        record = _parse(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc="192.0.2.1", pdst="198.51.100.2")
        )
        assert record.network_layer == "ARP"
        assert record.arp_op == 1
        # ARP legitimately has no transport layer; that is not a parse problem.
        assert "no_transport_layer" not in record.parse_warnings
        assert record.parse_status == PARSE_OK

    def test_optional_fields_are_none_not_invented(self):
        record = _parse(Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / UDP(sport=1, dport=2))
        assert record.tcp_flags is None
        assert record.tcp_seq is None
        assert record.dns_query is None
        assert record.icmp_type is None
        assert record.tls_sni is None
        assert record.dns_answers == []


class TestVlanAndHttp:
    def test_vlan_extraction(self):
        record = _parse(Ether() / Dot1Q(vlan=42, prio=3) / IP(src="192.0.2.1", dst="198.51.100.2") / TCP())
        assert record.vlan_id == 42
        assert record.vlan_priority == 3
        assert "VLAN" in record.protocols

    def test_http_request_metadata(self):
        payload = (
            b"GET /path HTTP/1.1\r\nHost: example.test\r\nUser-Agent: tester/1.0\r\n\r\n"
        )
        record = _parse(
            Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / TCP(sport=44000, dport=80) / Raw(load=payload)
        )
        assert record.http_method == "GET"
        assert record.http_uri == "/path"
        assert record.http_host == "example.test"
        assert record.http_user_agent == "tester/1.0"
        assert "HTTP" in record.protocols

    def test_http_body_is_not_stored(self):
        payload = b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n" + b"SECRETBODY" * 100
        record = _parse(
            Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / TCP(sport=1, dport=80) / Raw(load=payload)
        )
        serialized = str(record.to_dict())
        assert "SECRETBODY" not in serialized


class TestMalformedPackets:
    def test_truncated_packet_does_not_raise(self):
        """A packet cut mid-header must produce a record, not an exception."""
        packet = Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / TCP(sport=1, dport=2)
        truncated = packet.copy()
        truncated.remove_payload()
        record = _parse(truncated)
        assert record.packet_id == 1
        assert record.parse_status in (PARSE_OK, PARSE_PARTIAL, PARSE_FAILED)

    def test_non_packet_input_is_handled(self):
        """parse_packet must contain failures rather than propagating them."""

        class Broken:
            time = None

            def __len__(self):
                raise RuntimeError("broken length")

            def getlayer(self, *args, **kwargs):
                raise RuntimeError("broken getlayer")

        record = parse_packet(Broken(), packet_id=7, source_type="file")
        assert record.packet_id == 7
        assert record.parse_status == PARSE_FAILED
        assert record.parse_warnings

    def test_packet_ids_and_timestamps_are_preserved(self):
        packet = Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / TCP()
        packet.time = 1700000000.5
        record = _parse(packet, packet_id=99)
        assert record.packet_id == 99
        assert record.timestamp == pytest.approx(1700000000.5)
