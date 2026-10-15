"""PCAP / PCAPNG file reading.

Reading is streaming: packets are yielded in batches and never all held in
memory at once. Unreadable frames are counted and reported rather than raising,
so a partially corrupt capture still produces useful analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from scapy.packet import Packet

from ..models.packet import PacketRecord
from ..parsing.packet_parser import parse_packet

# Magic numbers used to detect the capture format without guessing from the suffix.
PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_NS = b"\x4d\x3c\xb2\xa1"
PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

SUPPORTED_SUFFIXES = (".pcap", ".pcapng", ".cap")


@dataclass
class ReadStats:
    """Counters describing a read operation."""

    packets_read: int = 0
    packets_parsed: int = 0
    packets_failed: int = 0
    capture_format: Optional[str] = None
    read_errors: list[str] = field(default_factory=list)
    truncated: bool = False


class CaptureFileError(Exception):
    """Raised when a capture file cannot be opened or is not a supported format."""


def detect_format(path: Path) -> str:
    """Return ``'pcap'`` or ``'pcapng'`` based on the file's magic bytes."""
    try:
        with open(path, "rb") as handle:
            header = handle.read(4)
    except OSError as exc:
        raise CaptureFileError(f"Cannot read capture file {path}: {exc}") from exc

    if header in (PCAP_MAGIC, PCAP_MAGIC_NS, PCAP_MAGIC_BE):
        return "pcap"
    if header == PCAPNG_MAGIC:
        return "pcapng"
    raise CaptureFileError(
        f"Unrecognized capture format in {path}. Expected a PCAP or PCAPNG file."
    )


def validate_capture_file(path: str | Path) -> Path:
    """Check existence, readability, and format. Returns the resolved path."""
    resolved = Path(path).expanduser()
    if not resolved.exists():
        raise CaptureFileError(f"Capture file not found: {resolved}")
    if resolved.is_dir():
        raise CaptureFileError(f"Expected a file but got a directory: {resolved}")
    if not resolved.stat().st_size:
        raise CaptureFileError(f"Capture file is empty: {resolved}")
    try:
        with open(resolved, "rb"):
            pass
    except OSError as exc:
        raise CaptureFileError(f"Capture file is not readable: {resolved} ({exc})") from exc

    detect_format(resolved)
    return resolved


def _open_reader(path: Path):
    """Open the appropriate Scapy reader for the detected format."""
    fmt = detect_format(path)
    try:
        if fmt == "pcapng":
            from scapy.utils import PcapNgReader

            return PcapNgReader(str(path))
        from scapy.utils import PcapReader

        return PcapReader(str(path))
    except Exception as exc:  # noqa: BLE001 - surface reader failures as our own error
        raise CaptureFileError(f"Failed to open {path}: {exc}") from exc


def read_packets(
    path: str | Path,
    batch_size: int = 5000,
    max_packets: Optional[int] = None,
    source_type: str = "file",
) -> tuple[Iterator[list[PacketRecord]], ReadStats]:
    """Return a batch iterator over normalized packet records plus read stats.

    The returned iterator must be consumed to completion for ``stats`` to be
    accurate; ``stats`` is mutated as batches are produced.
    """
    resolved = validate_capture_file(path)
    stats = ReadStats()
    stats.capture_format = detect_format(resolved)

    def _generate() -> Iterator[list[PacketRecord]]:
        reader = _open_reader(resolved)
        batch: list[PacketRecord] = []
        frame_number = 0
        try:
            while True:
                if max_packets is not None and stats.packets_read >= max_packets:
                    stats.truncated = True
                    break
                try:
                    packet = reader.read_packet()
                except EOFError:
                    break
                except Exception as exc:  # noqa: BLE001 - keep going past corrupt frames
                    stats.packets_failed += 1
                    if len(stats.read_errors) < 50:
                        stats.read_errors.append(
                            f"frame {frame_number + 1}: {exc.__class__.__name__}: {exc}"
                        )
                    continue
                if packet is None:
                    break

                frame_number += 1
                stats.packets_read += 1
                record = parse_packet(
                    packet,
                    packet_id=stats.packets_read,
                    source_type=source_type,
                    source_ref=str(resolved),
                    frame_number=frame_number,
                )
                if record.parse_status == "failed":
                    stats.packets_failed += 1
                else:
                    stats.packets_parsed += 1
                batch.append(record)

                if len(batch) >= batch_size:
                    yield batch
                    batch = []
            if batch:
                yield batch
        finally:
            try:
                reader.close()
            except Exception:  # noqa: BLE001 - closing must never mask results
                pass

    return _generate(), stats


def iter_packet_batches(
    path: str | Path,
    batch_size: int = 5000,
    max_packets: Optional[int] = None,
    source_type: str = "file",
) -> Iterator[tuple[list[PacketRecord], ReadStats]]:
    """Convenience wrapper yielding ``(batch, stats)`` so callers see live counts."""
    batches, stats = read_packets(
        path, batch_size=batch_size, max_packets=max_packets, source_type=source_type
    )
    for batch in batches:
        yield batch, stats
