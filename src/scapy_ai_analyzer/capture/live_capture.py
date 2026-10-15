"""Live packet capture.

Design constraints that follow from the project scope:

* Capture is **opt-in**: it only starts when the user names an interface and
  confirms. There is no implicit capture on import or on a bare command.
* Capture is **passive**: packets are read, never sent, modified, or blocked.
* Capture is **bounded**: it stops after the requested duration or packet count,
  and it can be stopped safely from a signal handler.

Interface enumeration is best-effort: on systems without the required
privileges or without the optional dependency, listing returns an empty result
with a reason rather than raising.
"""

from __future__ import annotations

import importlib
import signal
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..models.packet import PacketRecord
from ..parsing.packet_parser import parse_packet


class LiveCaptureError(Exception):
    """Raised when live capture cannot start or cannot continue."""


@dataclass
class InterfaceInfo:
    """A capture-capable network interface."""

    name: str
    description: str = ""
    addresses: list[str] = field(default_factory=list)
    is_loopback: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "addresses": self.addresses,
            "is_loopback": self.is_loopback,
        }


@dataclass
class CaptureRequest:
    """Parameters for one live capture session."""

    interface: str
    duration: Optional[float] = None
    max_packets: Optional[int] = None
    bpf_filter: Optional[str] = None
    snaplen: int = 65535
    promisc: bool = True
    confirmed: bool = False

    def validate(self) -> None:
        if not self.interface:
            raise LiveCaptureError("An interface must be selected before capturing.")
        if not self.confirmed:
            raise LiveCaptureError(
                "Live capture requires explicit confirmation (--yes). "
                "Only capture traffic on networks you are authorized to monitor."
            )
        if self.duration is None and self.max_packets is None:
            raise LiveCaptureError(
                "Specify a capture duration or a maximum packet count so the capture "
                "cannot run unbounded."
            )
        if self.duration is not None and self.duration <= 0:
            raise LiveCaptureError("Capture duration must be greater than 0.")
        if self.max_packets is not None and self.max_packets <= 0:
            raise LiveCaptureError("Maximum packet count must be greater than 0.")


@dataclass
class CaptureOutcome:
    """Result of a live capture session."""

    records: list[PacketRecord] = field(default_factory=list)
    packets_seen: int = 0
    packets_failed: int = 0
    interface: str = ""
    started_at: float = 0.0
    ended_at: float = 0.0
    stop_reason: str = "unknown"
    errors: list[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return max(0.0, self.ended_at - self.started_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "interface": self.interface,
            "packets_seen": self.packets_seen,
            "packets_failed": self.packets_failed,
            "duration_seconds": round(self.duration, 3),
            "stop_reason": self.stop_reason,
            "errors": self.errors,
        }


def list_interfaces() -> tuple[list[InterfaceInfo], Optional[str]]:
    """List capture interfaces.

    Returns ``(interfaces, reason_unavailable)``. ``reason_unavailable`` is set
    when enumeration could not be performed, so the CLI can explain why the list
    is empty instead of implying there are no interfaces.
    """
    try:
        from scapy.arch import get_if_list
    except Exception as exc:  # noqa: BLE001 - scapy may lack platform support
        return [], f"Interface enumeration is unavailable: {exc}"

    try:
        names = get_if_list()
    except Exception as exc:  # noqa: BLE001
        return [], f"Interface enumeration failed: {exc}"

    interfaces: list[InterfaceInfo] = []
    for name in names:
        info = InterfaceInfo(name=name, is_loopback=name in ("lo", "lo0"))
        try:
            from scapy.arch import get_if_addr

            address = get_if_addr(name)
            if address:
                info.addresses.append(address)
        except Exception:  # noqa: BLE001 - address lookup is optional detail
            pass
        interfaces.append(info)

    if not interfaces:
        return [], "No capture interfaces were reported by the platform."
    return interfaces, None


def check_capture_privileges() -> tuple[bool, str]:
    """Report whether the process appears able to capture.

    A definitive check requires actually opening the interface, which would be a
    side effect. This reports the likely outcome so ``doctor`` can warn early.
    """
    import os

    if hasattr(os, "geteuid"):
        if os.geteuid() == 0:
            return True, "Running as root; raw capture should be permitted."
        return (
            False,
            "Not running as root. Raw capture usually requires root or "
            "CAP_NET_RAW/CAP_NET_ADMIN. On Linux you can grant the capability with "
            "setcap, or run the capture under sudo.",
        )
    return True, "Privilege check is not applicable on this platform."


def _sniffer_is_running(sniffer: Any) -> bool:
    """Return True once the sniffer thread has opened its socket."""
    if getattr(sniffer, "running", False):
        return True
    thread = getattr(sniffer, "thread", None)
    return bool(thread is not None and thread.is_alive() and getattr(sniffer, "running", False))


def _sniffer_failure(sniffer: Any) -> Optional[str]:
    """Return a description if the sniffer thread recorded an exception."""
    exc = getattr(sniffer, "exception", None)
    if exc is None:
        return None
    return f"{exc.__class__.__name__}: {exc}"


def _sniffer_accepts_snaplen() -> bool:
    """Report whether the platform capture socket accepts a ``snaplen`` argument."""
    try:
        import inspect

        module = importlib.import_module("scapy.arch.linux")
        socket_cls = getattr(module, "L2Socket", None)
        if socket_cls is None:
            return True
        return "snaplen" in inspect.signature(socket_cls.__init__).parameters
    except Exception:  # noqa: BLE001 - default to not passing it
        return False


class LiveCapture:
    """Passive, bounded live capture using Scapy's AsyncSniffer."""

    def __init__(self, request: CaptureRequest) -> None:
        self.request = request
        self._stop_event = threading.Event()
        self._previous_sigint: Any = None

    def stop(self) -> None:
        """Request a safe stop. Safe to call from a signal handler."""
        self._stop_event.set()

    def _install_signal_handler(self) -> None:
        try:
            self._previous_sigint = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, self._handle_sigint)
        except (ValueError, OSError):
            # Not on the main thread, or the platform does not allow it.
            self._previous_sigint = None

    def _restore_signal_handler(self) -> None:
        if self._previous_sigint is not None:
            try:
                signal.signal(signal.SIGINT, self._previous_sigint)
            except (ValueError, OSError):
                pass
            self._previous_sigint = None

    def _handle_sigint(self, signum, frame) -> None:  # noqa: ARG002
        self.stop()

    def run(self, on_packet: Optional[Callable[[PacketRecord], None]] = None) -> CaptureOutcome:
        """Execute the capture and return everything collected."""
        self.request.validate()

        try:
            from scapy.sendrecv import AsyncSniffer
        except Exception as exc:  # noqa: BLE001
            raise LiveCaptureError(f"Scapy capture support is unavailable: {exc}") from exc

        outcome = CaptureOutcome(
            interface=self.request.interface,
            started_at=time.time(),
            stop_reason="unknown",
        )

        sniffer_kwargs: dict[str, Any] = {
            "iface": self.request.interface,
            "store": False,
            "prn": lambda packet: self._handle_packet(packet, outcome, on_packet),
            "promisc": self.request.promisc,
        }
        # Scapy only accepts `snaplen` where the platform's capture socket
        # supports it (it was removed from the Linux L2 socket in Scapy 2.8).
        # Passing an unsupported keyword raises inside the sniffer thread, so it
        # is offered only when the underlying socket accepts it.
        if self.request.snaplen and _sniffer_accepts_snaplen():
            sniffer_kwargs["snaplen"] = self.request.snaplen
        if self.request.bpf_filter:
            sniffer_kwargs["filter"] = self.request.bpf_filter

        self._install_signal_handler()
        sniffer = None
        try:
            sniffer = AsyncSniffer(**sniffer_kwargs)
            sniffer.start()
        except PermissionError as exc:
            self._restore_signal_handler()
            raise LiveCaptureError(
                f"Permission denied opening {self.request.interface}. "
                "Raw capture requires elevated privileges."
            ) from exc
        except Exception as exc:  # noqa: BLE001
            self._restore_signal_handler()
            raise LiveCaptureError(
                f"Could not start capture on {self.request.interface}: {exc}"
            ) from exc

        # AsyncSniffer runs its socket setup in a worker thread, so an open
        # failure surfaces there rather than at start(). Detect it instead of
        # reporting an empty capture as success.
        startup_error = self._wait_for_sniffer_start(sniffer)
        if startup_error is not None:
            self._restore_signal_handler()
            raise LiveCaptureError(
                f"Capture on {self.request.interface} could not start: {startup_error}"
            )

        try:
            self._wait(outcome, sniffer)
        finally:
            self._restore_signal_handler()
            try:
                if sniffer is not None:
                    sniffer.stop()
            except Exception:  # noqa: BLE001 - stopping must not mask the outcome
                if not outcome.errors:
                    outcome.errors.append("Sniffer did not stop cleanly.")

        outcome.ended_at = time.time()
        if outcome.packets_seen == 0 and not outcome.errors:
            outcome.errors.append(
                "No packets were observed on this interface during the capture window. "
                "The interface may be idle, or capture permissions may be insufficient."
            )
        return outcome

    def _wait_for_sniffer_start(self, sniffer: Any) -> Optional[str]:
        """Return an error string if the sniffer thread failed to start.

        The socket is opened inside the worker thread, so ``start()`` returning
        does not mean the capture is running.
        """
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            failure = _sniffer_failure(sniffer)
            if failure is not None:
                return failure
            if _sniffer_is_running(sniffer):
                return None
            time.sleep(0.02)
        # Still not running after the grace period: report the last known state.
        failure = _sniffer_failure(sniffer)
        if failure is not None:
            return failure
        if not _sniffer_is_running(sniffer):
            return "the capture thread did not start."
        return None

    def _wait(self, outcome: CaptureOutcome, sniffer: Any = None) -> None:
        """Block until the duration, packet limit, or a stop request ends capture."""
        deadline = (
            time.monotonic() + self.request.duration if self.request.duration is not None else None
        )
        while True:
            # Check the packet limit before the stop flag: the handler sets the
            # stop flag when the limit is reached, and that must be reported as
            # a completed limit rather than a user stop.
            if (
                self.request.max_packets is not None
                and outcome.packets_seen >= self.request.max_packets
            ):
                outcome.stop_reason = "max_packets_reached"
                return
            if self._stop_event.is_set():
                outcome.stop_reason = "stopped_by_user"
                return
            if deadline is not None and time.monotonic() >= deadline:
                outcome.stop_reason = "duration_elapsed"
                return
            # A sniffer thread that dies mid-capture must end the wait rather
            # than spin until the deadline.
            if sniffer is not None:
                failure = _sniffer_failure(sniffer)
                if failure is not None:
                    outcome.stop_reason = "capture_error"
                    if len(outcome.errors) < 20:
                        outcome.errors.append(f"capture thread failed: {failure}")
                    return
            time.sleep(0.05)

    def _handle_packet(
        self,
        packet,
        outcome: CaptureOutcome,
        on_packet: Optional[Callable[[PacketRecord], None]],
    ) -> None:
        """Parse one sniffed packet. Never raises into the sniffer thread."""
        try:
            # Enforce the packet limit here rather than only in the polling
            # loop: the sniffer delivers packets far faster than the loop polls,
            # so a loop-only check would overshoot the requested limit.
            if (
                self.request.max_packets is not None
                and outcome.packets_seen >= self.request.max_packets
            ):
                self._stop_event.set()
                return

            outcome.packets_seen += 1
            record = parse_packet(
                packet,
                packet_id=outcome.packets_seen,
                source_type="live",
                source_ref=self.request.interface,
                frame_number=outcome.packets_seen,
            )
            if record.parse_status == "failed":
                outcome.packets_failed += 1
            outcome.records.append(record)
            if on_packet is not None:
                on_packet(record)
        except Exception as exc:  # noqa: BLE001 - a bad frame must not kill the capture
            outcome.packets_failed += 1
            if len(outcome.errors) < 20:
                outcome.errors.append(f"frame {outcome.packets_seen}: {exc.__class__.__name__}: {exc}")
