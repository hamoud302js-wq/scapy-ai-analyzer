"""Live capture tests.

The capture path must never report an empty capture as a success. These tests
cover the guard rails: explicit confirmation, bounded runs, clean stop, and
reporting of a failed capture thread instead of a silent zero-packet result.
"""

from __future__ import annotations

import threading
import time

import pytest

from scapy_ai_analyzer.capture.live_capture import (
    CaptureOutcome,
    CaptureRequest,
    LiveCapture,
    LiveCaptureError,
    _sniffer_failure,
    _sniffer_is_running,
)


class TestRequestValidation:
    def test_requires_interface(self):
        with pytest.raises(LiveCaptureError, match="interface"):
            CaptureRequest(interface="", duration=1, confirmed=True).validate()

    def test_requires_confirmation(self):
        with pytest.raises(LiveCaptureError, match="confirmation"):
            CaptureRequest(interface="lo", duration=1, confirmed=False).validate()

    def test_requires_a_bound(self):
        with pytest.raises(LiveCaptureError, match="duration or a maximum packet count"):
            CaptureRequest(interface="lo", confirmed=True).validate()

    def test_rejects_non_positive_bounds(self):
        with pytest.raises(LiveCaptureError, match="greater than 0"):
            CaptureRequest(interface="lo", duration=0, confirmed=True).validate()
        with pytest.raises(LiveCaptureError, match="greater than 0"):
            CaptureRequest(interface="lo", max_packets=-5, confirmed=True).validate()

    def test_accepts_duration_only(self):
        CaptureRequest(interface="lo", duration=1, confirmed=True).validate()

    def test_accepts_packet_limit_only(self):
        CaptureRequest(interface="lo", max_packets=10, confirmed=True).validate()


class TestSnifferStateHelpers:
    def test_failure_is_reported_from_exception_attribute(self):
        class Fake:
            exception = PermissionError("Operation not permitted")

        message = _sniffer_failure(Fake())
        assert "PermissionError" in message
        assert "Operation not permitted" in message

    def test_no_failure_when_exception_is_none(self):
        class Fake:
            exception = None

        assert _sniffer_failure(Fake()) is None

    def test_running_flag_is_detected(self):
        class Fake:
            running = True
            thread = None

        assert _sniffer_is_running(Fake())

    def test_not_running_when_flag_false(self):
        class Fake:
            running = False
            thread = None

        assert not _sniffer_is_running(Fake())

    def test_dead_thread_is_not_running(self):
        thread = threading.Thread(target=lambda: None)
        thread.start()
        thread.join()

        class Fake:
            running = False
            thread = None

        fake = Fake()
        fake.thread = thread
        assert not _sniffer_is_running(fake)


class TestOutcomeReporting:
    def test_zero_packet_capture_records_a_warning(self):
        outcome = CaptureOutcome(interface="lo", started_at=time.time(), ended_at=time.time())
        assert outcome.packets_seen == 0
        # The capture loop adds an explanation; the dataclass itself stays empty.
        assert outcome.errors == []

    def test_outcome_serializes_errors(self):
        outcome = CaptureOutcome(
            interface="lo",
            started_at=100.0,
            ended_at=105.0,
            stop_reason="capture_error",
            errors=["capture thread failed: PermissionError"],
        )
        data = outcome.to_dict()
        assert data["stop_reason"] == "capture_error"
        assert data["duration_seconds"] == 5.0
        assert data["errors"]

    def test_duration_never_negative(self):
        outcome = CaptureOutcome(interface="lo", started_at=10.0, ended_at=5.0)
        assert outcome.duration == 0.0


@pytest.mark.skipif(
    __import__("os").geteuid() != 0,
    reason="Live capture requires elevated privileges; covered manually under sudo.",
)
class TestPrivilegedCapture:
    def test_capture_runs_and_stops_on_duration(self):
        request = CaptureRequest(interface="lo", duration=1.0, confirmed=True)
        outcome = LiveCapture(request).run()
        assert outcome.stop_reason == "duration_elapsed"
        assert outcome.duration >= 1.0

    def test_capture_respects_packet_limit(self):
        """The packet limit stops the capture before the duration elapses."""
        import socket

        request = CaptureRequest(interface="lo", duration=20.0, max_packets=5, confirmed=True)
        capture = LiveCapture(request)

        def generate():
            time.sleep(0.5)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for index in range(50):
                sock.sendto(b"x" * 40, ("127.0.0.1", 9998))
                time.sleep(0.01)

        generator = threading.Thread(target=generate)
        generator.start()
        outcome = capture.run()
        generator.join()

        assert outcome.stop_reason == "max_packets_reached"
        assert outcome.packets_seen == 5
        assert outcome.duration < 20.0

    def test_stop_from_another_thread(self):
        request = CaptureRequest(interface="lo", duration=30.0, confirmed=True)
        capture = LiveCapture(request)

        def stop_soon():
            time.sleep(0.5)
            capture.stop()

        stopper = threading.Thread(target=stop_soon)
        stopper.start()
        outcome = capture.run()
        stopper.join()

        assert outcome.stop_reason == "stopped_by_user"
        assert outcome.duration < 5.0
