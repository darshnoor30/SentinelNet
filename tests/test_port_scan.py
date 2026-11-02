from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from detection_engine.port_scan import PortScanDetector


def test_detector_alerts_at_threshold_and_respects_cooldown() -> None:
    detector = PortScanDetector(threshold=3, window_seconds=60, cooldown_seconds=10)
    start = datetime(2026, 8, 18, tzinfo=timezone.utc)

    assert detector.observe("192.0.2.9", 20, observed_at=start) is None
    assert detector.observe("192.0.2.9", 21, observed_at=start + timedelta(seconds=1)) is None
    event = detector.observe("192.0.2.9", 22, observed_at=start + timedelta(seconds=2))

    assert event is not None
    assert event.unique_ports == 3
    assert detector.observe("192.0.2.9", 23, observed_at=start + timedelta(seconds=3)) is None
    assert detector.observe("192.0.2.9", 24, observed_at=start + timedelta(seconds=13))


def test_detector_prunes_observations_outside_window() -> None:
    detector = PortScanDetector(threshold=2, window_seconds=10)
    start = datetime(2026, 8, 18, tzinfo=timezone.utc)

    assert detector.observe("198.51.100.2", 80, observed_at=start) is None
    assert detector.observe("198.51.100.2", 81, observed_at=start + timedelta(seconds=11)) is None


def test_detector_validates_configuration() -> None:
    with pytest.raises(ValueError, match="threshold"):
        PortScanDetector(threshold=1)
    with pytest.raises(ValueError, match="window"):
        PortScanDetector(window_seconds=0)


def test_reset_clears_state_and_naive_times_are_normalized() -> None:
    detector = PortScanDetector(threshold=2)
    naive_time = datetime(2026, 8, 18)

    assert detector.observe("203.0.113.8", 80, observed_at=naive_time) is None
    detector.reset()
    assert detector.observe("203.0.113.8", 81, observed_at=naive_time) is None


def test_idle_sources_expire_when_other_traffic_arrives() -> None:
    detector = PortScanDetector(threshold=2, window_seconds=10, cooldown_seconds=10)
    start = datetime(2026, 8, 18, tzinfo=timezone.utc)
    for index in range(100):
        source = f"192.0.2.{index}"
        detector.observe(source, 80, observed_at=start)
        detector.observe(source, 81, observed_at=start)
    detector.observe("198.51.100.1", 443, observed_at=start + timedelta(seconds=11))
    assert set(detector._observations) == {"198.51.100.1"}
    assert detector._last_alert == {}


def test_cleanup_preserves_unexpired_cooldown() -> None:
    detector = PortScanDetector(threshold=2, window_seconds=10, cooldown_seconds=30)
    start = datetime(2026, 8, 18, tzinfo=timezone.utc)
    detector.observe("192.0.2.1", 80, observed_at=start)
    assert detector.observe("192.0.2.1", 81, observed_at=start)
    later = start + timedelta(seconds=11)
    detector.observe("198.51.100.1", 443, observed_at=later)
    assert detector.observe("192.0.2.1", 82, observed_at=later) is None
    assert detector.observe("192.0.2.1", 83, observed_at=later) is None


def test_cleanup_keeps_observations_at_window_boundary() -> None:
    detector = PortScanDetector(threshold=2, window_seconds=10)
    start = datetime(2026, 8, 18, tzinfo=timezone.utc)
    detector.observe("192.0.2.1", 80, observed_at=start)
    assert detector.observe("192.0.2.1", 81, observed_at=start + timedelta(seconds=10))
