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
