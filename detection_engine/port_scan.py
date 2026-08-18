"""Stateful, time-windowed port-scan detection."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True, slots=True)
class PortScanEvent:
    source_ip: str
    unique_ports: int
    window_seconds: int
    observed_at: datetime


class PortScanDetector:
    """Detect sources touching many unique ports inside a rolling window."""

    def __init__(
        self,
        *,
        threshold: int = 10,
        window_seconds: int = 60,
        cooldown_seconds: int = 60,
    ) -> None:
        if threshold < 2:
            raise ValueError("threshold must be at least 2")
        if window_seconds < 1 or cooldown_seconds < 0:
            raise ValueError("window and cooldown must be non-negative")

        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self._observations: dict[str, dict[int, datetime]] = defaultdict(dict)
        self._last_alert: dict[str, datetime] = {}

    def observe(
        self,
        source_ip: str,
        port: int,
        *,
        observed_at: datetime | None = None,
    ) -> PortScanEvent | None:
        """Record an observation and return a deduplicated scan event."""

        now = observed_at or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        cutoff = now - timedelta(seconds=self.window_seconds)
        observations = self._observations[source_ip]
        stale_ports = [seen_port for seen_port, seen_at in observations.items() if seen_at < cutoff]
        for stale_port in stale_ports:
            del observations[stale_port]

        observations[int(port)] = now
        if len(observations) < self.threshold:
            return None

        last_alert = self._last_alert.get(source_ip)
        cooldown = timedelta(seconds=self.cooldown_seconds)
        if last_alert is not None and now - last_alert < cooldown:
            return None

        self._last_alert[source_ip] = now
        return PortScanEvent(source_ip, len(observations), self.window_seconds, now)

    def reset(self) -> None:
        """Clear detector state, primarily for controlled capture sessions."""

        self._observations.clear()
        self._last_alert.clear()


_default_detector = PortScanDetector()


def check_port_scan(source_ip: str, port: int) -> bool:
    """Compatibility wrapper for the original function-based API."""

    return _default_detector.observe(source_ip, port) is not None


detect_port_scan = check_port_scan
