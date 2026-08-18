"""Rule-based network threat detection and CSV alert persistence.

The rules in this module are intentionally explainable. A port match is a signal
for analyst review, not proof that a host is compromised.
"""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ALERT_FILE = PROJECT_ROOT / "alerts" / "alerts.csv"


@dataclass(frozen=True, slots=True)
class ThreatRule:
    """An explainable detection rule for a network service."""

    service: str
    severity: str
    category: str
    description: str


@dataclass(frozen=True, slots=True)
class ThreatAlert:
    """Normalized alert passed from detection to storage and analytics."""

    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    port: int
    service: str
    severity: str
    category: str
    description: str

    def to_row(self) -> dict[str, str | int]:
        """Return a stable CSV representation of the alert."""

        values = asdict(self)
        values["timestamp"] = self.timestamp.astimezone(timezone.utc).isoformat()
        return {CSV_COLUMNS[key]: value for key, value in values.items()}


CSV_COLUMNS = {
    "timestamp": "Timestamp",
    "source_ip": "SourceIP",
    "destination_ip": "DestinationIP",
    "protocol": "Protocol",
    "port": "Port",
    "service": "Service",
    "severity": "Severity",
    "category": "Category",
    "description": "Description",
}
ALERT_FIELDS = list(CSV_COLUMNS.values())

SUSPICIOUS_PORTS: dict[int, ThreatRule] = {
    21: ThreatRule(
        "FTP",
        "Medium",
        "Cleartext protocol exposure",
        "FTP may expose credentials or data without transport encryption.",
    ),
    23: ThreatRule(
        "Telnet",
        "High",
        "Cleartext remote access",
        "Telnet sends administrative sessions without transport encryption.",
    ),
    445: ThreatRule(
        "SMB",
        "High",
        "Lateral movement surface",
        "SMB is frequently targeted for discovery and lateral movement.",
    ),
    3389: ThreatRule(
        "RDP",
        "Medium",
        "Remote access exposure",
        "RDP traffic should be checked against approved remote-access activity.",
    ),
    4444: ThreatRule(
        "Common reverse-shell port",
        "Critical",
        "Command-and-control indicator",
        "Port 4444 is commonly associated with reverse shells and test frameworks.",
    ),
    1337: ThreatRule(
        "Non-standard service",
        "Critical",
        "Potential backdoor activity",
        "Unexpected traffic on port 1337 warrants immediate analyst validation.",
    ),
}


class CsvAlertStore:
    """Append alerts to a CSV file while supporting legacy SentinelNet headers."""

    def __init__(self, path: str | Path = DEFAULT_ALERT_FILE) -> None:
        self.path = Path(path)

    def write(self, alert: ThreatAlert) -> None:
        """Persist one alert and create the parent directory on first use."""

        self.path.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = self._fieldnames()
        is_empty = not self.path.exists() or self.path.stat().st_size == 0

        with self.path.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
            if is_empty:
                writer.writeheader()
            writer.writerow(alert.to_row())

    def _fieldnames(self) -> list[str]:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return ALERT_FIELDS

        with self.path.open("r", newline="", encoding="utf-8-sig") as handle:
            existing = next(csv.reader(handle), [])

        # Older versions used five columns. Preserve that file rather than
        # appending incompatible rows; newly created files use the richer schema.
        return existing if existing else ALERT_FIELDS


def create_alert(
    port: int,
    source_ip: str,
    *,
    destination_ip: str = "",
    protocol: str = "",
    observed_at: datetime | None = None,
) -> ThreatAlert | None:
    """Build an alert when ``port`` matches an explainable service rule."""

    rule = SUSPICIOUS_PORTS.get(int(port))
    if rule is None:
        return None

    timestamp = observed_at or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return ThreatAlert(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol.upper(),
        port=int(port),
        service=rule.service,
        severity=rule.severity,
        category=rule.category,
        description=rule.description,
    )


def detect_threat(
    port: int,
    source_ip: str,
    *,
    destination_ip: str = "",
    protocol: str = "",
    observed_at: datetime | None = None,
    alert_store: CsvAlertStore | None = None,
    emit_console: bool = True,
    output: TextIO | None = None,
) -> ThreatAlert | None:
    """Evaluate a port, persist a matching alert, and return it.

    Returning the alert instead of a boolean keeps the API useful to packet
    capture, dashboards, tests, and future SIEM integrations.
    """

    alert = create_alert(
        port,
        source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        observed_at=observed_at,
    )
    if alert is None:
        return None

    (alert_store or CsvAlertStore()).write(alert)
    if emit_console:
        _print_alert(alert, output=output)
    return alert


def _print_alert(alert: ThreatAlert, *, output: TextIO | None = None) -> None:
    import sys

    destination = output or sys.stdout
    print("\n" + "=" * 48, file=destination)
    print("SECURITY SIGNAL", file=destination)
    print("=" * 48, file=destination)
    print(f"Source      : {alert.source_ip}", file=destination)
    print(f"Destination : {alert.destination_ip or 'unknown'}", file=destination)
    print(
        f"Service     : {alert.service} ({alert.protocol or 'IP'}/{alert.port})", file=destination
    )
    print(f"Severity    : {alert.severity}", file=destination)
    print(f"Category    : {alert.category}", file=destination)
    print("=" * 48, file=destination)
