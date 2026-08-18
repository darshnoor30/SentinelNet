"""Generate deterministic, non-sensitive alerts for the dashboard demo."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from detection_engine.detector import DEFAULT_ALERT_FILE, CsvAlertStore, ThreatAlert, create_alert

DEMO_SIGNALS = (
    (4444, "203.0.113.41", "10.20.0.12", "TCP", 118),
    (23, "198.51.100.22", "10.20.0.8", "TCP", 111),
    (445, "192.0.2.73", "10.20.0.15", "TCP", 102),
    (3389, "203.0.113.19", "10.20.0.21", "TCP", 94),
    (21, "198.51.100.36", "10.20.0.9", "TCP", 88),
    (1337, "192.0.2.73", "10.20.0.15", "TCP", 77),
    (445, "203.0.113.41", "10.20.0.12", "TCP", 69),
    (23, "198.51.100.22", "10.20.0.8", "TCP", 61),
    (3389, "203.0.113.58", "10.20.0.21", "TCP", 50),
    (4444, "192.0.2.73", "10.20.0.15", "TCP", 42),
    (21, "198.51.100.36", "10.20.0.9", "TCP", 31),
    (445, "203.0.113.41", "10.20.0.12", "TCP", 22),
    (1337, "203.0.113.58", "10.20.0.21", "TCP", 14),
    (23, "198.51.100.22", "10.20.0.8", "TCP", 6),
)


def generate_demo_data(output: Path, *, now: datetime | None = None) -> int:
    """Write representative alerts using IANA documentation-only IP ranges."""

    store = CsvAlertStore(output)
    base_time = now or datetime.now(timezone.utc)
    written = 0

    for port, source_ip, destination_ip, protocol, minutes_ago in DEMO_SIGNALS:
        alert = create_alert(
            port,
            source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            observed_at=base_time - timedelta(minutes=minutes_ago),
        )
        if alert is not None:
            store.write(alert)
            written += 1

    store.write(
        ThreatAlert(
            timestamp=base_time - timedelta(minutes=37),
            source_ip="192.0.2.140",
            destination_ip="10.20.0.30",
            protocol="TCP",
            port=8080,
            service="Multiple services",
            severity="High",
            category="Network discovery",
            description="Observed 12 unique destination ports within 60 seconds.",
        )
    )
    return written + 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate safe SentinelNet dashboard demo data")
    parser.add_argument("--output", type=Path, default=DEFAULT_ALERT_FILE)
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing alert file (never use this on evidence you need to retain)",
    )
    args = parser.parse_args(argv)

    if args.output.exists():
        if not args.force:
            parser.error(f"{args.output} already exists; pass --force to replace it")
        args.output.unlink()

    count = generate_demo_data(args.output)
    print(f"Generated {count} safe demo alerts in {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
