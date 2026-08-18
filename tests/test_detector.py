from __future__ import annotations

import csv
from datetime import datetime, timezone
from io import StringIO

from detection_engine.detector import CsvAlertStore, create_alert, detect_threat


def test_create_alert_returns_explainable_rule() -> None:
    alert = create_alert(445, "192.0.2.10", destination_ip="10.0.0.4", protocol="tcp")

    assert alert is not None
    assert alert.service == "SMB"
    assert alert.severity == "High"
    assert alert.protocol == "TCP"
    assert "lateral movement" in alert.description


def test_unknown_port_does_not_write_alert(tmp_path) -> None:
    alert_path = tmp_path / "alerts.csv"
    alert = detect_threat(
        443,
        "192.0.2.10",
        alert_store=CsvAlertStore(alert_path),
        emit_console=False,
    )

    assert alert is None
    assert not alert_path.exists()


def test_detect_threat_writes_normalized_csv(tmp_path) -> None:
    alert_path = tmp_path / "nested" / "alerts.csv"
    observed_at = datetime(2026, 8, 18, 10, 30, tzinfo=timezone.utc)

    alert = detect_threat(
        4444,
        "203.0.113.8",
        destination_ip="10.0.0.9",
        protocol="tcp",
        observed_at=observed_at,
        alert_store=CsvAlertStore(alert_path),
        emit_console=False,
    )

    assert alert is not None
    with alert_path.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == 1
    assert rows[0]["Timestamp"] == "2026-08-18T10:30:00+00:00"
    assert rows[0]["DestinationIP"] == "10.0.0.9"
    assert rows[0]["Category"] == "Command-and-control indicator"


def test_store_preserves_legacy_five_column_schema(tmp_path) -> None:
    alert_path = tmp_path / "legacy.csv"
    alert_path.write_text("Timestamp,SourceIP,Port,Service,Severity\n", encoding="utf-8")
    alert = create_alert(23, "198.51.100.5")

    assert alert is not None
    CsvAlertStore(alert_path).write(alert)

    with alert_path.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["Service"] == "Telnet"
    assert set(rows[0]) == {"Timestamp", "SourceIP", "Port", "Service", "Severity"}


def test_console_alert_supports_naive_observation_time(tmp_path) -> None:
    output = StringIO()
    alert = detect_threat(
        21,
        "192.0.2.44",
        observed_at=datetime(2026, 8, 18, 12, 0),
        alert_store=CsvAlertStore(tmp_path / "alerts.csv"),
        output=output,
    )

    assert alert is not None
    assert alert.timestamp.tzinfo == timezone.utc
    assert "SECURITY SIGNAL" in output.getvalue()
    assert "FTP" in output.getvalue()
