from __future__ import annotations

import sys

from analytics.stats import load_alerts, main, summarize_alerts


def test_summarize_alerts_uses_stable_order() -> None:
    rows = [
        {"Severity": "High"},
        {"Severity": "Critical"},
        {"Severity": "High"},
        {"Severity": "Informational"},
    ]

    summary = summarize_alerts(rows)

    assert list(summary) == ["Critical", "High", "Medium", "Low", "Informational"]
    assert summary["High"] == 2


def test_load_alerts_returns_empty_list_for_missing_file(tmp_path) -> None:
    assert load_alerts(tmp_path / "missing.csv") == []


def test_load_and_cli_summary(tmp_path, monkeypatch, capsys) -> None:
    alert_path = tmp_path / "alerts.csv"
    alert_path.write_text(
        "Timestamp,SourceIP,Port,Service,Severity\n2026-08-18T10:00:00Z,192.0.2.2,23,Telnet,High\n",
        encoding="utf-8",
    )

    assert load_alerts(alert_path)[0]["Service"] == "Telnet"
    monkeypatch.setattr(sys, "argv", ["stats", "--alerts", str(alert_path)])
    assert main() == 0
    output = capsys.readouterr().out
    assert "Total alerts    : 1" in output
    assert "High" in output
