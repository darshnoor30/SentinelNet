"""Command-line alert summary for SentinelNet."""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ALERT_FILE = PROJECT_ROOT / "alerts" / "alerts.csv"
SEVERITY_ORDER = ("Critical", "High", "Medium", "Low")


def load_alerts(path: str | Path = DEFAULT_ALERT_FILE) -> list[dict[str, str]]:
    """Load alert rows, returning an empty list when no capture exists yet."""

    alert_path = Path(path)
    if not alert_path.exists():
        return []
    with alert_path.open("r", newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def summarize_alerts(rows: Iterable[Mapping[str, str]]) -> dict[str, int]:
    """Count alerts using a stable severity order."""

    counts = Counter(row.get("Severity", "Unknown") or "Unknown" for row in rows)
    summary = {severity: counts.pop(severity, 0) for severity in SEVERITY_ORDER}
    summary.update(sorted(counts.items()))
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize SentinelNet alert severities")
    parser.add_argument("--alerts", type=Path, default=DEFAULT_ALERT_FILE)
    args = parser.parse_args()

    rows = load_alerts(args.alerts)
    summary = summarize_alerts(rows)
    print("\nThreat statistics")
    print("=" * 32)
    print(f"Total alerts    : {sum(summary.values())}")
    for severity, count in summary.items():
        print(f"{severity:<15} : {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
