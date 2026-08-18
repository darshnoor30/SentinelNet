"""Packet capture entrypoint and testable packet-processing pipeline."""

from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from detection_engine.detector import CsvAlertStore, ThreatAlert, detect_threat
from detection_engine.port_scan import PortScanDetector

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG_FILE = PROJECT_ROOT / "logs" / "network_log.csv"
NETWORK_FIELDS = (
    "Timestamp",
    "SourceIP",
    "DestinationIP",
    "Protocol",
    "SourcePort",
    "DestinationPort",
)


@dataclass(frozen=True, slots=True)
class PacketRecord:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int | str
    destination_port: int | str

    def to_row(self) -> dict[str, str | int]:
        return {
            "Timestamp": self.timestamp.astimezone(timezone.utc).isoformat(),
            "SourceIP": self.source_ip,
            "DestinationIP": self.destination_ip,
            "Protocol": self.protocol,
            "SourcePort": self.source_port,
            "DestinationPort": self.destination_port,
        }


class CsvPacketStore:
    """Append normalized packet metadata without retaining packet payloads."""

    def __init__(self, path: str | Path = DEFAULT_LOG_FILE) -> None:
        self.path = Path(path)

    def write(self, record: PacketRecord) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        is_empty = not self.path.exists() or self.path.stat().st_size == 0
        with self.path.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=NETWORK_FIELDS)
            if is_empty:
                writer.writeheader()
            writer.writerow(record.to_row())


class PacketProcessor:
    """Extract packet metadata and feed explainable detections."""

    def __init__(
        self,
        *,
        alert_store: CsvAlertStore | None = None,
        packet_store: CsvPacketStore | None = None,
        scan_detector: PortScanDetector | None = None,
        emit_console: bool = True,
    ) -> None:
        self.alert_store = alert_store or CsvAlertStore()
        self.packet_store = packet_store or CsvPacketStore()
        self.scan_detector = scan_detector or PortScanDetector()
        self.emit_console = emit_console

    def process(self, packet: Any) -> PacketRecord | None:
        """Process one Scapy packet; return ``None`` for non-IP traffic."""

        if not packet.haslayer("IP"):
            return None

        observed_at = _packet_timestamp(packet)
        ip_layer = packet.getlayer("IP")
        source_ip = str(ip_layer.src)
        destination_ip = str(ip_layer.dst)
        protocol = "OTHER"
        source_port: int | str = ""
        destination_port: int | str = ""

        if packet.haslayer("TCP"):
            transport_layer = packet.getlayer("TCP")
            protocol = "TCP"
            source_port = int(transport_layer.sport)
            destination_port = int(transport_layer.dport)
        elif packet.haslayer("UDP"):
            transport_layer = packet.getlayer("UDP")
            protocol = "UDP"
            source_port = int(transport_layer.sport)
            destination_port = int(transport_layer.dport)

        record = PacketRecord(
            observed_at,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
        )
        self.packet_store.write(record)

        if isinstance(destination_port, int):
            detect_threat(
                destination_port,
                source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
                observed_at=observed_at,
                alert_store=self.alert_store,
                emit_console=self.emit_console,
            )
            scan_event = self.scan_detector.observe(
                source_ip,
                destination_port,
                observed_at=observed_at,
            )
            if scan_event is not None:
                alert = ThreatAlert(
                    timestamp=observed_at,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    protocol=protocol,
                    port=destination_port,
                    service="Multiple services",
                    severity="High",
                    category="Network discovery",
                    description=(
                        f"Observed {scan_event.unique_ports} unique destination ports "
                        f"within {scan_event.window_seconds} seconds."
                    ),
                )
                self.alert_store.write(alert)
                if self.emit_console:
                    print(
                        f"PORT-SCAN SIGNAL: {source_ip} touched "
                        f"{scan_event.unique_ports} unique ports"
                    )

        if self.emit_console:
            print(
                f"{source_ip} -> {destination_ip} | {protocol} | "
                f"{source_port} -> {destination_port}"
            )
        return record


def _packet_timestamp(packet: Any) -> datetime:
    raw_timestamp = getattr(packet, "time", None)
    if raw_timestamp is None:
        return datetime.now(timezone.utc)
    return datetime.fromtimestamp(float(raw_timestamp), tz=timezone.utc)


def run_capture(
    *,
    interface: str | None = None,
    packet_count: int = 0,
    capture_filter: str = "ip and (tcp or udp)",
    emit_console: bool = True,
) -> None:
    """Start packet capture. Administrator/root privileges may be required."""

    # Scapy may inspect host interfaces during import, so keep it outside the
    # testable packet-processing core and load it only for a live capture.
    from scapy.all import sniff

    processor = PacketProcessor(emit_console=emit_console)
    sniff_options: dict[str, Any] = {
        "prn": processor.process,
        "store": False,
        "count": packet_count,
    }
    if interface:
        sniff_options["iface"] = interface
    if capture_filter:
        sniff_options["filter"] = capture_filter
    sniff(**sniff_options)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture network metadata and generate SentinelNet alerts"
    )
    parser.add_argument(
        "--interface", help="Network interface name (uses Scapy default if omitted)"
    )
    parser.add_argument(
        "--count", type=int, default=0, help="Packets to capture; 0 runs continuously"
    )
    parser.add_argument(
        "--filter",
        default="ip and (tcp or udp)",
        help="BPF capture filter",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress per-packet console output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.count < 0:
        print("--count cannot be negative", file=sys.stderr)
        return 2

    print("SentinelNet monitoring started. Press Ctrl+C to stop.")
    try:
        run_capture(
            interface=args.interface,
            packet_count=args.count,
            capture_filter=args.filter,
            emit_console=not args.quiet,
        )
    except KeyboardInterrupt:
        print("\nCapture stopped.")
    except (OSError, PermissionError) as exc:
        print(f"Capture failed: {exc}", file=sys.stderr)
        print("Try an elevated terminal and verify Npcap/libpcap is installed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
