from __future__ import annotations

import csv
from dataclasses import dataclass

import packet_capture.capture as capture_module
from detection_engine.detector import CsvAlertStore
from detection_engine.port_scan import PortScanDetector
from packet_capture.capture import CsvPacketStore, PacketProcessor, main


@dataclass
class FakeLayer:
    src: str = ""
    dst: str = ""
    sport: int = 0
    dport: int = 0


class FakePacket:
    def __init__(
        self,
        *,
        source_ip: str,
        destination_ip: str,
        source_port: int,
        destination_port: int,
        protocol: str = "TCP",
    ) -> None:
        self.time = 1_776_508_200
        self.layers = {
            "IP": FakeLayer(src=source_ip, dst=destination_ip),
            protocol: FakeLayer(sport=source_port, dport=destination_port),
        }

    def haslayer(self, name: str) -> bool:
        return name in self.layers

    def getlayer(self, name: str) -> FakeLayer:
        return self.layers[name]


class NonIpPacket:
    def haslayer(self, name: str) -> bool:
        return False


def build_processor(tmp_path, *, threshold: int = 10):
    alert_path = tmp_path / "alerts.csv"
    log_path = tmp_path / "network.csv"
    processor = PacketProcessor(
        alert_store=CsvAlertStore(alert_path),
        packet_store=CsvPacketStore(log_path),
        scan_detector=PortScanDetector(threshold=threshold),
        emit_console=False,
    )
    return processor, alert_path, log_path


def test_processor_logs_metadata_and_checks_destination_port_only(tmp_path) -> None:
    processor, alert_path, log_path = build_processor(tmp_path)
    benign_reply = FakePacket(
        source_ip="192.0.2.5",
        destination_ip="10.0.0.2",
        source_port=23,
        destination_port=443,
    )
    suspicious_request = FakePacket(
        source_ip="198.51.100.7",
        destination_ip="10.0.0.3",
        source_port=51000,
        destination_port=23,
    )

    processor.process(benign_reply)
    processor.process(suspicious_request)

    with log_path.open(encoding="utf-8") as handle:
        packet_rows = list(csv.DictReader(handle))
    with alert_path.open(encoding="utf-8") as handle:
        alert_rows = list(csv.DictReader(handle))

    assert len(packet_rows) == 2
    assert packet_rows[1]["DestinationPort"] == "23"
    assert len(alert_rows) == 1
    assert alert_rows[0]["SourceIP"] == "198.51.100.7"


def test_processor_emits_port_scan_alert(tmp_path) -> None:
    processor, alert_path, _ = build_processor(tmp_path, threshold=2)

    processor.process(
        FakePacket(
            source_ip="203.0.113.9",
            destination_ip="10.0.0.4",
            source_port=50000,
            destination_port=80,
        )
    )
    processor.process(
        FakePacket(
            source_ip="203.0.113.9",
            destination_ip="10.0.0.4",
            source_port=50001,
            destination_port=81,
        )
    )

    with alert_path.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["Category"] == "Network discovery"
    assert "2 unique destination ports" in rows[0]["Description"]


def test_cli_rejects_negative_packet_count(capsys) -> None:
    assert main(["--count", "-1"]) == 2
    assert "cannot be negative" in capsys.readouterr().err


def test_processor_handles_udp_and_ignores_non_ip(tmp_path) -> None:
    processor, _, log_path = build_processor(tmp_path)

    assert processor.process(NonIpPacket()) is None
    record = processor.process(
        FakePacket(
            source_ip="192.0.2.21",
            destination_ip="10.0.0.6",
            source_port=53000,
            destination_port=53,
            protocol="UDP",
        )
    )

    assert record is not None
    assert record.protocol == "UDP"
    assert log_path.exists()


def test_cli_handles_success_interrupt_and_capture_error(monkeypatch, capsys) -> None:
    monkeypatch.setattr(capture_module, "run_capture", lambda **_: None)
    assert main(["--count", "1", "--quiet"]) == 0

    def interrupt(**_):
        raise KeyboardInterrupt

    monkeypatch.setattr(capture_module, "run_capture", interrupt)
    assert main([]) == 0
    assert "Capture stopped" in capsys.readouterr().out

    def fail(**_):
        raise OSError("permission denied")

    monkeypatch.setattr(capture_module, "run_capture", fail)
    assert main([]) == 1
    assert "Capture failed" in capsys.readouterr().err
