import sys
import os

sys.path.append(
    os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            ".."
        )
    )
)

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from detection_engine.detector import detect_threat
import csv
# =====================================================
# LOG FILE
# =====================================================

LOG_FILE = "logs/network_log.csv"

# Create log file if it doesn't exist
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            "Source IP",
            "Destination IP",
            "Protocol",
            "Source Port",
            "Destination Port"
        ])

# =====================================================
# PACKET PROCESSING
# =====================================================

def process_packet(packet):

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = "OTHER"
    src_port = ""
    dst_port = ""

    # -----------------------------
    # TCP PACKETS
    # -----------------------------
    if packet.haslayer(TCP):

        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        detect_threat(src_port, src_ip)
        detect_threat(dst_port, src_ip)

    # -----------------------------
    # UDP PACKETS
    # -----------------------------
    elif packet.haslayer(UDP):

        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

        detect_threat(src_port, src_ip)
        detect_threat(dst_port, src_ip)

    # -----------------------------
    # DISPLAY PACKET
    # -----------------------------
    print(
        f"{src_ip} -> {dst_ip} | "
        f"{protocol} | "
        f"{src_port} -> {dst_port}"
    )

    # -----------------------------
    # SAVE TO LOG FILE
    # -----------------------------
    with open(LOG_FILE, "a", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port
        ])


# =====================================================
# START MONITORING
# =====================================================

print("=" * 50)
print("🛡 SentinelNet Threat Monitoring Started")
print("=" * 50)

sniff(
    prn=process_packet,
    store=False
)