import csv
import os
from datetime import datetime

SUSPICIOUS_PORTS = {
    21: ("FTP", "Medium"),
    23: ("Telnet", "High"),
    445: ("SMB", "High"),
    3389: ("RDP", "Medium"),
    4444: ("Metasploit", "Critical"),
    1337: ("Backdoor Activity", "Critical")
}

ALERT_FILE = "alerts/alerts.csv"

if not os.path.exists(ALERT_FILE):
    with open(ALERT_FILE, "w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            
    "Timestamp",
    "SourceIP",
    "Port",
    "Service",
    "Severity"
])

def detect_threat(port, source_ip):

    if port in SUSPICIOUS_PORTS:

        service, severity = SUSPICIOUS_PORTS[port]

        print("\n" + "=" * 40)
        print("⚠ SECURITY ALERT")
        print("=" * 40)
        print(f"Source IP: {source_ip}")
        print(f"Port     : {port}")
        print(f"Service  : {service}")
        print(f"Severity : {severity}")
        print("=" * 40)

        with open(ALERT_FILE, "a", newline="") as file:
            writer = csv.writer(file)

            writer.writerow([
                datetime.now(),
                source_ip,
                port,
                service,
                severity
            ])

        return True

    return False