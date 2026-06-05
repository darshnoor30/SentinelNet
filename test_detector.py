from detection_engine.detector import detect_threat

print("=" * 50)
print("🛡 SentinelNet Threat Detection Test")
print("=" * 50)

# Simulated Threat Traffic

test_cases = [
    (3389, "192.168.1.100"),   # RDP
    (4444, "10.0.0.5"),        # Metasploit
    (445, "172.16.1.25"),      # SMB
    (23, "203.0.113.50"),      # Telnet
    (1337, "198.51.100.10")    # Backdoor Activity
]

for port, ip in test_cases:
    detect_threat(port, ip)

print("\n✅ Threat Detection Test Completed")