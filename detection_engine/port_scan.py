from collections import defaultdict

ip_ports = defaultdict(set)

def check_port_scan(source_ip, port):

    ip_ports[source_ip].add(port)

    if len(ip_ports[source_ip]) >= 5:

        print("\n" + "=" * 50)
        print("⚠ POTENTIAL PORT SCAN DETECTED")
        print("=" * 50)
        print(f"Source IP: {source_ip}")
        print(f"Unique Ports: {len(ip_ports[source_ip])}")
        print("=" * 50)

        return True

    return False