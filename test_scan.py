from detection_engine.port_scan import detect_port_scan

for port in range(20, 35):
    detect_port_scan("192.168.1.100", port)