# AeroLink-Analyzer
A Python-based network traffic sniffer and logger designed for aviation enthusiasts to analyze real-time datalink communication.
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

# Log file path
LOG_FILE = "dashboard_log.txt"

def log_to_file(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def packet_callback(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER"
        
        # Local network traffic filter
        if src.startswith("192.168.1") or dst.startswith("192.168.1"):
            log_message = f"[DATALINK] {proto} | {src} -> {dst}"
            print(log_message)
            log_to_file(log_message)

print("--- AeroLink Analyzer Active [Logging to dashboard_log.txt] ---")
try:
    # Sniffing network packets
    sniff(filter="ip", prn=packet_callback, store=0)
except KeyboardInterrupt:
    print("\nAnalyzer stopped. Log saved.")
