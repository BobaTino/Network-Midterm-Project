from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
from datetime import datetime
from logger import log_device_activity
from utils import get_mac, get_protocol, get_geoip, detect_anomaly

devices = {}

def process_packet(packet):
    # DNS Parsing
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        domain = packet[DNSQR].qname.decode(errors="ignore")
        src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"

        if src_ip not in devices:
            devices[src_ip] = init_device(src_ip)

        devices[src_ip]["domains"].add(domain)

        print(f"[DNS] {src_ip} -> {domain}")

    # IP Traffic
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = get_protocol(packet)

        if src_ip not in devices:
            devices[src_ip] = init_device(src_ip)

        devices[src_ip]["connections"].add(dst_ip)
        devices[src_ip]["protocols"].add(protocol)

        # GeoIP lookup
        geo = get_geoip(dst_ip)
        if geo:
            devices[src_ip]["geo"].append({"ip": dst_ip, "info": geo})

        # Anomaly detection
        alerts = detect_anomaly(devices[src_ip])
        if alerts:
            devices[src_ip]["alerts"] = alerts
            print(f"[ALERT] {src_ip}: {alerts}")

        log_device_activity(src_ip, devices[src_ip])

        print(f"[+] {src_ip} -> {dst_ip} ({protocol})")


def init_device(ip):
    return {
        "mac": get_mac(ip),
        "first_seen": str(datetime.now()),
        "connections": set(),
        "protocols": set(),
        "domains": set(),
        "geo": [],
        "alerts": []
    }


print("Starting IoT Device Profiler...")
sniff(prn=process_packet, store=False)