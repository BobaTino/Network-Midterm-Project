from scapy.all import sniff, IP, DNS, DNSQR
from datetime import datetime
from logger import log_device_activity
from utils import *

devices = {}

WHITELIST_MACS = [
    "AA:BB:CC:DD:EE:FF"
]

ALLOWED_COUNTRIES = [
    "United States",
]

BLOCKED_DOMAINS = [
    "malware.com",
    "badsite.net",
    "phishing.org"
]

def init_device(ip):
    return {
        "mac": get_mac(ip),
        "first_seen": str(datetime.now()),
        "connections": set(),
        "protocols": set(),
        "domains": set(),
        "geo": [],
        "alerts": [],
        "dns_count": {},
        "local_ips": set(),
        "trust_score": 100
    }

def process_packet(packet):

    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if src_ip not in devices:
        devices[src_ip] = init_device(src_ip)
        devices[src_ip]["alerts"].append("New Device Detected")

    device = devices[src_ip]

    protocol = get_protocol(packet)

    device["connections"].add(dst_ip)
    device["protocols"].add(protocol)

    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        domain = packet[DNSQR].qname.decode(errors="ignore").lower()

        device["domains"].add(domain)

        # Blocked Domain Detection
        for bad in BLOCKED_DOMAINS:
            if bad in domain:
                add_alert(device, "HIGH: Contacted blocked domain")

        # Repeated DNS Requests
        device["dns_count"][domain] = device["dns_count"].get(domain, 0) + 1
        if device["dns_count"][domain] > 10:
            add_alert(device, "MEDIUM: Repeated DNS requests")

    geo = get_geoip(dst_ip)
    if geo:
        device["geo"].append({"ip": dst_ip, "info": geo})

        # Feature 3: Suspicious Country
        if geo.get("country") not in ALLOWED_COUNTRIES:
            add_alert(device, "MEDIUM: Traffic to foreign country")

    if dst_ip.startswith("192.168.") or dst_ip.startswith("10."):
        device["local_ips"].add(dst_ip)

    if len(device["local_ips"]) > 15:
        add_alert(device, "HIGH: Possible local network scan")

    # MAC Not Whitelisted
    if device["mac"] not in WHITELIST_MACS:
        add_alert(device, "LOW: Untrusted MAC address")

    # Too Many Connections
    if len(device["connections"]) > 20:
        add_alert(device, "MEDIUM: Too many connections")

    # Too Many Domains
    if len(device["domains"]) > 10:
        add_alert(device, "MEDIUM: Too many domains contacted")

    # Too Many Protocols
    if len(device["protocols"]) > 3:
        add_alert(device, "LOW: Unusual protocol usage")

    # Midnight Activity
    hour = datetime.now().hour
    if hour >= 1 and hour <= 5:
        add_alert(device, "LOW: Late-night activity")

    # New External IP
    if not dst_ip.startswith("192.168.") and not dst_ip.startswith("10."):
        if len(device["connections"]) > 15:
            add_alert(device, "LOW: Many outbound requests")

    # High Geo Requests
    if len(device["geo"]) > 30:
        add_alert(device, "MEDIUM: High external traffic")

    
    device["trust_score"] = max(0, 100 - len(device["alerts"]) * 5)
    log_device_activity(src_ip, device)

    print(f"[+] {src_ip} -> {dst_ip} ({protocol})")


print("Starting IoT Security Profiler...")
sniff(prn=process_packet, store=False)