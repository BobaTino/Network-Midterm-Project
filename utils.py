from scapy.all import ARP, Ether, srp
import requests

def get_mac(ip):
    try:
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        result = srp(packet, timeout=1, verbose=0)[0]
        if result:
            return result[0][1].hwsrc
    except:
        return "Unknown"

def get_protocol(packet):
    if packet.haslayer("TCP"):
        return "TCP"
    elif packet.haslayer("UDP"):
        return "UDP"
    else:
        return "Other"

def get_geoip(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if res["status"] == "success":
            return {
                "country": res.get("country"),
                "city": res.get("city"),
                "isp": res.get("isp")
            }
    except:
        pass
    return {}

def detect_anomaly(device):
    alerts = []

    if len(device.get("connections", [])) > 20:
        alerts.append("High number of connections")

    if len(device.get("domains", [])) > 10:
        alerts.append("Too many domains contacted")

    if len(device.get("geo", [])) > 30:
        alerts.append("High external communication")

    return alerts