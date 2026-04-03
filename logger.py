import json

LOG_FILE = "devices.json"

def log_device_activity(ip, data):
    try:
        with open(LOG_FILE, "r") as f:
            devices = json.load(f)
    except:
        devices = {}

    # Convert sets → lists
    clean_data = {
        "mac": data["mac"],
        "first_seen": data["first_seen"],
        "connections": list(data["connections"]),
        "protocols": list(data["protocols"]),
        "domains": list(data["domains"]),
        "geo": data["geo"],
        "alerts": data["alerts"]
    }

    devices[ip] = clean_data

    with open(LOG_FILE, "w") as f:
        json.dump(devices, f, indent=4)