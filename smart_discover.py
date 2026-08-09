from scapy.all import rdpcap, IP, TCP, UDP
import json
import re

PORT_MAP = {
    502:   {"service": "Modbus",  "device_type": "Dosing_Pump_PLC",        "zone": "OT"},
    10201: {"service": "S7comm",  "device_type": "Filtration_PLC",         "zone": "OT"},
    47808: {"service": "BACnet",  "device_type": "Ventilation_Controller",  "zone": "OT"},
    20000: {"service": "DNP3",    "device_type": "Water_Level_RTU",         "zone": "OT"},
    5020:  {"service": "Modbus",  "device_type": "WaterQuality_Sensor",     "zone": "OT"},
    6230:  {"service": "IPMI",    "device_type": "SCADA_Server",            "zone": "IT"},
    80:    {"service": "HTTP",    "device_type": "HMI_Interface",           "zone": "IT"},
    5031:  {"service": "Modbus",  "device_type": "Turbidity_Sensor_PLC",   "zone": "OT"},
    5032:  {"service": "Modbus",  "device_type": "UV_Disinfection_PLC",    "zone": "OT"},
    10203: {"service": "S7comm",  "device_type": "Reservoir_Level_PLC",    "zone": "OT"},
    10204: {"service": "S7comm",  "device_type": "Booster_Pump_PLC",       "zone": "OT"},
    20001: {"service": "DNP3",    "device_type": "Flow_Meter_RTU",         "zone": "OT"},
    8080:  {"service": "HTTP",    "device_type": "Backup_HMI_Interface",   "zone": "IT"},
    443:   {"service": "HTTPS",   "device_type": "Historian",              "zone": "IT"},
    2222:  {"service": "SSH",     "device_type": "Engineering_WS",         "zone": "IT"},
}

CONPOT_CONFIG = {
    502: {
        "vendor":      "Schneider Electric",
        "product":     "Modicon M340",
        "firmware":    "2.39",
        "description": "Chemical dosing pump controller"
    },
    10201: {
        "vendor":      "Siemens",
        "product":     "S7-300",
        "firmware":    "V3.2.5",
        "description": "Water filtration system PLC"
    },
    47808: {
        "vendor":      "Siemens",
        "product":     "APOGEE PXC",
        "firmware":    "1.2",
        "description": "Chemical storage ventilation"
    },
    20000: {
        "vendor":      "General Electric",
        "product":     "D20MX",
        "firmware":    "8.0",
        "description": "Remote water level RTU"
    },
    5020: {
        "vendor":      "Schneider Electric",
        "product":     "Modicon M221",
        "firmware":    "1.8",
        "description": "Water quality sensor controller"
    },
    6230: {
        "vendor":      "Dell",
        "product":     "iDRAC 8",
        "firmware":    "2.40.40",
        "description": "SCADA server remote management"
    },
    80: {
        "vendor":      "Siemens",
        "product":     "WinCC OA",
        "firmware":    "3.17",
        "description": "Plant engineer HMI web interface"
    },
    5031: {
        "vendor":      "Schneider Electric",
        "product":     "Modicon M221",
        "firmware":    "1.6",
        "description": "Water turbidity monitoring sensor"
    },
    5032: {
        "vendor":      "Schneider Electric",
        "product":     "Modicon M340",
        "firmware":    "2.10",
        "description": "UV disinfection system controller"
    },
    10203: {
        "vendor":      "Siemens",
        "product":     "S7-1200",
        "firmware":    "V4.1",
        "description": "Reservoir water level controller"
    },
    10204: {
        "vendor":      "Siemens",
        "product":     "S7-300",
        "firmware":    "V3.1",
        "description": "Booster pump station controller"
    },
    20001: {
        "vendor":      "General Electric",
        "product":     "D20MX",
        "firmware":    "7.5",
        "description": "Distribution network flow meter RTU"
    },
    8080: {
        "vendor":      "Siemens",
        "product":     "WinCC OA",
        "firmware":    "3.15",
        "description": "Backup HMI for emergency operations"
    },
    443: {
        "vendor":      "OSIsoft",
        "product":     "PI Server",
        "firmware":    "3.4.400",
        "description": "Plant data historian secure web interface"
    },
    2222: {
        "vendor":      "Cisco",
        "product":     "ASA Firewall",
        "firmware":    "9.16.4",
        "description": "Network DMZ gateway SSH management"
    },
}

CRITICALITY_MAP = {
    "Filtration_PLC":         0.98,
    "Dosing_Pump_PLC":        0.97,
    "UV_Disinfection_PLC":    0.96,
    "SCADA_Server":           0.95,
    "Booster_Pump_PLC":       0.93,
    "Reservoir_Level_PLC":    0.91,
    "Water_Level_RTU":        0.90,
    "WaterQuality_Sensor":    0.88,
    "Flow_Meter_RTU":         0.87,
    "Turbidity_Sensor_PLC":   0.84,
    "HMI_Interface":          0.70,
    "Backup_HMI_Interface":   0.65,
    "Historian":              0.60,
    "Ventilation_Controller": 0.55,
    "Engineering_WS":         0.55,
    "Linux_Server":           0.50,
}

def read_suricata_alerts(log_file="/var/log/suricata/fast.log"):
    alerts = []
    try:
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                msg_match  = re.search(r'\[\*\*\] \[.*?\] (.+?) \[\*\*\]', line)
                port_match = re.search(r'-> [\d\.]+:(\d+)', line)
                src_match  = re.search(r'(\d+\.\d+\.\d+\.\d+):\d+ -> ', line)
                if not msg_match or not port_match:
                    continue
                msg       = msg_match.group(1).strip()
                dest_port = int(port_match.group(1))
                src_ip    = src_match.group(1) if src_match else "unknown"
                if "Attack" in msg or "Rapid" in msg or "Brute" in msg:
                    severity = 1
                elif "Write" in msg:
                    severity = 2
                else:
                    severity = 3
                alerts.append({
                    "message":   msg,
                    "dest_port": dest_port,
                    "src_ip":    src_ip,
                    "severity":  severity
                })
    except Exception as e:
        print(f"[!] Suricata log error: {e}")
    return alerts

def discover_assets(pcap_file):
    print(f"[*] Reading: {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"[*] Packets loaded: {len(packets)}")
    assets = {}
    for pkt in packets:
        if IP not in pkt:
            continue
        src      = pkt[IP].src
        dst      = pkt[IP].dst
        port     = None
        src_port = None
        if TCP in pkt:
            port     = pkt[TCP].dport
            src_port = pkt[TCP].sport
        elif UDP in pkt:
            port     = pkt[UDP].dport
            src_port = pkt[UDP].sport
        if not port:
            continue
        actual_port = None
        actual_dst  = None
        if port in PORT_MAP:
            actual_port = port
            actual_dst  = dst
        elif src_port and src_port in PORT_MAP:
            actual_port = src_port
            actual_dst  = src
        if not actual_port:
            continue
        asset_key = f"{actual_dst}:{actual_port}"
        if asset_key not in assets:
            a = PORT_MAP[actual_port].copy()
            a["ip"]           = actual_dst
            a["port"]         = actual_port
            a["talkers"]      = set()
            a["packet_count"] = 0
            a["total_size"]   = 0
            if actual_port in CONPOT_CONFIG:
                a.update(CONPOT_CONFIG[actual_port])
            else:
                a["vendor"]      = "Unknown"
                a["product"]     = "Unknown"
                a["firmware"]    = "Unknown"
                a["description"] = ""
            a["criticality"] = CRITICALITY_MAP.get(a["device_type"], 0.5)
            assets[asset_key] = a
        assets[asset_key]["talkers"].add(src)
        assets[asset_key]["packet_count"] += 1
        assets[asset_key]["total_size"] += len(pkt)
    return assets

def run(pcap_file):
    print("\n" + "="*60)
    print("  STEP 1: Asset Discovery from PCAP")
    print("="*60)
    assets = discover_assets(pcap_file)
    print(f"[+] Discovered {len(assets)} assets")

    print("\n" + "="*60)
    print("  STEP 2: Reading Suricata Alerts")
    print("="*60)
    alerts = read_suricata_alerts()
    print(f"[+] Found {len(alerts)} alerts")

    assets_output   = []
    suricata_output = []

    for key, asset in assets.items():
        port           = asset["port"]
        asset_alerts   = [a for a in alerts if a["dest_port"] == port]
        alert_count    = len(asset_alerts)
        alert_severity = min((a["severity"] for a in asset_alerts), default=0)
        is_attacked    = 1 if any(a["severity"] == 1 for a in asset_alerts) else 0

        assets_output.append({
            "ip":           asset["ip"],
            "port":         port,
            "service":      asset["service"],
            "device_type":  asset["device_type"],
            "zone":         asset["zone"],
            "vendor":       asset.get("vendor"),
            "product":      asset.get("product"),
            "firmware":     asset.get("firmware"),
            "description":  asset.get("description"),
            "criticality":  asset["criticality"],
            "packet_count": asset["packet_count"],
            "talkers":      list(asset["talkers"]),
            "avg_packet_size": round(asset["total_size"] / asset["packet_count"], 1) if asset["packet_count"] else 0.0
        })

        suricata_output.append({
            "ip":             asset["ip"],
            "port":           port,
            "service":        asset["service"],
            "device_type":    asset["device_type"],
            "zone":           asset["zone"],
            "vendor":         asset.get("vendor"),
            "product":        asset.get("product"),
            "firmware":       asset.get("firmware"),
            "description":    asset.get("description"),
            "criticality":    asset["criticality"],
            "alert_count":    alert_count,
            "alert_severity": alert_severity,
            "is_attacked":    is_attacked,
            "alert_messages": [a["message"] for a in asset_alerts]
        })

    with open("assets.json", "w") as f:
        json.dump(assets_output, f, indent=2)
    print(f"\n[+] assets.json saved -> {len(assets_output)} assets")

    with open("suricata_context.json", "w") as f:
        json.dump(suricata_output, f, indent=2)
    print(f"[+] suricata_context.json saved -> {len(suricata_output)} assets")

    print("\n" + "="*60)
    print("  WATER TREATMENT PLANT - DISCOVERY SUMMARY")
    print("="*60)
    for a in assets_output:
        ctx      = next(s for s in suricata_output if s["port"] == a["port"])
        attacked = "UNDER ATTACK" if ctx["is_attacked"] else "Normal"
        print(f"\n  {a['device_type']}")
        print(f"  {a['vendor']} {a['product']} fw {a['firmware']}")
        print(f"  IP:Port     : {a['ip']}:{a['port']}")
        print(f"  Zone        : {a['zone']} | Criticality: {a['criticality']}")
        print(f"  Alerts      : {ctx['alert_count']} | {attacked}")
        print("-"*60)

    print(f"\n[+] Done. Feed assets.json into your model.")

if __name__ == "__main__":
    run("test_all.pcap")