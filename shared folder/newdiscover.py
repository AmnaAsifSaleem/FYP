from scapy.all import rdpcap, IP, TCP, UDP, Raw
import json

PORT_MAP = {
    502:   {"service": "Modbus",  "device_type": "PLC",               "zone": "OT"},
    10201: {"service": "S7comm",  "device_type": "Siemens_PLC",       "zone": "OT"},
    47808: {"service": "BACnet",  "device_type": "BACnet_Controller", "zone": "OT"},
    20000: {"service": "DNP3",    "device_type": "RTU",               "zone": "OT"},
    6230:  {"service": "IPMI",    "device_type": "Server",            "zone": "IT"},
    22:    {"service": "SSH",     "device_type": "Linux_Server",      "zone": "IT"},
}

CONPOT_CONFIG = {
    502:   {"vendor": "Schneider Electric", "product": "Modicon M340", "firmware": "2.39"},
    10201: {"vendor": "Siemens",            "product": "S7-300",       "firmware": "V3.2.5"},
    47808: {"vendor": "Siemens",            "product": "APOGEE PXC",   "firmware": "1.2"},
    6230:  {"vendor": "Dell",               "product": "iDRAC",        "firmware": "2.40.40"},
}

VERSION_CVES = [
    ("schneider", "2.40", "CVE-2019-10915", 8.8),
    ("schneider", "4.00", "CVE-2020-7537",  7.5),
    ("schneider", "3.00", "CVE-2018-10952", 6.5),
    ("siemens",   "4.0",  "CVE-2019-13945", 9.8),
    ("siemens",   "5.0",  "CVE-2016-9158",  7.5),
    ("dell",      "3.00", "CVE-2013-4786",  10.0),
]

CRITICALITY_MAP = {
    "PLC":               0.90,
    "Siemens_PLC":       0.95,
    "BACnet_Controller": 0.50,
    "RTU":               0.85,
    "Server":            0.60,
    "Linux_Server":      0.55,
}

def is_vulnerable(firmware, max_version):
    try:
        fw = [int(x) for x in firmware.replace('V','').replace('v','').split('.')]
        mx = [int(x) for x in max_version.replace('V','').replace('v','').split('.')]
        while len(fw) < 3: fw.append(0)
        while len(mx) < 3: mx.append(0)
        return fw < mx
    except:
        return False

def map_cves(vendor, firmware):
    matched = []
    if not vendor or not firmware:
        return matched
    for keyword, max_ver, cve_id, cvss in VERSION_CVES:
        if keyword in vendor.lower():
            if is_vulnerable(firmware, max_ver):
                matched.append({
                    "cve_id": cve_id,
                    "cvss":   cvss,
                    "reason": f"firmware {firmware} < {max_ver}"
                })
    return matched

def run(pcap_file):
    print(f"\n[*] Reading: {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"[*] Packets loaded: {len(packets)}")

    # KEY CHANGE: use IP+Port as key
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

        # Use IP:Port as unique key
        # This fixes same IP multiple services
        asset_key = f"{actual_dst}:{actual_port}"

        if asset_key not in assets:
            a = PORT_MAP[actual_port].copy()
            a["ip"]           = actual_dst
            a["port"]         = actual_port
            a["talkers"]      = set()
            a["packet_count"] = 0

            if actual_port in CONPOT_CONFIG:
                a.update(CONPOT_CONFIG[actual_port])
                a["id_method"] = "conpot_config"
            else:
                a["vendor"]    = "Unknown"
                a["product"]   = "Unknown"
                a["firmware"]  = "Unknown"
                a["id_method"] = "port_only"

            a["criticality"] = CRITICALITY_MAP.get(
                a["device_type"], 0.5
            )

            a["cves"] = map_cves(
                a.get("vendor",   ""),
                a.get("firmware", "")
            )

            assets[asset_key] = a

        assets[asset_key]["talkers"].add(src)
        assets[asset_key]["packet_count"] += 1

    return assets

def show(assets):
    print("\n" + "="*60)
    print("     PORT → SERVICE → VERSION → CVE OUTPUT")
    print("="*60)

    ml_records = []

    for key, a in assets.items():
        print(f"\n  IP           : {a['ip']}")
        print(f"  Port         : {a['port']}")
        print(f"  Service      : {a['service']}")
        print(f"  Device Type  : {a['device_type']}")
        print(f"  Zone         : {a['zone']}")
        print(f"  Vendor       : {a.get('vendor',   'Unknown')}")
        print(f"  Product      : {a.get('product',  'Unknown')}")
        print(f"  Firmware     : {a.get('firmware', 'Unknown')}")
        print(f"  Criticality  : {a.get('criticality', 0.5)}")
        print(f"  Packet Count : {a['packet_count']}")
        print(f"  Talkers      : {', '.join(a['talkers'])}")

        print(f"\n  CVEs Found   : {len(a['cves'])}")
        for cve in a["cves"]:
            print(f"    ✓ {cve['cve_id']} | CVSS {cve['cvss']} | {cve['reason']}")

        print("-"*60)

        for cve in a["cves"]:
            ml_records.append({
                "ip":             a["ip"],
                "port":           a["port"],
                "service":        a["service"],
                "device_type":    a["device_type"],
                "zone":           a["zone"],
                "vendor":         a.get("vendor"),
                "product":        a.get("product"),
                "firmware":       a.get("firmware"),
                "criticality":    a.get("criticality"),
                "cve_id":         cve["cve_id"],
                "cvss":           cve["cvss"],
                "epss":           None,
                "kev_listed":     None,
                "alert_count":    0,
                "alert_severity": 0,
                "is_attacked":    0,
                "risk_score":     None,
            })

    with open("model_input.json", "w") as f:
        json.dump(ml_records, f, indent=2)

    print(f"\n[+] Total assets discovered : {len(assets)}")
    print(f"[+] Total CVE records       : {len(ml_records)}")
    print(f"[+] Saved to model_input.json")
    print(f"[+] Ready for next step: EPSS + NVD API")

if __name__ == "__main__":
    assets = run("test_all.pcap")
    show(assets)