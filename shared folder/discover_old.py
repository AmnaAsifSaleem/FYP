from scapy.all import rdpcap, IP, TCP, UDP, Raw
import json

# ── Port to Service Mapping ──────────────────────────
PORT_MAP = {
    502:   {"service": "Modbus",  "device_type": "PLC",         "zone": "OT"},
    102:   {"service": "S7comm",  "device_type": "Siemens_PLC", "zone": "OT"},
    47808: {"service": "BACnet",  "device_type": "BACnet_Controller", "zone": "OT"},
    20000: {"service": "DNP3",    "device_type": "RTU",         "zone": "OT"},
    623:   {"service": "IPMI",    "device_type": "Server",      "zone": "IT"},
    22:    {"service": "SSH",     "device_type": "Linux_Server","zone": "IT"},
}

# ── Conpot Version Config ────────────────────────────
CONPOT_CONFIG = {
    502:   {"vendor": "Schneider Electric", "product": "Modicon M340", "firmware": "2.39"},
    102:   {"vendor": "Siemens",            "product": "S7-300",       "firmware": "V3.2.5"},
    47808: {"vendor": "Siemens",            "product": "APOGEE PXC",   "firmware": "1.2"},
}

# ── Version Aware CVE Mapping ────────────────────────
VERSION_CVES = [
    ("schneider", "2.40", "CVE-2019-10915", 8.8),
    ("schneider", "4.00", "CVE-2020-7537",  7.5),
    ("schneider", "3.00", "CVE-2018-10952", 6.5),
    ("siemens",   "4.0",  "CVE-2019-13945", 9.8),
    ("siemens",   "5.0",  "CVE-2016-9158",  7.5),
]

# ── Version Comparison ───────────────────────────────
def is_vulnerable(firmware, max_version):
    try:
        fw  = [int(x) for x in firmware.replace('V','').split('.')]
        mx  = [int(x) for x in max_version.replace('V','').split('.')]
        while len(fw) < 3: fw.append(0)
        while len(mx) < 3: mx.append(0)
        return fw < mx
    except:
        return False

# ── CVE Mapping ──────────────────────────────────────
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

# ── Main Discovery ───────────────────────────────────
def run(pcap_file):
    print(f"\n[*] Reading: {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"[*] Packets: {len(packets)}")

    assets = {}

    for pkt in packets:
        if IP not in pkt:
            continue

        src  = pkt[IP].src
        dst  = pkt[IP].dst
        port = None

        if TCP in pkt:
            port = pkt[TCP].dport
        elif UDP in pkt:
            port = pkt[UDP].dport

        if not port:
            continue

        # Check both directions
        # Request: src → dst:502
        # Response: src:502 → dst
        actual_port = None
        actual_dst  = None

        if port in PORT_MAP:
            actual_port = port
            actual_dst  = dst
        elif TCP in pkt and pkt[TCP].sport in PORT_MAP:
            actual_port = pkt[TCP].sport
            actual_dst  = src

        if not actual_port:
            continue

        if actual_dst not in assets:
            a = PORT_MAP[actual_port].copy()
            a["ip"]      = actual_dst
            a["port"]    = actual_port
            a["talkers"] = set()

            if actual_port in CONPOT_CONFIG:
                a.update(CONPOT_CONFIG[actual_port])

            a["cves"] = map_cves(
                a.get("vendor", ""),
                a.get("firmware", "")
            )
            assets[actual_dst] = a

        assets[actual_dst]["talkers"].add(src)

    return assets

# ── Display Results ──────────────────────────────────
def show(assets):
    print("\n" + "="*55)
    print("   PORT → SERVICE → VERSION → CVE OUTPUT")
    print("="*55)

    ml_records = []

    for ip, a in assets.items():
        print(f"\n  IP       : {ip}")
        print(f"  Port     : {a['port']}")
        print(f"  Service  : {a['service']}")
        print(f"  Device   : {a['device_type']}")
        print(f"  Zone     : {a['zone']}")
        print(f"  Vendor   : {a.get('vendor','Unknown')}")
        print(f"  Product  : {a.get('product','Unknown')}")
        print(f"  Firmware : {a.get('firmware','Unknown')}")
        print(f"  Talkers  : {', '.join(a['talkers'])}")

        print(f"\n  CVEs Found: {len(a['cves'])}")
        for cve in a["cves"]:
            print(f"    ✓ {cve['cve_id']} | CVSS {cve['cvss']} | {cve['reason']}")

        print("-"*55)

        for cve in a["cves"]:
            ml_records.append({
                "ip":          ip,
                "port":        a["port"],
                "service":     a["service"],
                "device_type": a["device_type"],
                "zone":        a["zone"],
                "vendor":      a.get("vendor"),
                "product":     a.get("product"),
                "firmware":    a.get("firmware"),
                "cve_id":      cve["cve_id"],
                "cvss":        cve["cvss"],
                "epss":        None,
                "kev_listed":  None,
                "criticality": None,
                "risk_score":  None,
            })

    with open("model_input.json", "w") as f:
        json.dump(ml_records, f, indent=2)

    print(f"\n[+] {len(ml_records)} records saved to model_input.json")
    print("[+] Ready for next step: EPSS + NVD API")

# ── Run ───────────────────────────────────────────────
if __name__ == "__main__":
    assets = run("test.pcap")
    show(assets)