"""
Policy compliance test against all assets in assets.json
enriched with CVE data from vulnerability_scan_results.json
"""
import json, os, sys
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "Policy_Compliance"))
from policy_predictor import PolicyCompliancePredictor

ASSETS_FILE  = "Assets/assets.json"
SCAN_FILE    = "Assets/vulnerability_scan_results.json"

# ── service → IPMI not in INSECURE list but has no encryption either
EXTRA_INSECURE = {"IPMI"}  # added separately below

# ── load data ────────────────────────────────────────────────────────────────
with open(ASSETS_FILE, encoding='utf-8-sig') as f: assets = json.load(f)
with open(SCAN_FILE)    as f: scan   = json.load(f)

# build cve lookup keyed by device_type
cve_by_type = {}
for entry in scan.get("devices", []):
    dt   = entry["device"]["device_type"]
    cves = entry.get("cves", [])
    if cves:
        cve_by_type[dt] = cves

# protocol encryption map — known insecure protocols
INSECURE = {"Modbus", "S7comm", "DNP3", "BACnet", "HTTP", "Telnet",
            "FTP", "SNMP_v1", "SNMP_v2", "IPMI"}

# ── build feature rows ───────────────────────────────────────────────────────
# Map device types not in the model's training set to closest known class
DT_MAP = {
    "SCADA_Server":         "HMI",
    "UV_Disinfection_PLC":  "PLC",
    "Dosing_Pump_PLC":      "PLC",
    "Filtration_PLC":       "PLC",
    "Booster_Pump_PLC":     "PLC",
    "Turbidity_Sensor_PLC": "Sensor",
    "WaterQuality_Sensor":  "Sensor",
    "Water_Level_RTU":      "RTU",
    "Flow_Meter_RTU":       "RTU",
    "HMI_Interface":        "HMI",
    "Backup_HMI_Interface": "HMI",
    "Ventilation_Controller": "PLC",
}

rows = []
for asset in assets:
    dt      = asset.get("device_type", "Generic")
    dt_model = DT_MAP.get(dt, dt)   # normalised for model
    cves    = cve_by_type.get(dt, [])
    service = asset.get("service", "Unknown")

    if cves:
        avg_cvss     = sum(c["cvss"] for c in cves) / len(cves)
        avg_epss     = sum(c["epss"] for c in cves) / len(cves)
        has_kev      = int(any(c["kev"] == 1 for c in cves))
        # CIA from scored results if available, else 0
        avg_c = avg_i = avg_a = 0.0
    else:
        avg_cvss = avg_epss = 0.0
        has_kev  = 0
        avg_c = avg_i = avg_a = 0.0

    rows.append({
        "device_type":      dt_model,
        "vendor":           asset.get("vendor", "Unknown"),
        "zone":             asset.get("zone", "OT"),
        "service":          service,
        "port":             asset.get("port", 0),
        "encrypted":        0 if service in INSECURE else 1,
        "cvss":             round(avg_cvss, 3),
        "epss":             round(avg_epss, 5),
        "kev":              has_kev,
        "c_impact":         avg_c,
        "i_impact":         avg_i,
        "a_impact":         avg_a,
        "criticality":      asset.get("criticality", 0.5),
        "days_since_patch": 45,   # conservative default
        "firmware_eol":     0,
        "alert_count":      0,
        # keep for display only
        "_name":  f"{asset.get('vendor','')} {asset.get('product','')}",
        "_ip":    asset.get("ip", "?"),
    })

# ── predict ──────────────────────────────────────────────────────────────────
predictor = PolicyCompliancePredictor()

display_cols = ["_name", "_ip"]
feature_cols = [k for k in rows[0] if not k.startswith("_")]

df_features = pd.DataFrame(rows)[feature_cols]
results     = predictor.predict(df_features)

# ── print results ─────────────────────────────────────────────────────────────
print("\n" + "=" * 90)
print("POLICY COMPLIANCE RESULTS — ALL ASSETS")
print("=" * 90)
print(f"  {'Asset':<32} {'IP':<15} {'Zone':<4} {'Service':<10} "
      f"{'Status':<14} {'Score':>5}  {'Conf':>5}  Explanation")
print("  " + "-" * 88)

compliant = non_compliant = 0
for row, result in zip(rows, results):
    status = result["compliance_status"]
    score  = result["compliance_score"]
    conf   = result["confidence"]
    expl   = result["explanation"]
    icon   = "✅" if status == "COMPLIANT" else "❌"
    if status == "COMPLIANT": compliant += 1
    else: non_compliant += 1

    print(f"  {icon} {row['_name'][:30]:<30} {row['_ip']:<15} {row['zone']:<4} "
          f"{row['service']:<10} {status:<14} {score:>5.3f}  {conf:>5.3f}")
    print(f"       {expl}")
    print()

print("=" * 90)
print(f"  Total: {len(rows)}  |  Compliant: {compliant}  |  Non-compliant: {non_compliant}")
print("=" * 90)

# ── save output ───────────────────────────────────────────────────────────────
out = []
for row, result in zip(rows, results):
    out.append({
        "asset":             row["_name"],
        "ip":                row["_ip"],
        "zone":              row["zone"],
        "service":           row["service"],
        "compliance_status": result["compliance_status"],
        "compliance_score":  result["compliance_score"],
        "confidence":        result["confidence"],
        "explanation":       result["explanation"],
        "avg_cvss":          row["cvss"],
        "avg_epss":          row["epss"],
        "encrypted":         row["encrypted"],
        "criticality":       row["criticality"],
    })

with open("Assets/policy_results.json", "w") as f:
    json.dump(out, f, indent=2)
print(f"\n  Saved → Assets/policy_results.json\n")
