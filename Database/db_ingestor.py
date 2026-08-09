"""
CAVE-OT Database Ingestor
=========================
Reads your pipeline JSON output and loads it into PostgreSQL.

Run from the Database folder:
    python db_ingestor.py                                  loads ../model_input.json
    python db_ingestor.py ../assets.json
    python db_ingestor.py ../vulnerability_scan_results.json
"""

import json
import sys
import os

# Add parent folder to path so we can find JSON files easily
PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from db_manager import load_devices_into_db, get_connection, get_dashboard_summary, test_connection

# ── Risk scoring (same logic as risk_scorer.py) ───────────────
ASSET_CRITICALITY = {
    'PLC': 1.00, 'RTU': 0.95, 'SCADA': 0.90, 'HMI': 0.80,
    'Engineering_WS': 0.70, 'Historian': 0.60, 'IT_Server': 0.40,
    'Generic': 0.30,
}

def calculate_risk(cve, device_type, alert_count=0, alert_severity=3):
    """Calculate risk score and tier for a CVE."""
    cvss = float(cve.get('cvss', 0))
    epss = float(cve.get('epss', 0))
    kev  = int(cve.get('kev', 0))
    c    = float(cve.get('c_impact', 0))
    i    = float(cve.get('i_impact', 0))
    a    = float(cve.get('a_impact', 0))

    if epss >= 0.70:   ecm = 1.00
    elif epss >= 0.40: ecm = 0.97
    elif epss >= 0.10: ecm = 0.94
    else:              ecm = 0.91

    rl       = 1.00 if kev else 0.95
    temporal = cvss * ecm * rl
    cia      = (c * 0.20) + (i * 0.30) + (a * 0.50)
    ac       = ASSET_CRITICALITY.get(device_type, 0.30)
    env      = min(temporal * cia * ac * 10, 10.0)
    if kev:
        env = min(env * 1.10, 10.0)

    sw    = {1: 1.00, 2: 0.60, 3: 0.30}.get(alert_severity, 0.30)
    sf    = min((alert_count * sw) / 30.0, 1.0) if alert_count > 0 else 0.0
    score = round(min(env + (sf * 1.5), 10.0), 1)

    if score >= 8.0:   tier = 'CRITICAL'
    elif score >= 6.0: tier = 'HIGH'
    elif score >= 4.0: tier = 'MEDIUM'
    else:              tier = 'LOW'

    return score, tier


def load_json_file(filepath):
    """
    Load devices from any pipeline JSON format.
    Handles model_input.json, assets.json, vulnerability_scan_results.json.
    """
    with open(filepath, 'r') as f:
        data = json.load(f)

    # vulnerability_scan_results.json format  (has nested 'device' key)
    if isinstance(data, dict) and 'devices' in data:
        devices = []
        for entry in data['devices']:
            if 'device' in entry:
                # vulnerability_scan_results.json
                device = dict(entry['device'])
                device['cves'] = entry.get('cves', [])
            else:
                # risk_scored_results.json (flat device object with cves inline)
                device = dict(entry)
            devices.append(device)
        return devices

    # model_input.json or assets.json format (plain list)
    if isinstance(data, list):
        return data

    raise ValueError(f"Unknown JSON format in {filepath}")


def enrich_risk_scores(devices):
    """Add risk_score and risk_tier to any CVE that is missing them."""
    for device in devices:
        device_type    = device.get('device_type', 'Generic')
        alert_count    = device.get('alert_count', 0)
        alert_severity = device.get('alert_severity', 3)
        for cve in device.get('cves', []):
            if not cve.get('risk_score'):
                score, tier = calculate_risk(cve, device_type, alert_count, alert_severity)
                cve['risk_score'] = score
                cve['risk_tier']  = tier
            elif not cve.get('risk_tier'):
                s = cve['risk_score']
                if s >= 8.0:   cve['risk_tier'] = 'CRITICAL'
                elif s >= 6.0: cve['risk_tier'] = 'HIGH'
                elif s >= 4.0: cve['risk_tier'] = 'MEDIUM'
                else:          cve['risk_tier'] = 'LOW'
    return devices


def main():
    # Default file is model_input.json in the parent folder
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        # If relative path given, look in parent folder first
        if not os.path.isabs(filepath) and not os.path.exists(filepath):
            filepath = os.path.join(PARENT_DIR, sys.argv[1])
    else:
        filepath = os.path.join(PARENT_DIR, "model_input.json")

    print("=" * 55)
    print("CAVE-OT DATABASE INGESTOR")
    print("=" * 55)
    print(f"\nFile: {filepath}")

    if not os.path.exists(filepath):
        print(f"\nERROR: File not found: {filepath}")
        sys.exit(1)

    print("\nTesting database connection...")
    if not test_connection():
        print("Cannot connect. Check DB_CONFIG in db_manager.py")
        sys.exit(1)

    print(f"\nLoading {os.path.basename(filepath)}...")
    devices = load_json_file(filepath)
    total_cves = sum(len(d.get('cves', [])) for d in devices)
    print(f"  Devices : {len(devices)}")
    print(f"  CVEs    : {total_cves}")

    devices = enrich_risk_scores(devices)

    print("\nSaving to database...")
    stats = load_devices_into_db(devices)
    print(f"  Assets saved : {stats['assets_saved']}")
    print(f"  CVEs saved   : {stats['cves_saved']}")

    if stats['errors']:
        print(f"\n  Errors:")
        for err in stats['errors']:
            print(f"    - {err}")

    print("\n" + "=" * 55)
    print("DATABASE SUMMARY")
    print("=" * 55)
    conn = get_connection()
    s = get_dashboard_summary(conn)
    conn.close()
    print(f"  Total assets  : {s['total_assets']}")
    print(f"  Active assets : {s['active_assets']}")
    print(f"  Total CVEs    : {s['total_cves']}")
    print(f"  Critical CVEs : {s['critical_cves']}")
    print(f"  High CVEs     : {s['high_cves']}")
    print(f"  Total alerts  : {s['total_alerts']}")
    print("\nDone.")


if __name__ == "__main__":
    main()
