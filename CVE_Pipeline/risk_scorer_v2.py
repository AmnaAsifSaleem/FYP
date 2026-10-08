"""
CAVE-OT Risk Scorer v2
Accepts vulnerability_scan_results format.
- Enriches CVEs with real c/i/a_impact from local OT+general databases
- Falls back to OT-context CVSS-band estimates when CVE not in database
- Sorts by risk_score DESC, then epss DESC as tiebreaker
"""

import json
import sys
import os
import joblib

_HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_FOLDER = os.path.join(_HERE, "..", "model")

RISK_TIERS = [
    (8.0, "CRITICAL", "🔴"),
    (6.0, "HIGH",     "🟠"),
    (4.0, "MEDIUM",   "🟡"),
    (0.0, "LOW",      "🟢"),
]
SEVERITY_WEIGHT = {1: 1.00, 2: 0.60, 3: 0.30}



# ---------------------------------------------------------------------------
# CIA lookup — built once from local pkl databases
# OT database takes precedence on conflict
# ---------------------------------------------------------------------------

def build_cia_lookup() -> dict:
    lookup = {}
    for fname in ("cve_database.pkl", "ot_cve_database.pkl"):
        path = os.path.join(MODEL_FOLDER, fname)
        if not os.path.exists(path):
            print(f"  [warn] {fname} not found, skipping")
            continue
        db = joblib.load(path)
        for _, row in db.iterrows():
            lookup[row["cve_id"]] = (
                float(row["c_impact"]),
                float(row["i_impact"]),
                float(row["a_impact"]),
            )
    return lookup


# ---------------------------------------------------------------------------
# CIA fallback — OT-context bands when CVE is absent from local database
#
#  CVSS >= 9.0  → H/H/H  (0.56, 0.56, 0.56)  full impact
#  CVSS >= 7.0  → L/H/H  (0.22, 0.56, 0.56)  high A + I
#  CVSS >= 5.5  → N/L/H  (0.00, 0.22, 0.56)  availability dominant
#  CVSS >= 4.0  → N/L/L  (0.00, 0.22, 0.22)  low impact
#  CVSS <  4.0  → N/N/L  (0.00, 0.00, 0.22)  minimal
# ---------------------------------------------------------------------------

def cia_fallback(cvss: float):
    if cvss >= 9.0: return 0.56, 0.56, 0.56
    if cvss >= 7.0: return 0.22, 0.56, 0.56
    if cvss >= 5.5: return 0.00, 0.22, 0.56
    if cvss >= 4.0: return 0.00, 0.22, 0.22
    return 0.00, 0.00, 0.22



# ---------------------------------------------------------------------------
# Formula helpers
# ---------------------------------------------------------------------------

def get_exploit_maturity(epss: float) -> float:
    if epss >= 0.70: return 1.00
    if epss >= 0.40: return 0.97
    if epss >= 0.10: return 0.94
    return 0.91

def get_remediation_level(kev: int) -> float:
    return 1.00 if kev == 1 else 0.95

def calculate_cia_score(c: float, i: float, a: float) -> float:
    """OT-weighted CIA (NIST SP 800-82): C=20%, I=30%, A=50%"""
    return (c * 0.20) + (i * 0.30) + (a * 0.50)

def calculate_suricata_factor(alert_count: int, alert_severity: int) -> float:
    if alert_count == 0:
        return 0.0
    w = SEVERITY_WEIGHT.get(alert_severity, 0.30)
    return min((alert_count * w) / 30.0, 1.0)

def get_risk_tier(score: float):
    for threshold, tier, emoji in RISK_TIERS:
        if score >= threshold:
            return tier, emoji
    return "LOW", "🟢"

from contextual_risk import score_cve


# ---------------------------------------------------------------------------
# Main processing
# ---------------------------------------------------------------------------

def process(input_path: str, output_path: str, cia_lookup: dict):
    with open(input_path, "r") as f:
        data = json.load(f)

    results = []

    for entry in data.get("devices", []):
        device      = entry.get("device", {})
        cves_raw    = entry.get("cves", [])
        ip          = device.get("ip", "unknown")
        device_type = device.get("device_type", "Generic")
        vendor      = device.get("vendor", "")
        product     = device.get("product", "")
        criticality = device.get("criticality", 0.30)
        alert_count = device.get("alert_count", 0)
        alert_sev   = device.get("alert_severity", 3)

        db_hits = 0
        scored_cves = []
        for cve in cves_raw:
            risk_score, c, i, a, src = score_cve(
                cve, criticality, cia_lookup, alert_count, alert_sev
            )
            tier, emoji = get_risk_tier(risk_score)
            if src == "db":
                db_hits += 1
            scored_cves.append({
                **cve,
                "c_impact":   c,
                "i_impact":   i,
                "a_impact":   a,
                "cia_source": src,
                "risk_score": risk_score,
                "risk_tier":  tier,
                "risk_emoji": emoji,
            })

        # Primary: risk_score DESC  |  Tiebreaker: epss DESC
        scored_cves.sort(key=lambda x: (x["risk_score"], x["epss"]), reverse=True)

        results.append({
            "ip":           ip,
            "device_type":  device_type,
            "vendor":       vendor,
            "product":      product,
            "criticality":  criticality,
            "cia_db_hits":  db_hits,
            "cia_fallback": len(scored_cves) - db_hits,
            "cves":         scored_cves,
        })

    with open(output_path, "w") as f:
        json.dump({"devices": results}, f, indent=2)

    return results


def print_summary(results: list):
    print("\n" + "=" * 74)
    print("CAVE-OT RISK SCORING RESULTS")
    print("=" * 74)

    total_cves  = 0
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for device in results:
        cves = device["cves"]
        total_cves += len(cves)
        print(f"\n{device['device_type']}  |  {device['vendor']} {device['product']}")
        print(f"  Criticality: {device['criticality']}  |  CVEs: {len(cves)}"
              f"  (DB lookup: {device['cia_db_hits']}  estimated: {device['cia_fallback']})")
        print(f"  {'CVE ID':<20} {'CVSS':>5}  {'EPSS':>7}  {'C / I / A':>13}  {'Risk':>5}  Tier")
        print(f"  {'-'*20} {'-'*5}  {'-'*7}  {'-'*13}  {'-'*5}  ----")
        for cve in cves:
            cia_str = f"{cve['c_impact']:.2f}/{cve['i_impact']:.2f}/{cve['a_impact']:.2f}"
            src_tag = " " if cve["cia_source"] == "db" else "*"
            print(f"  {cve['cve_id']:<20} {cve['cvss']:>5.1f}  {cve['epss']:>7.5f}"
                  f"  {cia_str:>13}{src_tag}  {cve['risk_score']:>5.1f}"
                  f"  {cve['risk_emoji']} {cve['risk_tier']}")
            risk_counts[cve["risk_tier"]] += 1

    print("\n* = CIA estimated from CVSS band (CVE not in local database)")
    print("\n" + "=" * 74)
    print(f"Total devices : {len(results)}")
    print(f"Total CVEs    : {total_cves}")
    print(f"  🔴 CRITICAL : {risk_counts['CRITICAL']}")
    print(f"  🟠 HIGH     : {risk_counts['HIGH']}")
    print(f"  🟡 MEDIUM   : {risk_counts['MEDIUM']}")
    print(f"  🟢 LOW      : {risk_counts['LOW']}")
    print("=" * 74)


if __name__ == "__main__":
    input_file  = sys.argv[1] if len(sys.argv) > 1 else "Assets/vulnerability_scan_results.json"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "Assets/risk_scored_results.json"

    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found")
        sys.exit(1)

    print("Loading CIA lookup from local database...")
    cia_lookup = build_cia_lookup()
    print(f"  ✓ {len(cia_lookup):,} CVEs loaded")

    print(f"Scoring CVEs from: {input_file}")
    results = process(input_file, output_file, cia_lookup)
    print_summary(results)
    print(f"\nOutput saved to: {output_file}")
