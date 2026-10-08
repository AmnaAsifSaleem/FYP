"""
CAVE-OT Risk Scorer v2
Accepts vulnerability_scan_results format.
- Enriches CVEs with real c/i/a_impact from local OT+general databases
- Missing vectors/CIA remain explicit; see Reports/FORMULAS.md
- Sorts by risk_score DESC, then epss DESC as tiebreaker
"""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from contextual_risk import score_cve,score_details,VERSION
from ids_context import risk_context

import json
import sys
import os
import joblib

_HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_FOLDER = os.path.join(_HERE, "..", "model")

RISK_TIERS = [
    (9.0, "CRITICAL", "🔴"),
    (7.0, "HIGH",     "🟠"),
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
# Missing CIA stays unknown; no CVSS-band inference.

# Formula helpers
# ---------------------------------------------------------------------------





def get_risk_tier(score: float):
    for threshold, tier, emoji in RISK_TIERS:
        if score >= threshold:
            return tier, emoji
    return "LOW", "🟢"




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
            context=risk_context(device.get('alert_events',[]))
            details=score_details(cve,criticality,cia_lookup,
                weighted_alert_count=context['risk_alert_weighted_count'],
                security_requirements=device.get('cvss_requirements'))
            risk_score=details['risk_score']
            c,i,a,src=[details[k] for k in ('c_impact','i_impact','a_impact','cia_source')]
            tier, emoji = get_risk_tier(risk_score)
            if src == "db":
                db_hits += 1
            scored_cves.append({
                **cve,
                **details,
                "c_impact":   c,
                "i_impact":   i,
                "a_impact":   a,
                "cia_source": src,
                "risk_score": risk_score,
                "risk_tier":  tier,
                "risk_emoji": emoji,
            })

        # Preserve priority differences hidden by display capping/rounding.
        scored_cves.sort(key=lambda x: (x["priority_total"], x["epss"]), reverse=True)

        results.append({
            "ip":           ip,
            "device_type":  device_type,
            "vendor":       vendor,
            "product":      product,
            "criticality":  criticality,
            "cia_db_hits":  db_hits,
            "cia_unknown": sum(c["cia_source"]=="unknown" for c in scored_cves),
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
              f"  (DB lookup: {device['cia_db_hits']}  unknown: {device['cia_unknown']})")
        print(f"  {'CVE ID':<20} {'CVSS':>5}  {'EPSS':>7}  {'C / I / A':>13}  {'Risk':>5}  Tier")
        print(f"  {'-'*20} {'-'*5}  {'-'*7}  {'-'*13}  {'-'*5}  ----")
        for cve in cves:
            cia_str = f"{cve['c_impact']:.2f}/{cve['i_impact']:.2f}/{cve['a_impact']:.2f}"
            src_tag = " " if cve["cia_source"] == "db" else "*"
            print(f"  {cve['cve_id']:<20} {cve['cvss']:>5.1f}  {cve['epss']:>7.5f}"
                  f"  {cia_str:>13}{src_tag}  {cve['risk_score']:>5.1f}"
                  f"  {cve['risk_emoji']} {cve['risk_tier']}")
            risk_counts[cve["risk_tier"]] += 1

    print("\nUnknown CIA remains unknown; no CVSS-band inference")
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
