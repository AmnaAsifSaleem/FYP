"""
CAVE-OT CVE Discovery Script
Reads assets.json and maps CVEs to each device
Runs automatically after smart_discover.py generates assets.json
"""

import joblib
from sklearn.metrics.pairwise import cosine_similarity
import json
import os
import sys

# ── Config ───────────────────────────────────────────────────────────────────
CAVE_DIR     = "/home/caveot/cave_ot_test"
MODEL_FOLDER = os.path.join(CAVE_DIR, "model")
ASSETS_FILE  = os.path.join(CAVE_DIR, "assets.json")
OUTPUT_FILE  = os.path.join(CAVE_DIR, "vulnerability_scan_results.json")
TOP_K        = 25
# ─────────────────────────────────────────────────────────────────────────────

def load_model():
    required = ["ot_vectorizer.pkl", "ot_matrix.pkl", "ot_cve_database.pkl"]
    for f in required:
        path = os.path.join(MODEL_FOLDER, f)
        if not os.path.exists(path):
            print(f"ERROR: Model file not found: {path}")
            print(f"Copy model files to {MODEL_FOLDER}/")
            sys.exit(1)

    print("Loading CAVE-OT model...")
    vectorizer   = joblib.load(os.path.join(MODEL_FOLDER, "ot_vectorizer.pkl"))
    matrix       = joblib.load(os.path.join(MODEL_FOLDER, "ot_matrix.pkl"))
    cve_database = joblib.load(os.path.join(MODEL_FOLDER, "ot_cve_database.pkl"))
    print("✓ Model loaded")
    return vectorizer, matrix, cve_database


def load_assets():
    if not os.path.exists(ASSETS_FILE):
        print(f"ERROR: {ASSETS_FILE} not found — run smart_discover.py first")
        sys.exit(1)

    with open(ASSETS_FILE, "r") as f:
        assets = json.load(f)

    if not assets:
        print("WARNING: assets.json is empty — nothing to scan")
        sys.exit(0)

    print(f"✓ Loaded {len(assets)} devices from assets.json")
    return assets


def run_cve_scan():
    vectorizer, matrix, cve_database = load_model()
    assets = load_assets()

    print("=" * 80)
    print("CAVE-OT VULNERABILITY DISCOVERY")
    print(f"Scanning {len(assets)} devices from asset inventory")
    print("=" * 80)

    all_results = []

    for i, asset in enumerate(assets, 1):
        vendor   = asset.get("vendor",   "")
        product  = asset.get("product",  "")
        firmware = asset.get("firmware", "")
        query    = f"{vendor} {product} {firmware}".strip()

        print(f"\n[Device {i}/{len(assets)}]")
        print(f"  IP:          {asset.get('ip','?')}:{asset.get('port','?')}")
        print(f"  Vendor:      {vendor}")
        print(f"  Product:     {product}")
        print(f"  Firmware:    {firmware}")
        print(f"  Service:     {asset.get('service','?')}")
        print(f"  Zone:        {asset.get('zone','?')}")
        print(f"  Criticality: {asset.get('criticality','?')}")
        print("-" * 80)

        query_vector = vectorizer.transform([query.lower()])
        scores       = cosine_similarity(query_vector, matrix).flatten()
        top_idx      = scores.argsort()[-TOP_K:][::-1]

        device_cves = []
        for idx in top_idx:
            cve = cve_database.iloc[idx]
            cve_info = {
                "cve_id": cve["cve_id"],
                "cvss":   float(cve["cvss"]),
                "epss":   float(cve["epss"]),
                "kev":    int(cve["kev"]),
            }
            device_cves.append(cve_info)
            print(f"  {cve_info['cve_id']}  cvss={cve_info['cvss']:.1f}  "
                  f"epss={cve_info['epss']:.3f}  kev={cve_info['kev']}")

        all_results.append({
            "device": asset,
            "query":  query,
            "cves":   device_cves,
        })

    output = {
        "scan_summary": {
            "total_devices":    len(assets),
            "total_cves_found": sum(len(r["cves"]) for r in all_results),
            "cves_per_device":  TOP_K,
        },
        "devices": all_results,
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)

    print("\n" + "=" * 80)
    print("✓ CVE SCAN COMPLETE")
    print("=" * 80)
    print(f"Scanned {len(assets)} devices")
    print(f"Found {sum(len(r['cves']) for r in all_results)} total CVE mappings")
    print(f"Results saved to: {OUTPUT_FILE}")

    for i, result in enumerate(all_results, 1):
        d = result["device"]
        print(f"  {i}. {d.get('vendor','')} {d.get('product','')} "
              f"({d.get('ip','?')}) — {len(result['cves'])} CVEs")


if __name__ == "__main__":
    run_cve_scan()
