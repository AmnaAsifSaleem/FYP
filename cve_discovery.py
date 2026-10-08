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
from pipeline_paths import ENGINE_FOLDER
from cve_applicability import evaluate, known, identity, product_match
from validation import validate_asset, validate_cve
from snapshot_io import atomic_json
CAVE_DIR     = ENGINE_FOLDER
MODEL_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model")
ASSETS_FILE  = os.path.join(CAVE_DIR, "assets.json")
OUTPUT_FILE  = os.path.join(CAVE_DIR, "vulnerability_scan_results.json")
TOP_K        = 25
# ─────────────────────────────────────────────────────────────────────────────

def load_model(general=False):
    required = (["general_vectorizer.pkl", "general_matrix.pkl", "cve_database.pkl"]
                if general else ["ot_vectorizer.pkl", "ot_matrix.pkl", "ot_cve_database.pkl"])
    for f in required:
        path = os.path.join(MODEL_FOLDER, f)
        if not os.path.exists(path):
            print(f"ERROR: Model file not found: {path}")
            print(f"Copy model files to {MODEL_FOLDER}/")
            sys.exit(1)

    print("Loading CAVE-OT model...")
    vectorizer, matrix, cve_database = [joblib.load(os.path.join(MODEL_FOLDER, f)) for f in required]
    print("✓ Model loaded")
    return vectorizer, matrix, cve_database


class CandidateCorpus:
    """Name lookup prevents TF-IDF's top-k cutoff hiding known products."""
    def __init__(self, name, model):
        self.name = name
        self.vectorizer, self.matrix, self.database = model
        self.by_vendor = {}
        for index, vendor in enumerate(self.database['vendor']):
            self.by_vendor.setdefault(identity(vendor), []).append(index)
        # A preserved secondary affected product may use a different vendor.
        self.with_cpe = []
        if 'cpe_matches' in self.database.columns:
            self.with_cpe = [i for i, value in enumerate(self.database['cpe_matches'])
                             if isinstance(value, (str, list)) and value not in ('', '[]', [])]
        self.name_cache = {}

    def candidates(self, asset, query):
        scores = cosine_similarity(self.vectorizer.transform([query.lower()]), self.matrix).flatten()
        key = (identity(asset['vendor']), identity(asset['product']))
        if key not in self.name_cache:
            indexes = set(self.by_vendor.get(key[0], [])) | set(self.with_cpe)
            matched = []
            for index in indexes:
                record = self.database.iloc[index].to_dict()
                if product_match(asset['vendor'], asset['product'], record.get('vendor'), record.get('product')):
                    matched.append(index)
                elif record.get('cpe_matches') is not None and evaluate(asset, record)[0] != 'UNKNOWN':
                    matched.append(index)
            self.name_cache[key] = matched
        textual = [int(i) for i in scores.argsort()[-TOP_K:][::-1] if scores[i] >= .10]
        indexes = set(textual) | set(self.name_cache[key])
        return [(self.database.iloc[i].to_dict(), float(scores[i]))
                for i in sorted(indexes, key=lambda i: (-scores[i], i))]


def assess_asset(asset, corpora):
    asset = validate_asset(asset)
    query = ' '.join(str(asset.get(k) or '') for k in ('vendor', 'product', 'firmware')).strip()
    if not known(asset.get('vendor')) or not known(asset.get('product')):
        return {'device': asset, 'query': query, 'cves': [], 'assessment': 'UNKNOWN',
                'reason': 'Asset identity missing; absence of candidates does not establish safety.'}
    accepted, excluded = {}, {}
    for corpus in corpora:
        for record, similarity in corpus.candidates(asset, query):
            status, evidence = evaluate(asset, record)
            if status == 'UNKNOWN':
                continue
            if status == 'NOT_AFFECTED':
                excluded[record['cve_id']] = {'cve_id': record['cve_id'], 'applicability': status,
                                               'applicability_evidence': evidence}
                continue
            info = validate_cve({
                'cve_id': record['cve_id'], 'similarity': similarity, 'applicability': status,
                'applicability_evidence': evidence, 'description': str(record.get('description', '')),
                'cvss': float(record['cvss']), 'epss': float(record['epss']), 'kev': int(record['kev']),
                'matched_product': record.get('product'), 'corpus': corpus.name,
            })
            previous = accepted.get(info['cve_id'])
            if previous is None or status == 'CONFIRMED' and previous['applicability'] != 'CONFIRMED':
                accepted[info['cve_id']] = info
    return {'device': asset, 'query': query, 'cves': list(accepted.values()),
            'excluded_cves': [v for k, v in excluded.items() if k not in accepted],
            'assessment': 'CANDIDATES_FOUND' if accepted else 'UNKNOWN',
            'reason': ('Candidate applicability is assessed individually.' if accepted else
                       'No applicable candidates found in existing corpora; coverage is not proof of safety.'),
            'corpora_searched': [c.name for c in corpora]}


def load_assets():
    if not os.path.exists(ASSETS_FILE):
        print(f"ERROR: {ASSETS_FILE} not found — run smart_discover.py first")
        sys.exit(1)

    with open(ASSETS_FILE, "r") as f:
        assets = json.load(f)

    if not assets:
        print("WARNING: assets.json is empty — nothing to scan")
        return []

    print(f"✓ Loaded {len(assets)} devices from assets.json")
    return assets


def run_cve_scan():
    # Supplement OT results even when OT has some hits: it is a filtered subset.
    corpora = [CandidateCorpus('OT', load_model()), CandidateCorpus('GENERAL', load_model(general=True))]
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

        result = assess_asset(asset, corpora)
        for cve_info in result['cves']:
            print(f"  {cve_info['cve_id']}  cvss={cve_info['cvss']:.1f}  "
                  f"epss={cve_info['epss']:.3f}  kev={cve_info['kev']}")

        all_results.append(result)

    output = {
        "scan_summary": {
            "total_devices":    len(assets),
            "total_cves_found": sum(len(r["cves"]) for r in all_results),
            "text_candidate_limit_per_corpus": TOP_K,
            "retrieval": "OT plus general corpus; recognized names bypass text cutoff; deduplicated by CVE",
            "confirmed_count": sum(c.get("applicability")=="CONFIRMED" for r in all_results for c in r["cves"]),
        },
        "devices": all_results,
    }

    atomic_json(OUTPUT_FILE,output)

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
