"""
Query the model for MULTIPLE assets/PLCs
Finds CVEs for all devices in your asset inventory
"""

import joblib
from sklearn.metrics.pairwise import cosine_similarity
import os

MODEL_FOLDER = r"D:\Downloads\CAVE-OT Datasets\model"

# Load the OT model
print("Loading model...")
ot_vectorizer = joblib.load(os.path.join(MODEL_FOLDER, 'ot_vectorizer.pkl'))
ot_matrix = joblib.load(os.path.join(MODEL_FOLDER, 'ot_matrix.pkl'))
ot_cve_database = joblib.load(os.path.join(MODEL_FOLDER, 'ot_cve_database.pkl'))
print("✓ Model loaded\n")

# YOUR ASSET INVENTORY - Add all your PLCs here
assets = [
    "siemens simatic s7-1200 v4.1 profinet",
    "siemens simatic s7-300 cpu 315-2 pn/dp",
    "siemens simatic s7-1500 cpu 1516-3 pn/dp",
    "schneider electric modicon m580 bmep584040",
    "schneider electric modicon m340 bmxp342020",
    "rockwell automation controllogix 1756-l73",
    "rockwell automation compactlogix 5380",
    "allen bradley micrologix 1400",
    "abb ac500 plc pm595",
    "delta electronics dvp-es2 plc",
    "mitsubishi electric melsec iq-r r08cpu",
    "omron sysmac nj501-1300",
    "wago 750-8202 pfc200",
    "phoenix contact plcnext axi",
    "beckhoff cx5140 embedded pc",
]

print("="*80)
print(f"SCANNING {len(assets)} ASSETS FOR VULNERABILITIES")
print("="*80)

TOP_K = 10  # Show top 10 CVEs per asset

for i, asset in enumerate(assets, 1):
    print(f"\n[{i}/{len(assets)}] Asset: {asset}")
    print("-" * 80)
    
    # Convert query to vector
    query_vector = ot_vectorizer.transform([asset.lower()])
    
    # Find similar CVEs
    scores = cosine_similarity(query_vector, ot_matrix).flatten()
    
    # Get top K results
    top_idx = scores.argsort()[-TOP_K:][::-1]
    
    # Display results
    print(f"Found {TOP_K} matching CVEs:")
    for idx in top_idx:
        cve = ot_cve_database.iloc[idx]
        print(f"  {cve['cve_id']} cvss={cve['cvss']:.1f} epss={cve['epss']:.3f} kev={cve['kev']}")

print("\n" + "="*80)
print("✓ SCAN COMPLETE")
print("="*80)
print(f"\nScanned {len(assets)} assets")
print(f"Showing top {TOP_K} CVEs per asset")
print("\nTo scan YOUR assets:")
print("  1. Edit the 'assets' list in this script")
print("  2. Add your device descriptions")
print("  3. Run: python query_multiple_assets.py")
