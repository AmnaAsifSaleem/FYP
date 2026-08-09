"""
CAVE-OT Discovery Script
Reads asset inventory JSON and maps CVEs to each device
Query format: vendor + product + firmware
"""

import joblib
from sklearn.metrics.pairwise import cosine_similarity
import json
import os

# Model folder is at project root (one level up from CVE_Pipeline/)
MODEL_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "model")

# Load the OT model
print("Loading CAVE-OT model...")
ot_vectorizer = joblib.load(os.path.join(MODEL_FOLDER, 'ot_vectorizer.pkl'))
ot_matrix = joblib.load(os.path.join(MODEL_FOLDER, 'ot_matrix.pkl'))
ot_cve_database = joblib.load(os.path.join(MODEL_FOLDER, 'ot_cve_database.pkl'))
print("[OK] Model loaded\n")

# Assets folder is at project root/Assets/
ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Assets")

# Load asset inventory from JSON file
try:
    assets_path = os.path.join(ASSETS_DIR, 'assets.json')
    with open(assets_path, 'r') as f:
        assets = json.load(f)
    print(f"[OK] Loaded {len(assets)} devices from assets.json\n")
except FileNotFoundError:
    print("ERROR: assets.json not found!")
    exit(1)

print("="*80)
print(f"CAVE-OT VULNERABILITY DISCOVERY")
print(f"Scanning {len(assets)} devices from asset inventory")
print("="*80)

TOP_K = 25  # Show top 15 CVEs per device (change this number as needed)

# Results storage
all_results = []

for i, asset in enumerate(assets, 1):
    # Build query from vendor + product + firmware
    vendor = asset.get('vendor', '')
    product = asset.get('product', '')
    firmware = asset.get('firmware', '')
    
    query = f"{vendor} {product} {firmware}".strip()
    
    print(f"\n[Device {i}/{len(assets)}]")
    print(f"IP:         {asset['ip']}:{asset['port']}")
    print(f"Vendor:     {vendor}")
    print(f"Product:    {product}")
    print(f"Firmware:   {firmware}")
    print(f"Service:    {asset['service']}")
    print(f"Zone:       {asset['zone']}")
    print(f"Criticality: {asset['criticality']}")
    print("-" * 80)
    
    # Convert query to vector
    query_vector = ot_vectorizer.transform([query.lower()])
    
    # Find similar CVEs
    scores = cosine_similarity(query_vector, ot_matrix).flatten()
    
    # Get top K results
    top_idx = scores.argsort()[-TOP_K:][::-1]
    
    # Collect CVEs for this device
    device_cves = []
    print(f"Model finds ALL matching CVEs:")
    for idx in top_idx:
        cve = ot_cve_database.iloc[idx]
        cve_info = {
            'cve_id': cve['cve_id'],
            'cvss': float(cve['cvss']),
            'epss': float(cve['epss']),
            'kev': int(cve['kev'])
        }
        device_cves.append(cve_info)
        print(f"  {cve_info['cve_id']} cvss={cve_info['cvss']:.1f} epss={cve_info['epss']:.3f} kev={cve_info['kev']}")
    
    # Store results
    all_results.append({
        'device': asset,
        'query': query,
        'cves': device_cves
    })

# Save results to JSON
output = {
    'scan_summary': {
        'total_devices': len(assets),
        'total_cves_found': sum(len(r['cves']) for r in all_results),
        'cves_per_device': TOP_K
    },
    'devices': all_results
}

output_path = os.path.join(ASSETS_DIR, 'vulnerability_scan_results.json')
with open(output_path, 'w') as f:
    json.dump(output, f, indent=2)

print("\n" + "="*80)
print("✓ SCAN COMPLETE")
print("="*80)
print(f"\nScanned {len(assets)} devices")
print(f"Found {sum(len(r['cves']) for r in all_results)} total CVE mappings")
print(f"Results saved to: {output_path}")
print("\nSummary:")
for i, result in enumerate(all_results, 1):
    device = result['device']
    print(f"  {i}. {device['vendor']} {device['product']} ({device['ip']}) - {len(result['cves'])} CVEs")
