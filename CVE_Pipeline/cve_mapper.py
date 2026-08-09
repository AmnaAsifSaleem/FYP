"""
CAVE-OT CVE Mapper
Maps discovered devices to matching CVEs using trained TF-IDF similarity models.
Reads model_input.json, adds CVE list to each device, saves back to model_input.json.
"""

import json
import sys
import os
import pandas as pd
import joblib
from sklearn.metrics.pairwise import cosine_similarity

# Default paths
MODEL_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "model")
INPUT_FILE = "model_input.json"

def load_models():
    """Load trained models from disk"""
    print("Loading models...")
    
    models = {
        'general_vectorizer': joblib.load(f'{MODEL_FOLDER}/general_vectorizer.pkl'),
        'general_matrix': joblib.load(f'{MODEL_FOLDER}/general_matrix.pkl'),
        'general_df': joblib.load(f'{MODEL_FOLDER}/cve_database.pkl'),
        'ot_vectorizer': joblib.load(f'{MODEL_FOLDER}/ot_vectorizer.pkl'),
        'ot_matrix': joblib.load(f'{MODEL_FOLDER}/ot_matrix.pkl'),
        'ot_df': joblib.load(f'{MODEL_FOLDER}/ot_cve_database.pkl')
    }
    
    print(f"  ✓ General model: {len(models['general_df']):,} CVEs")
    print(f"  ✓ OT model: {len(models['ot_df']):,} CVEs")
    return models

def filter_by_version(df, firmware):
    """Filter CVEs by firmware version range"""
    if not firmware or firmware.strip() == '':
        return df
    
    results = []
    for _, row in df.iterrows():
        v_start = str(row.get('version_start', '')).strip()
        v_end = str(row.get('version_end', '')).strip()
        
        # No version range = include (conservative)
        if not v_start and not v_end:
            results.append(row)
            continue
        
        try:
            fw = tuple(int(x) for x in firmware.split('.') if x.isdigit())
            if not fw:
                results.append(row)
                continue
            
            start = tuple(int(x) for x in v_start.split('.') if x.isdigit()) if v_start else (0,)
            end = tuple(int(x) for x in v_end.split('.') if x.isdigit()) if v_end else (999,)
            
            if start <= fw <= end:
                results.append(row)
        except:
            # Parse error = include conservatively
            results.append(row)
    
    return pd.DataFrame(results) if results else pd.DataFrame()

def map_cves_for_device(device, models):
    """Map a single device to matching CVEs"""
    # Build query string
    vendor = device.get('vendor', '')
    product = device.get('product', '')
    service = device.get('service', '')
    query = f"{vendor} {product} {service}".lower().strip()
    
    if not query:
        return []
    
    # Select model based on zone
    zone = device.get('zone', 'IT')
    if zone == 'OT':
        vectorizer = models['ot_vectorizer']
        matrix = models['ot_matrix']
        df = models['ot_df']
        threshold = 0.10  # Lowered from 0.15 to get more CVEs
    else:
        vectorizer = models['general_vectorizer']
        matrix = models['general_matrix']
        df = models['general_df']
        threshold = 0.15  # Lowered from 0.20 to get more CVEs
    
    # TF-IDF similarity
    query_vec = vectorizer.transform([query])
    scores = cosine_similarity(query_vec, matrix).flatten()
    
    # Get top 200 candidates
    top_idx = scores.argsort()[-200:][::-1]
    candidates = df.iloc[top_idx].copy()
    candidates['similarity'] = scores[top_idx]
    
    # Filter by similarity threshold
    candidates = candidates[candidates['similarity'] >= threshold]
    
    # Filter by firmware version
    firmware = device.get('firmware', '')
    if firmware and len(candidates) > 0:
        candidates = filter_by_version(candidates, firmware)
    
    # Build result list
    result = []
    for _, row in candidates.iterrows():
        result.append({
            'cve_id': row['cve_id'],
            'cvss': float(row['cvss']),
            'epss': float(row['epss']),
            'kev': int(row['kev']),
            'c_impact': float(row['c_impact']),
            'i_impact': float(row['i_impact']),
            'a_impact': float(row['a_impact']),
            'similarity': round(float(row['similarity']), 4)
        })
    
    return result

def main():
    # Parse command line arguments
    input_file = sys.argv[1] if len(sys.argv) > 1 else INPUT_FILE
    
    print("=" * 60)
    print("CAVE-OT CVE MAPPER")
    print("=" * 60)
    print(f"\nInput file: {input_file}")
    
    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"\n✗ Error: {input_file} not found")
        print("  Create a model_input.json file with device data first")
        sys.exit(1)
    
    # Load models
    models = load_models()
    
    # Load input data
    print(f"\nLoading devices from {input_file}...")
    with open(input_file, 'r') as f:
        devices = json.load(f)
    
    print(f"  ✓ Found {len(devices)} device(s)")
    
    # Map CVEs for each device
    print("\nMapping CVEs to devices...")
    for i, device in enumerate(devices, 1):
        ip = device.get('ip', 'unknown')
        vendor = device.get('vendor', 'unknown')
        product = device.get('product', 'unknown')
        
        print(f"\n[{i}/{len(devices)}] {ip} - {vendor} {product}")
        
        cves = map_cves_for_device(device, models)
        device['cves'] = cves
        
        print(f"  ✓ Found {len(cves)} matching CVE(s)")
        if len(cves) > 0:
            print(f"    Top match: {cves[0]['cve_id']} (similarity: {cves[0]['similarity']})")
    
    # Save results
    print(f"\nSaving results to {input_file}...")
    with open(input_file, 'w') as f:
        json.dump(devices, f, indent=2)
    
    print("\n" + "=" * 60)
    print("✓ CVE MAPPING COMPLETE")
    print("=" * 60)
    
    # Summary
    total_cves = sum(len(d.get('cves', [])) for d in devices)
    print(f"\nSummary:")
    print(f"  Devices processed: {len(devices)}")
    print(f"  Total CVEs mapped: {total_cves}")
    print(f"\nNext step: python risk_scorer.py")

if __name__ == "__main__":
    main()
