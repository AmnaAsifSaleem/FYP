"""
CAVE-OT Risk Scorer
Calculates contextual risk scores for CVEs using a custom contextual prioritization formula
with OT-specific CIA reweighting and Suricata alert integration.
"""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from contextual_risk import score_cve,score_details,VERSION

import json
import sys
import os

# Project testbed criticalities; not IEC-prescribed numerical values
ASSET_CRITICALITY = {
    'PLC': 1.00,
    'RTU': 0.95,
    'SCADA': 0.90,
    'HMI': 0.80,
    'Engineering_WS': 0.70,
    'Historian': 0.60,
    'IT_Server': 0.40,
    'Generic': 0.30,
}

# Risk tier thresholds
RISK_TIERS = [
    (9.0, 'CRITICAL', '🔴'),
    (7.0, 'HIGH', '🟠'),
    (4.0, 'MEDIUM', '🟡'),
    (0.0, 'LOW', '🟢'),
]

# Suricata severity weights
SEVERITY_WEIGHT = {1: 1.00, 2: 0.60, 3: 0.30}






def calculate_risk_score(cve, device_type, alert_count=0, alert_severity=3):
    from contextual_risk import score_cve
    lookup = {cve.get('cve_id'): (cve['c_impact'],cve['i_impact'],cve['a_impact'])} if all(cve.get(k) is not None for k in ('c_impact','i_impact','a_impact')) else {}
    return score_cve(cve, ASSET_CRITICALITY.get(device_type,.3),lookup,alert_count,alert_severity)[0]


def get_risk_tier(score):
    """Determine risk tier from score"""
    for threshold, tier, emoji in RISK_TIERS:
        if score >= threshold:
            return tier, emoji
    return 'LOW', '🟢'

def score_device_cves(device):
    """Score all CVEs for a device and sort by risk"""
    cves = device.get('cves', [])
    if not cves:
        return
    
    device_type = device.get('device_type', 'Generic')
    from ids_context import risk_context
    ctx=risk_context(device.get('alert_events',[]))
    
    # Calculate risk score for each CVE
    for cve in cves:
        lookup={cve.get('cve_id'):tuple(cve[k] for k in ('c_impact','i_impact','a_impact'))} if all(cve.get(k) is not None for k in ('c_impact','i_impact','a_impact')) else {}
        details=score_details(cve,ASSET_CRITICALITY.get(device_type,.3),lookup,
            weighted_alert_count=ctx['risk_alert_weighted_count'],
            security_requirements=device.get('cvss_requirements'))
        cve.update(details)
        risk_score=details['risk_score']
        risk_tier, risk_emoji = get_risk_tier(risk_score)
        
        cve['risk_score'] = risk_score
        cve['risk_tier'] = risk_tier
        cve['risk_emoji'] = risk_emoji
    
    # Sort by risk score (highest first)
    device['cves'].sort(key=lambda x: x['priority_total'], reverse=True)

def main():
    # Parse command line arguments
    input_file = sys.argv[1] if len(sys.argv) > 1 else "model_input.json"
    
    print("=" * 60)
    print("CAVE-OT RISK SCORER")
    print("=" * 60)
    print(f"\nInput file: {input_file}")
    
    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"\n✗ Error: {input_file} not found")
        print("  Run cve_mapper.py first")
        sys.exit(1)
    
    # Load input data
    print(f"\nLoading devices from {input_file}...")
    with open(input_file, 'r') as f:
        devices = json.load(f)
    
    print(f"  ✓ Found {len(devices)} device(s)")
    
    # Score CVEs for each device
    print("\nCalculating risk scores...")
    for i, device in enumerate(devices, 1):
        ip = device.get('ip', 'unknown')
        vendor = device.get('vendor', 'unknown')
        product = device.get('product', 'unknown')
        cve_count = len(device.get('cves', []))
        
        print(f"\n[{i}/{len(devices)}] {ip} - {vendor} {product}")
        print(f"  CVEs to score: {cve_count}")
        
        if cve_count > 0:
            score_device_cves(device)
            
            # Show top 3 risks
            top_cves = device['cves'][:3]
            for j, cve in enumerate(top_cves, 1):
                print(f"  #{j} {cve['cve_id']} - {cve['risk_score']} {cve['risk_emoji']} {cve['risk_tier']}")
    
    # Save results
    print(f"\nSaving results to {input_file}...")
    with open(input_file, 'w') as f:
        json.dump(devices, f, indent=2)
    
    print("\n" + "=" * 60)
    print("✓ RISK SCORING COMPLETE")
    print("=" * 60)
    
    # Summary statistics
    total_cves = sum(len(d.get('cves', [])) for d in devices)
    risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    
    for device in devices:
        for cve in device.get('cves', []):
            tier = cve.get('risk_tier', 'LOW')
            risk_counts[tier] = risk_counts.get(tier, 0) + 1
    
    print(f"\nSummary:")
    print(f"  Devices processed: {len(devices)}")
    print(f"  Total CVEs scored: {total_cves}")
    print(f"\nRisk Distribution:")
    print(f"  🔴 CRITICAL: {risk_counts['CRITICAL']}")
    print(f"  🟠 HIGH:     {risk_counts['HIGH']}")
    print(f"  🟡 MEDIUM:   {risk_counts['MEDIUM']}")
    print(f"  🟢 LOW:      {risk_counts['LOW']}")
    print(f"\nOutput saved to: {input_file}")

if __name__ == "__main__":
    main()
