"""
CAVE-OT Risk Scorer
Calculates contextual risk scores for CVEs using CVSS v3.1 Environmental Scoring
with OT-specific CIA reweighting and Suricata alert integration.
"""

import json
import sys
import os

# Asset criticality values (IEC 62443)
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
    (8.0, 'CRITICAL', '🔴'),
    (6.0, 'HIGH', '🟠'),
    (4.0, 'MEDIUM', '🟡'),
    (0.0, 'LOW', '🟢'),
]

# Suricata severity weights
SEVERITY_WEIGHT = {1: 1.00, 2: 0.60, 3: 0.30}

def get_exploit_code_maturity(epss):
    """Calculate exploit code maturity factor from EPSS"""
    if epss >= 0.70:
        return 1.00  # High - actively exploited
    elif epss >= 0.40:
        return 0.97  # Functional exploit exists
    elif epss >= 0.10:
        return 0.94  # Proof of concept
    else:
        return 0.91  # Unproven

def get_remediation_level(kev):
    """Calculate remediation level factor from KEV status"""
    if kev == 1:
        return 1.00  # No fix - confirmed in wild
    else:
        return 0.95  # Official fix available

def calculate_temporal_score(cvss, epss, kev):
    """Calculate CVSS v3.1 Temporal Score"""
    exploit_maturity = get_exploit_code_maturity(epss)
    remediation = get_remediation_level(kev)
    return cvss * exploit_maturity * remediation

def calculate_cia_score(c_impact, i_impact, a_impact):
    """Calculate OT-weighted CIA score (NIST SP 800-82)"""
    # OT weighting: Availability > Integrity > Confidentiality
    return (c_impact * 0.20) + (i_impact * 0.30) + (a_impact * 0.50)

def calculate_suricata_factor(alert_count, alert_severity):
    """Calculate Suricata context factor"""
    if alert_count == 0:
        return 0.0
    
    severity_weight = SEVERITY_WEIGHT.get(alert_severity, 0.30)
    factor = (alert_count * severity_weight) / 30.0
    return min(factor, 1.0)

def calculate_risk_score(cve, device_type, alert_count=0, alert_severity=3):
    """Calculate final contextual risk score"""
    # Extract CVE data
    cvss = cve['cvss']
    epss = cve['epss']
    kev = cve['kev']
    c_impact = cve['c_impact']
    i_impact = cve['i_impact']
    a_impact = cve['a_impact']
    
    # Step 1: Temporal score
    temporal = calculate_temporal_score(cvss, epss, kev)
    
    # Step 2: OT CIA reweighting
    cia = calculate_cia_score(c_impact, i_impact, a_impact)
    
    # Step 3: Asset criticality
    asset_crit = ASSET_CRITICALITY.get(device_type, 0.30)
    
    # Step 4: Environmental score
    environmental = temporal * cia * asset_crit * 10
    environmental = min(environmental, 10.0)
    
    # Step 5: KEV bonus
    if kev == 1:
        environmental = min(environmental * 1.10, 10.0)
    
    # Step 6: Suricata context
    suricata_factor = calculate_suricata_factor(alert_count, alert_severity)
    final_score = min(environmental + (suricata_factor * 1.5), 10.0)
    
    return round(final_score, 1)

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
    alert_count = device.get('alert_count', 0)
    alert_severity = device.get('alert_severity', 3)
    
    # Calculate risk score for each CVE
    for cve in cves:
        risk_score = calculate_risk_score(
            cve, device_type, alert_count, alert_severity
        )
        risk_tier, risk_emoji = get_risk_tier(risk_score)
        
        cve['risk_score'] = risk_score
        cve['risk_tier'] = risk_tier
        cve['risk_emoji'] = risk_emoji
    
    # Sort by risk score (highest first)
    device['cves'].sort(key=lambda x: x['risk_score'], reverse=True)

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
