import json
import os

# Load model_input.json
with open('Assets/model_input.json', 'r') as f:
    devices = json.load(f)

# Convert to vulnerability_scan_results format
scan_results = {
    'scan_summary': {
        'total_devices': len(devices),
        'total_cves_found': sum(len(d.get('cves', [])) for d in devices),
        'cves_per_device': round(sum(len(d.get('cves', [])) for d in devices) / len(devices), 1)
    },
    'devices': []
}

for device in devices:
    device_data = {
        'device': {
            'ip': device['ip'],
            'port': device['port'],
            'service': device['service'],
            'device_type': device['device_type'],
            'zone': device['zone'],
            'vendor': device['vendor'],
            'product': device['product'],
            'firmware': device['firmware'],
            'description': f"{device['vendor']} {device['product']} {device['device_type']}",
            'criticality': 0.5,  # Default value
            'packet_count': 0,
            'talkers': [device['ip']]
        },
        'query': f"{device['vendor']} {device['product']} {device['firmware']}",
        'cves': []
    }
    
    for cve in device.get('cves', []):
        cve_data = {
            'cve_id': cve['cve_id'],
            'cvss': cve['cvss'],
            'epss': cve['epss'],
            'kev': cve['kev'],
            'risk_score': cve.get('risk_score', 0.0),
            'risk_tier': cve.get('risk_tier', 'LOW'),
            'c_impact': cve.get('c_impact', 0.0),
            'i_impact': cve.get('i_impact', 0.0),
            'a_impact': cve.get('a_impact', 0.0)
        }
        device_data['cves'].append(cve_data)
    
    scan_results['devices'].append(device_data)

# Save to vulnerability_scan_results.json
with open('Assets/vulnerability_scan_results.json', 'w') as f:
    json.dump(scan_results, f, indent=2)

print(f"Created vulnerability_scan_results.json with:")
print(f"  Devices: {scan_results['scan_summary']['total_devices']}")
print(f"  Total CVEs: {scan_results['scan_summary']['total_cves_found']}")
print(f"  CVEs per device: {scan_results['scan_summary']['cves_per_device']}")

# Count risk tiers
risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
for device in scan_results['devices']:
    for cve in device['cves']:
        tier = cve.get('risk_tier', 'LOW')
        risk_counts[tier] = risk_counts.get(tier, 0) + 1

print(f"\nRisk Distribution:")
print(f"  🔴 CRITICAL: {risk_counts['CRITICAL']}")
print(f"  🟠 HIGH:     {risk_counts['HIGH']}")
print(f"  🟡 MEDIUM:   {risk_counts['MEDIUM']}")
print(f"  🟢 LOW:      {risk_counts['LOW']}")