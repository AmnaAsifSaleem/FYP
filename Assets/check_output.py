import json
with open('Assets/risk_scored_results.json') as f:
    data = json.load(f)
for dev in data['devices']:
    print("\n%s | %s %s | crit=%.2f | db=%d fallback=%d" % (
        dev['device_type'], dev['vendor'], dev['product'],
        dev['criticality'], dev['cia_db_hits'], dev['cia_fallback']))
    for cve in dev['cves'][:5]:
        print("  %-20s cvss=%.1f epss=%.5f C=%.2f I=%.2f A=%.2f [%-8s] risk=%.1f %s%s" % (
            cve['cve_id'], cve['cvss'], cve['epss'],
            cve['c_impact'], cve['i_impact'], cve['a_impact'],
            cve['cia_source'], cve['risk_score'],
            cve['risk_emoji'], cve['risk_tier']))
