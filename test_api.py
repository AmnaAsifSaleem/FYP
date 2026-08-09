import requests
import json

try:
    # Test summary endpoint
    print('Testing dashboard API...')
    response = requests.get('http://localhost:5000/api/summary')
    if response.status_code == 200:
        data = response.json()
        print('✓ API Summary endpoint working')
        print(f'  Total assets: {data.get("total_assets", 0)}')
        print(f'  Total CVEs: {data.get("total_cves", 0)}')
        print(f'  Critical CVEs: {data.get("critical_cves", 0)}')
        print(f'  High CVEs: {data.get("high_cves", 0)}')
        print(f'  Medium CVEs: {data.get("medium_cves", 0)}')
        print(f'  Low CVEs: {data.get("low_cves", 0)}')
    else:
        print(f'✗ API Summary failed: {response.status_code}')
        
    # Test assets endpoint
    response = requests.get('http://localhost:5000/api/assets')
    if response.status_code == 200:
        data = response.json()
        print(f'✓ Assets endpoint working: {len(data)} assets')
    else:
        print(f'✗ Assets endpoint failed: {response.status_code}')
        
    # Test vulnerabilities endpoint
    response = requests.get('http://localhost:5000/api/vulnerabilities')
    if response.status_code == 200:
        data = response.json()
        print(f'✓ Vulnerabilities endpoint working: {len(data)} vulnerabilities')
    else:
        print(f'✗ Vulnerabilities endpoint failed: {response.status_code}')
        
except Exception as e:
    print(f'Error testing API: {e}')