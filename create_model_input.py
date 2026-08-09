import json
import os

# Load assets from assets.json
with open('Assets/assets.json', 'r') as f:
    assets = json.load(f)

# Convert to model_input format
model_input = []
for asset in assets:
    model_asset = {
        'ip': asset['ip'],
        'port': asset['port'],
        'service': asset['service'],
        'device_type': asset['device_type'],
        'zone': asset['zone'],
        'vendor': asset['vendor'],
        'product': asset['product'],
        'firmware': asset['firmware'],
        'alert_count': 0,
        'alert_severity': 3,
        'cves': []  # Will be populated by cve_mapper
    }
    model_input.append(model_asset)

# Save to model_input.json
with open('Assets/model_input.json', 'w') as f:
    json.dump(model_input, f, indent=2)

print(f'Created model_input.json with {len(model_input)} assets')
print('Assets:')
for i, asset in enumerate(model_input, 1):
    print(f'{i}. {asset["vendor"]} {asset["product"]} ({asset["ip"]}:{asset["port"]})')