"""Read-only deterministic check of stored runtime assets."""
import os,sys,json
sys.path.insert(0,os.path.join(os.path.dirname(__file__),'Policy_Compliance'))
from pipeline_paths import RUNTIME_FOLDER
from policy_engine import evaluate,DEFAULT_RULES
with open(os.path.join(RUNTIME_FOLDER,'assets.json'),encoding='utf-8-sig') as f:assets=json.load(f)
with open(os.path.join(RUNTIME_FOLDER,'vulnerability_scan_results.json'),encoding='utf-8-sig') as f:scan=json.load(f)
cves={(r['device'].get('ip'),r['device'].get('port')):r.get('cves',[]) for r in scan.get('devices',[])}
for a in assets:
    result=evaluate(a,cves.get((a.get('ip'),a.get('port')),[]),DEFAULT_RULES)
    print(a.get('device_type'),result['decision'],result['explanation'])
