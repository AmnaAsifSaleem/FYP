"""Verify fresh container→capture→snapshot→PostgreSQL→dashboard operation.
Run after Compose starts. Controlled IDS checks target only the local testbed.
"""
import os,sys,json,time,subprocess,argparse,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from docker_backend import command
from snapshot_io import load_cycle
from pipeline_paths import RUNTIME_FOLDER,DB_CONFIG
def docker(*args):
    p=subprocess.run(command(*args),cwd=ROOT/'docker',capture_output=True,text=True,timeout=30)
    if p.returncode:raise RuntimeError(p.stderr[-1500:])
    return p.stdout
def verify(timeout=180):
    started=time.time();deadline=started+timeout;observed=[]
    while time.time()<deadline:
        try:
            manifest,payload=load_cycle(RUNTIME_FOLDER)
            stamp=__import__('datetime').datetime.fromisoformat(manifest['generated_at']).timestamp()
            if stamp>=started and manifest['cycle_id'] not in observed:
                observed.append(manifest['cycle_id']);print('Fresh cycle',len(observed),flush=True)
                if len(observed)>=2:break
        except (FileNotFoundError,ValueError):pass
        time.sleep(5)
    if len(observed)<2:raise RuntimeError('Two complete fresh monitoring cycles were not published')
    running=docker('ps','--filter','name=caveot-','--format','{{.Names}}')
    if not all(n in running for n in ('caveot-engine','caveot-honeypot')):raise RuntimeError('Both testbed containers must be running')
    validation=docker('exec','caveot-engine','suricata','-T','-c','/etc/suricata/suricata.yaml','-S','/var/lib/suricata/rules/ot-rules.rules')
    events=docker('exec','caveot-engine','cat','/var/log/suricata/fast.log')
    if not events.strip():raise RuntimeError('No real Suricata events captured')
    assets=payload['assets.json'];cves=sum(len(d.get('cves',[])) for d in payload['risk_scored_results.json'].get('devices',[]))
    import psycopg2
    deadline=time.time()+30;counts={}
    while time.time()<deadline:
        with psycopg2.connect(**DB_CONFIG) as conn:
            conn.set_session(readonly=True)
            with conn.cursor() as cur:
                for table in ('assets','vulnerabilities','alerts','policy_compliance'):
                    cur.execute('SELECT COUNT(*) FROM '+table);counts[table]=cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM assets WHERE status='ACTIVE'");counts['active_assets']=cur.fetchone()[0]
        if counts['active_assets'] and counts['policy_compliance']==counts['assets'] and counts['alerts']:break
        time.sleep(3)
    if not counts.get('active_assets') or not counts.get('alerts'):raise RuntimeError('Fresh monitoring did not reach database assets and alerts')
    api={}
    for route in ('/api/summary','/api/assets','/api/alerts','/api/policy/assets','/api/attack_paths'):
        with urllib.request.urlopen('http://127.0.0.1:5000'+route,timeout=15) as r:api[route]={'status':r.status,'payload':json.load(r)}
    return {'verified':True,'fresh_cycle_ids':observed,'discovered_assets':len(assets),'candidate_cves':cves,'real_ids_events':len(events.splitlines()),'database':counts,'api_statuses':{k:v['status'] for k,v in api.items()},'rule_validation':'PASS','backend':'Configured installed container engine'}
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--timeout',type=int,default=180);parser.add_argument('--report',default=str(ROOT/'Testing/reports/live-monitoring.json'));args=parser.parse_args()
    result=verify(args.timeout);path=Path(args.report);path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result,indent=2))
