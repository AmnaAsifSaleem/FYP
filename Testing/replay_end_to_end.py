"""Run the actual modules in isolation, using labeled synthetic traffic."""
import os,sys,json,tempfile,pathlib,uuid,contextlib,io,subprocess
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1];WORK=pathlib.Path(tempfile.gettempdir())/'caveot-replay';WORK.mkdir(exist_ok=True);OUT=pathlib.Path(os.environ.get('CAVE_OT_REPLAY_REPORT_DIR',str(ROOT/'Testing'/'reports')));OUT.mkdir(parents=True,exist_ok=True)
sys.dont_write_bytecode=True
for p in (ROOT,ROOT/'Database',ROOT/'Dashboard',ROOT/'Policy_Compliance'):sys.path.insert(0,str(p))
from pipeline_paths import DB_CONFIG
import psycopg2
from psycopg2 import sql
from scapy.all import IP,TCP,Raw,wrpcap
import smart_discover,cve_discovery,anomaly_detector,cave_monitor,attack_path,sync_db,app,policy_api,remediation_api
from snapshot_io import publish_cycle
from migrate_audit_fixes import migrate
schema='caveot_test_'+uuid.uuid4().hex
admin=psycopg2.connect(**DB_CONFIG);admin.autocommit=True
with admin.cursor() as cur:cur.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
config={**DB_CONFIG,'options':f'-c search_path={schema}'}
summary={}
try:
 with psycopg2.connect(**config) as conn:
  with conn.cursor() as cur:
   for file in ('db_schema.sql','db_schema_policy.sql','db_schema_remediation.sql'):cur.execute((ROOT/'Database'/file).read_text(encoding='utf-8-sig'))
  migrate(conn)
 with tempfile.TemporaryDirectory(dir=WORK) as tmp:
  engine=pathlib.Path(tmp)/'engine';shared=pathlib.Path(tmp)/'shared';engine.mkdir()
  pcap=str(engine/'test.pcap');wrpcap(pcap,[IP(src='192.0.2.2',dst='127.0.0.1')/TCP(sport=51000,dport=502,flags='S')/Raw(b'\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01'),IP(src='192.0.2.2',dst='192.0.2.3')/TCP(sport=51001,dport=34567,flags='S')/Raw(b'audit')])
  with patch.object(smart_discover,'ENGINE_FOLDER',str(engine)),patch.object(smart_discover,'read_suricata_alerts',return_value=[]):smart_discover.run(pcap)
  with patch.object(cve_discovery,'MODEL_FOLDER',str(ROOT/'model')),patch.object(cve_discovery,'ASSETS_FILE',str(engine/'assets.json')),patch.object(cve_discovery,'OUTPUT_FILE',str(engine/'vulnerability_scan_results.json')):cve_discovery.run_cve_scan()
  with patch.object(anomaly_detector,'ASSETS_FILE',str(engine/'assets.json')),patch.object(anomaly_detector,'HISTORY_FILE',str(engine/'history.json')),patch.object(anomaly_detector,'OUTPUT_FILE',str(engine/'anomaly_results.json')):anomaly_detector.run()
  with patch.object(cave_monitor,'CAVE_DIR',str(engine)),patch.object(cave_monitor,'sync_to_shared',return_value=None):cave_monitor._score_and_display(str(engine/'vulnerability_scan_results.json'))
  with patch.object(attack_path,'CAVE_DIR',str(engine)),patch.object(attack_path,'sync_to_shared',return_value=None):attack_path.run_attack_path_analysis()
  cycle=publish_cycle(engine,shared)
  with patch.object(sync_db,'_SHARED',str(shared)),patch.object(sync_db,'DB_CONFIG',config):sync_db.sync()
  child_env={**os.environ,'CAVE_OT_RUNTIME_DIR':str(shared),'CAVE_OT_DB_SCHEMA':schema,'PYTHONIOENCODING':'utf-8','PYTHONDONTWRITEBYTECODE':'1'}
  child=subprocess.run([sys.executable,'-B',str(ROOT/'Database/sync_db.py')],cwd=ROOT,env=child_env,capture_output=True,text=True,encoding='utf-8',timeout=90)
  if child.returncode:raise RuntimeError('Standalone ingestion failed: '+child.stdout+child.stderr)
  summary['standalone_ingestion_verified']=True
  with psycopg2.connect(**config) as conn:
   with conn.cursor() as cur:
    for table in ('assets','vulnerabilities','policy_compliance','policy_violations','alerts','attack_paths'):
     cur.execute('SELECT COUNT(*) FROM '+table);summary[table]=cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM vulnerabilities WHERE applicability='CONFIRMED'");summary['confirmed']=cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM assets WHERE vendor='Unknown'");summary['unknown_assets']=cur.fetchone()[0]
  assert summary['unknown_assets']>=1 and summary['confirmed']==0 and summary['policy_compliance']==summary['assets']
  with patch.object(app,'get_conn',side_effect=lambda:psycopg2.connect(**config)),patch.object(policy_api,'get_db_connection',side_effect=lambda:psycopg2.connect(**config)),patch.object(remediation_api,'get_db_connection',side_effect=lambda:psycopg2.connect(**config)):
   client=app.app.test_client();summary['api_statuses']={url:client.get(url).status_code for url in ('/api/assets','/api/vulnerabilities','/api/policy/assets','/api/policy/summary','/api/attack_paths','/api/remediation/candidates')}
  assert all(s==200 for s in summary['api_statuses'].values())
  summary['cycle_id']=cycle;summary['mode']='Synthetic replay; no live IDS traffic or production writes'
finally:
 assert schema.startswith('caveot_test_') and len(schema)==44
 with admin.cursor() as cur:cur.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)))
 admin.close()
(OUT/'end-to-end-replay-results.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
print('END-TO-END REPLAY PASSED',json.dumps(summary),flush=True)
