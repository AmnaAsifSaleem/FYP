"""Opt-in real PostgreSQL tests in a disposable schema; no production writes."""
import os,sys,uuid
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]
for p in (ROOT,ROOT/'Database',ROOT/'Dashboard',ROOT/'Policy_Compliance'):sys.path.insert(0,str(p))

@pytest.fixture
def database():
 if os.environ.get('CAVE_OT_TEST_DB')!='1':pytest.skip('Set CAVE_OT_TEST_DB=1 to run isolated PostgreSQL integration tests')
 import psycopg2
 from psycopg2 import sql
 from pipeline_paths import DB_CONFIG
 schema='caveot_test_'+uuid.uuid4().hex
 admin=psycopg2.connect(**DB_CONFIG);admin.autocommit=True
 with admin.cursor() as cur:cur.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
 conn=psycopg2.connect(**DB_CONFIG,options=f'-c search_path={schema}')
 try:
  with conn.cursor() as cur:
   for file in ('db_schema.sql','db_schema_policy.sql','db_schema_remediation.sql'):cur.execute((ROOT/'Database'/file).read_text(encoding='utf-8-sig'))
  from migrate_audit_fixes import migrate
  migrate(conn);conn.commit()
  yield conn
 finally:
  conn.close()
  assert schema.startswith('caveot_test_') and len(schema)==44
  with admin.cursor() as cur:cur.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)))
  admin.close()

def asset(conn):
 with conn.cursor() as cur:
  cur.execute("INSERT INTO assets(ip,port,service,device_type,zone,vendor,product,criticality,encrypted,days_since_patch,firmware_eol,cve_assessment_complete) VALUES ('192.0.2.1',502,'Modbus','PLC','OT','Siemens','S7-300',.9,FALSE,1,FALSE,TRUE) RETURNING id")
  return cur.fetchone()[0]

def test_asset_policy_violation_alert_and_idempotency(database):
 from policy_service import run_checks
 aid=asset(database)
 first=run_checks(database,aid)[0]['prediction'];database.commit()
 assert first['decision']=='RESTRICT'
 run_checks(database,aid);database.commit()
 with database.cursor() as cur:
  for table in ('policy_compliance','policy_violations','alerts'):
   cur.execute('SELECT COUNT(*) FROM '+table);assert cur.fetchone()[0]==1
  cur.execute('UPDATE assets SET encrypted=TRUE WHERE id=%s',(aid,))
 second=run_checks(database,aid)[0]['prediction'];database.commit()
 assert second['decision']=='APPROVE'
 with database.cursor() as cur:
  cur.execute('SELECT COUNT(*) FROM policy_violations');assert cur.fetchone()[0]==0
  cur.execute('SELECT COUNT(*) FROM alerts');assert cur.fetchone()[0]==0

def test_policy_api_uses_same_evaluator(database,monkeypatch):
 import app,policy_api
 aid=asset(database);database.commit()
 class ConnectionProxy:
  def __getattr__(self,name):return getattr(database,name)
  def close(self):pass
 monkeypatch.setattr(policy_api,'get_db_connection',lambda:ConnectionProxy())
 client=app.app.test_client()
 r=client.post(f'/api/policy/check/{aid}')
 assert r.status_code==200 and r.json['prediction']['decision']=='RESTRICT'
 assert client.get('/api/policy/assets').status_code==200
 assert client.get('/api/policy/summary').status_code==200
 assert client.post('/api/policy/check/999999').status_code==404

def test_migration_is_idempotent_and_foreign_key_enforced(database):
 from migrate_audit_fixes import migrate
 import psycopg2
 assert migrate(database) is False
 with pytest.raises(psycopg2.IntegrityError):
  with database.cursor() as cur:cur.execute("INSERT INTO policy_compliance(asset_id,compliance_status) VALUES (99999,'COMPLIANT')")
 database.rollback()

def test_sync_rejects_partial_cycle_before_connect(tmp_path,monkeypatch):
 import sync_db
 from unittest.mock import patch
 monkeypatch.setattr(sync_db,'_SHARED',str(tmp_path))
 with patch('psycopg2.connect') as connect:
  with pytest.raises(FileNotFoundError):sync_db.sync()
  connect.assert_not_called()

def test_new_remediation_generation_cache_and_approval(database,monkeypatch):
 import app,remediation_api,remediation_advisor
 aid=asset(database)
 with database.cursor() as cur:
  cur.execute("UPDATE assets SET encrypted=TRUE,firmware='3.2' WHERE id=%s",(aid,))
  cur.execute("INSERT INTO vulnerabilities(asset_id,cve_id,cvss,epss,kev,risk_score,risk_tier,applicability) VALUES (%s,'CVE-2020-1234',8,.1,FALSE,8,'CRITICAL','CONFIRMED')",(aid,))
 database.commit()
 class ConnectionProxy:
  def __getattr__(self,name):return getattr(database,name)
  def close(self):pass
 monkeypatch.setattr(remediation_api,'get_db_connection',lambda:ConnectionProxy())
 recommendation=remediation_advisor.RemediationOutput(recommendation='Review vendor patch and restrict engineering access using firewall segmentation.',rationale='Addresses confirmed issue.',ot_safety_note='Test and retain rollback.',requires_maintenance_window=True,confidence=.9,references=[])
 monkeypatch.setattr(remediation_advisor,'generate_remediation',lambda *a,**kw:(recommendation,[{'source':'local test evidence'}],'test-model'))
 monkeypatch.setattr(remediation_advisor,'get_cve_description',lambda _: 'Test advisory evidence')
 client=app.app.test_client()
 response=client.post('/api/remediation/generate',json={'asset_id':aid,'cve_id':'CVE-2020-1234'})
 assert response.status_code==200,response.json
 rec=response.json['recommendation'];assert response.json['cached'] is False
 response=client.post('/api/remediation/generate',json={'asset_id':aid,'cve_id':'CVE-2020-1234'})
 assert response.status_code==200 and response.json['cached'] is True
 response=client.post(f"/api/remediation/{rec['id']}/approve",json={'note':'Reviewed applicability, vendor evidence, and maintenance plan.'})
 assert response.status_code==200,response.json
 with database.cursor() as cur:
  cur.execute('SELECT COUNT(*) FROM remediation_decision_audit');assert cur.fetchone()[0]==1
 assert client.post(f"/api/remediation/{rec['id']}/approve",json={'note':'again'}).status_code==409

def test_invalid_api_fields_return_client_errors(database,monkeypatch):
 import app,remediation_api
 client=app.app.test_client()
 assert client.get('/api/vulnerabilities?limit=abc').status_code==422
 assert client.get('/api/vulnerabilities?tier=invalid').status_code==422
 assert client.post('/api/remediation/generate',json=[]).status_code==400
 assert client.post('/api/remediation/generate',json={'asset_id':True,'cve_id':'CVE-2020-1234'}).status_code==422

def test_complete_module_replay(tmp_path):
 if os.environ.get('CAVE_OT_TEST_DB')!='1':pytest.skip('Complete replay requires isolated PostgreSQL access')
 import subprocess,json
 env={**os.environ,'CAVE_OT_REPLAY_REPORT_DIR':str(tmp_path),'PYTHONIOENCODING':'utf-8','PYTHONDONTWRITEBYTECODE':'1'}
 result=subprocess.run([sys.executable,'-B',str(ROOT/'Testing'/'replay_end_to_end.py')],capture_output=True,text=True,encoding='utf-8',timeout=120,env=env)
 assert result.returncode==0,result.stdout+'\n'+result.stderr
 report=json.loads((tmp_path/'end-to-end-replay-results.json').read_text())
 assert report['unknown_assets']>=1 and report['confirmed']==0
 assert all(status==200 for status in report['api_statuses'].values())


def test_dashboard_keeps_historical_candidates_visible(database, monkeypatch):
 import app
 aid=asset(database)
 with database.cursor() as cur:
  cur.execute("UPDATE assets SET status='INACTIVE' WHERE id=%s", (aid,))
  cur.execute("INSERT INTO vulnerabilities(asset_id,cve_id,cvss,epss,kev,risk_score,risk_tier,applicability) VALUES (%s,'CVE-2020-9999',9.8,.1,FALSE,9.0,'CRITICAL','POTENTIAL')", (aid,))
 database.commit()
 class Proxy:
  def __getattr__(self,name):return getattr(database,name)
  def close(self):pass
 monkeypatch.setattr(app,'get_conn',lambda:Proxy())
 monkeypatch.setattr(app,'_scan_running',lambda:False)
 client=app.app.test_client()
 data=client.get('/api/summary').json
 assert data['data_mode']=='HISTORICAL' and data['active_assets']==0
 assert data['total_cves']==1 and data['critical_cves']==1
 assert data['potential_cves']==1 and data['confirmed_cves']==0
 assert sum(x['total'] for x in client.get('/api/charts/cves_per_device').json)==1
 assert sum(x['count'] for x in client.get('/api/charts/risk_distribution').json)==1


def test_alert_asset_count_uses_all_asset_ids_not_ips_or_limited_feed(database, monkeypatch):
 import app
 aid=asset(database)
 with database.cursor() as cur:
  cur.execute("INSERT INTO assets(ip,port,vendor,product,zone,criticality) VALUES ('192.0.2.1',5031,'Other','Second device','OT',.5) RETURNING id")
  other=cur.fetchone()[0]
  cur.execute("INSERT INTO alerts(asset_id,alert_signature,alert_count,detected_at) VALUES (%s,'old other-asset event',1,NOW()-INTERVAL '1 day')",(other,))
  for i in range(101):
   cur.execute("INSERT INTO alerts(asset_id,alert_signature,alert_count) VALUES (%s,%s,1)",(aid,f'event {i}'))
 database.commit()
 class Proxy:
  def __getattr__(self,name):return getattr(database,name)
  def close(self):pass
 monkeypatch.setattr(app,'get_conn',lambda:Proxy())
 monkeypatch.setattr(app,'_scan_running',lambda:False)
 client=app.app.test_client()
 assert client.get('/api/summary').json['affected_assets']==2
 feed=client.get('/api/alerts').json
 assert len(feed)==100 and {row['asset_id'] for row in feed}=={aid}
 assert all(row['asset_port']==502 for row in feed)
