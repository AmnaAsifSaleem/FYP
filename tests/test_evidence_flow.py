import json
import math
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock,patch
import pytest

ROOT=Path(__file__).resolve().parents[1]
for p in (ROOT,ROOT/'Policy_Compliance',ROOT/'Dashboard',ROOT/'Remediation'):sys.path.insert(0,str(p))
from validation import validate_asset
from contextual_risk import score_details
from cve_applicability import evaluate as applicability
from policy_engine import evaluate,DEFAULT_RULES
from snapshot_io import FILES,publish_cycle,load_cycle

ASSET={'ip':'192.0.2.1','port':502,'zone':'OT','device_type':'PLC','service':'Modbus','vendor':'Siemens','product':'S7-300','firmware':'3.2','criticality':.9,'identity_verified':True,'firmware_verified':True}
def row(start='3.0',end='3.3'):
 return {'cpe_matches':[{'vulnerable':True,'simple_configuration':True,'vendor':'Siemens','product':'S7-300','version':'*','versionStartIncluding':start,'versionEndExcluding':end}]}

@pytest.mark.parametrize('value',[-1,11,float('nan'),float('inf'),True,None])
def test_invalid_cvss_is_rejected(value):
 with pytest.raises(ValueError):score_details({'cvss':value},.9,{})
def test_moderate_risk_does_not_saturate():
 r=score_details({'cvss':7,'cve_id':'CVE-2020-1234'},.9,{'CVE-2020-1234':(.56,.56,.56)})
 assert 6 < r['risk_score'] < 7 and r['contributions']['ids']==0
def test_missing_cia_is_not_fabricated():
 r=score_details({'cvss':5},.5,{})
 assert r['c_impact'] is None and r['cia_source']=='unknown'
def test_informational_ids_events_do_not_inflate_risk():
 base=score_details({'cvss':7},.9,{})['risk_score']
 assert score_details({'cvss':7},.9,{},alert_count=10000,alert_severity=3)['risk_score']==base
 assert score_details({'cvss':7},.9,{},alert_count=30,alert_severity=1)['risk_score']>base
def test_firmware_constraints_and_boundaries():
 assert applicability(ASSET,row())[0]=='CONFIRMED'
 assert applicability({**ASSET,'firmware':'3.3'},row())[0]=='NOT_AFFECTED'
 assert applicability({**ASSET,'firmware':'2.9'},row())[0]=='NOT_AFFECTED'
 assert applicability({**ASSET,'firmware':'3.0'},row())[0]=='CONFIRMED'
def test_configured_identity_does_not_confirm():
 assert applicability({**ASSET,'identity_verified':False},row())[0]=='POTENTIAL'
def test_unknown_identity_and_legacy_ranges_do_not_confirm():
 assert applicability({**ASSET,'vendor':'Unknown'},row())[0]=='UNKNOWN'
 assert applicability(ASSET,{'vendor':'Siemens','product':'S7-300','version_start':'3.0','version_end':'3.3'})[0]=='POTENTIAL'
def test_complex_configuration_requires_review():
 r=row();r['cpe_matches'][0]['simple_configuration']=False
 assert applicability(ASSET,r)[0]=='POTENTIAL'
def test_unknown_evidence_cannot_be_compliant():
 r=evaluate(ASSET,[],DEFAULT_RULES)
 assert r['decision']=='NEEDS_REVIEW' and r['compliance_status']=='NEEDS_REVIEW'
 assert {c['status'] for c in r['checks']}=={'UNKNOWN','NOT_APPLICABLE'}
def test_confirmed_cve_not_diluted_by_averages():
 r=evaluate({**ASSET,'encrypted':True,'days_since_patch':1,'firmware_eol':False,'cve_assessment_complete':True},[{'cve_id':'CVE-2020-1234','cvss':9,'applicability':'CONFIRMED'},{'cve_id':'CVE-2020-5678','cvss':1,'applicability':'CONFIRMED'}],DEFAULT_RULES)
 assert r['decision']=='REMEDIATE'
def test_verified_insecure_transport_recommends_restriction():
 assert evaluate({**ASSET,'encrypted':False},[],DEFAULT_RULES)['decision']=='RESTRICT'
def test_it_zone_modbus_restriction_cannot_be_overridden_by_ml():
 r=evaluate({**ASSET,'zone':'IT','encrypted':True},[],DEFAULT_RULES,ml_signal={'compliance_status':'COMPLIANT','confidence':1})
 assert r['decision']=='RESTRICT' and r['priority']=='URGENT'
 assert any(c['rule_name']=='IT Zone OT Protocol Restriction' and c['status']=='FAIL' for c in r['checks'])
def test_all_known_evidence_can_pass():
 a={**ASSET,'encrypted':True,'days_since_patch':1,'firmware_eol':False,'cve_assessment_complete':True}
 assert evaluate(a,[],DEFAULT_RULES)['decision']=='APPROVE'
def test_unsupported_rule_is_not_silent_pass():
 assert evaluate(ASSET,[],[{'rule_name':'Future unsupported rule'}])['decision']=='NEEDS_REVIEW'
def test_invalid_port_requires_review():
 assert evaluate({**ASSET,'port':0},[],DEFAULT_RULES)['validation_errors']
def test_snapshot_rejects_corruption_and_retains_manifest(tmp_path):
 src=tmp_path/'src';shared=tmp_path/'shared';src.mkdir()
 for f in FILES:(src/f).write_text(json.dumps([] if f in ('assets.json','suricata_context.json','anomaly_results.json') else {'devices':[]}))
 cycle=publish_cycle(src,shared);manifest,payload=load_cycle(shared)
 assert manifest['cycle_id']==cycle
 (shared/'cycles'/cycle/'assets.json').write_text('[] ')
 with pytest.raises(ValueError,match='checksum'):load_cycle(shared)
def test_failed_publish_keeps_previous_complete_cycle(tmp_path):
 src=tmp_path/'src';shared=tmp_path/'shared';src.mkdir()
 for f in FILES:(src/f).write_text('[]')
 original=publish_cycle(src,shared);(src/'assets.json').write_text('{')
 with pytest.raises(json.JSONDecodeError):publish_cycle(src,shared)
 assert load_cycle(shared)[0]['cycle_id']==original
def test_remediation_contract_and_reference_urls():
 import remediation_advisor as ra
 response=json.dumps({'recommendation':'Review vendor patch.','rationale':'Known issue.','ot_safety_note':'Test rollback.','requires_maintenance_window':True,'confidence':.8,'references':['https://nvd.nist.gov/vuln/detail/CVE-2020-1234']})
 with patch.object(ra,'_call_groq',return_value=response):
  recommendation,context,model=ra.generate_remediation(ASSET,{'cve_id':'CVE-2020-1234','cvss':8,'risk_score':8,'risk_tier':'CRITICAL','description':'Vendor issue'})
 assert recommendation.references[0].startswith('https://') and context and model
def test_blocked_recommendation_cannot_be_approved():
 import app,remediation_api
 conn=MagicMock();cur=conn.cursor.return_value.__enter__.return_value
 cur.fetchone.return_value={'status':'PENDING','gatekeeper_verdict':'BLOCK'}
 with patch.object(remediation_api,'get_db_connection',return_value=conn):
  response=app.app.test_client().post('/api/remediation/1/approve',json={})
 assert response.status_code==409
 assert not any(str(c.args[0]).lstrip().startswith('UPDATE') for c in cur.execute.call_args_list)
 assert conn.close.called
def test_approval_requires_json_object():
 import app
 assert app.app.test_client().post('/api/remediation/1/approve',json=[]).status_code==400

def test_constant_anomaly_baseline_and_sustained_spike(tmp_path,monkeypatch):
 import anomaly_detector as detector
 source=tmp_path/'assets.json';history=tmp_path/'history.json';output=tmp_path/'anomaly.json'
 for name,value in [('ASSETS_FILE',source),('HISTORY_FILE',history),('OUTPUT_FILE',output)]:monkeypatch.setattr(detector,name,str(value))
 a={**ASSET,'packet_count':100,'talkers':['192.0.2.2'],'avg_packet_size':64}
 source.write_text(json.dumps([a]))
 for _ in range(10):detector.run()
 normal=json.loads(output.read_text())[0];assert normal['anomaly_score']==0 and not normal['is_anomalous']
 a['packet_count']=100000;source.write_text(json.dumps([a]));detector.run()
 first=json.loads(output.read_text())[0];assert first['anomaly_score']>0 and not first['is_anomalous']
 detector.run();second=json.loads(output.read_text())[0];assert second['is_anomalous']
 values=json.loads(history.read_text())['windows']['192.0.2.1:502']
 assert all(v[0]==100 for v in values)
