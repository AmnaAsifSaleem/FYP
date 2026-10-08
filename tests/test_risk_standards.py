from datetime import datetime,timedelta,timezone
import json
from unittest.mock import MagicMock
import pytest
from cvss31 import calculate,roundup
from contextual_risk import score_details,get_risk_tier
from ids_context import risk_context,fast_timestamp

NOW=datetime(2026,10,9,12,tzinfo=timezone.utc)
VECTOR='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'

@pytest.mark.parametrize('vector,score',[
    (VECTOR,9.8),
    ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',7.5),
    ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',10.),
    ('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',0.),
])
def test_known_cvss_vectors(vector,score):
    assert calculate(vector)['base']==score

def test_temporal_metrics_are_evidence_not_epss_or_kev():
    result=calculate(VECTOR+'/E:P/RL:O/RC:R')
    assert result['temporal']==8.5
    a=score_details({'cvss':9.8,'cvss_vector':VECTOR,'epss':0,'kev':False},1,{})
    b=score_details({'cvss':9.8,'cvss_vector':VECTOR,'epss':1,'kev':True},1,{})
    assert a['cvss_environmental']==b['cvss_environmental']==9.8

def test_security_requirements_use_first_multipliers_and_no_impact_stays_zero():
    v='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L'
    assert calculate(v,{'AR':'H'})['environmental']>calculate(v,{'AR':'L'})['environmental']
    n=v.replace('/A:L','/A:N')
    assert calculate(n,{'AR':'H','IR':'H','CR':'H'})['environmental']==0
    assert calculate(v+'/AR:H')['environmental']==score_details({'cvss':5.3,'cvss_vector':v+'/AR:H'},1,{})['cvss_environmental']

@pytest.mark.parametrize('vector',[VECTOR+'/AV:N',VECTOR.replace('/PR:N',''),VECTOR+'/AR:Z',VECTOR.replace('3.1','3.0')])
def test_incomplete_or_unsupported_vectors_are_rejected(vector):
    with pytest.raises(ValueError):calculate(vector)

def test_first_roundup_and_tier_boundaries():
    assert roundup(4.02)==4.1 and roundup(4.0)==4.0
    assert roundup(.1+.2)==.3
    assert [get_risk_tier(v) for v in (3.9,4,6.9,7,8.9,9)]==['LOW','MEDIUM','MEDIUM','HIGH','HIGH','CRITICAL']

def event(seconds=0,severity=1,signature='write'):
    return {'timestamp':(NOW-timedelta(seconds=seconds)).isoformat(),'severity':severity,'message':signature,
            'src_ip':'192.0.2.2','dest_ip':'192.0.2.1','dest_port':502}

def test_expired_future_and_undated_events_do_not_boost_risk():
    ctx=risk_context([event(301),event(-1),{'severity':1}],now=NOW)
    assert ctx['risk_alert_weighted_count']==0
    assert risk_context([event(300)],now=NOW)['risk_alert_count']==1

def test_each_event_keeps_its_severity_and_exact_duplicates_are_deduplicated():
    events=[event(severity=1)]+[event(seconds=i+1,severity=2) for i in range(29)]
    ctx=risk_context(events+[events[0],event(severity=3,signature='info')],now=NOW)
    assert ctx['risk_alert_count']==30
    result=score_details({'cvss':7},1,{},weighted_alert_count=ctx['risk_alert_weighted_count'])
    assert result['contributions']['ids']==.92

def test_fast_log_expiry_and_year_rollover(tmp_path):
    from smart_discover import read_suricata_alerts
    log=tmp_path/'fast.log'
    line='10/09/2026-11:59:00.000000 [**] [1:9000001:1] Write [**] [Priority: 1] {TCP} 192.0.2.2:51000 -> 192.0.2.1:502\n'
    log.write_text(line+line+'01/01/2000-00:00:00.000000 [**] [1:1:1] Old [**] [Priority: 1] {TCP} 192.0.2.2:51000 -> 192.0.2.1:502\n')
    assert len(read_suricata_alerts(str(log),now=NOW))==1
    assert read_suricata_alerts(str(log),now=NOW+timedelta(minutes=10))==[]
    assert fast_timestamp('12/31-23:59:59.000000',datetime(2027,1,1,tzinfo=timezone.utc)).year==2026

def test_legacy_cia_does_not_fabricate_an_environmental_score():
    r=score_details({'cvss':7,'cve_id':'CVE-2026-1000'},1,{'CVE-2026-1000':(.22,.22,.22)})
    assert r['risk_score']==7 and r['cvss_environmental'] is None
    assert 'unavailable' in r['severity_basis']

def test_wording_does_not_invent_ids_priority(tmp_path):
    from smart_discover import read_suricata_alerts
    path=tmp_path/'fast.log'
    path.write_text('10/09/2026-11:59:00.000000 [**] [1:100:1] Attack Write Rapid words [**] {TCP} 192.0.2.2:51000 -> 192.0.2.1:502\n')
    events=read_suricata_alerts(str(path),now=NOW)
    assert events[0]['severity']==3
    assert risk_context(events,now=NOW)['risk_alert_weighted_count']==0

def test_candidate_discovery_preserves_vector():
    from tests.test_cve_matching import corpus,ASSET
    from cve_discovery import assess_asset
    data=corpus('OT',[('Siemens','SIMATIC S7-300')])
    data.database['cvss_vector']=VECTOR
    data.database['cvss_version']='3.1'
    result=assess_asset(ASSET,[data])['cves'][0]
    assert result['cvss_vector']==VECTOR and result['cvss_version']=='3.1'

def test_processed_csv_preserves_vectors_and_applicability(tmp_path):
    import pandas as pd
    from Data_Processing.data_processor import clean_and_save
    row={'cve_id':'CVE-2026-1000','vendor':'Siemens','product':'S7-300','version_start':'','version_end':'',
         'cvss':7,'epss':0,'kev':False,'c_impact':.56,'i_impact':.56,'a_impact':.56,
         'attack_vector':'NETWORK','complexity':'LOW','is_ot':1,'description':'Test',
         'cvss_vector':VECTOR,'cvss_version':'3.1','cpe_matches':'[{"vulnerable":true}]'}
    clean_and_save(pd.DataFrame([row]),str(tmp_path))
    restored=pd.read_csv(tmp_path/'processed_cves.csv')
    assert restored.iloc[0]['cvss_vector']==VECTOR
    assert restored.iloc[0]['cpe_matches']==row['cpe_matches']

def test_new_empty_ids_window_retires_old_active_signatures():
    from sync_db import upsert_alerts
    cur=MagicMock()
    assert upsert_alerts(cur,1,{'alert_messages':[],'alert_events':[]})==0
    sql,args=cur.execute.call_args.args
    assert 'is_active_attack=FALSE' in sql and args==(1,[])

@pytest.mark.parametrize('path',['CVE_Pipeline/risk_scorer.py','CVE_Pipeline/risk_scorer_v2.py','shared folder/risk_scorer_v2.py'])
def test_legacy_scorer_uses_current_formula_without_undated_ids_boost(path,tmp_path):
    from pathlib import Path
    import runpy
    module=runpy.run_path(str(Path(__file__).resolve().parents[1]/path))
    cve={'cve_id':'CVE-2026-1000','cvss':7,'epss':0,'kev':False}
    device={'ip':'192.0.2.1','port':502,'device_type':'PLC','criticality':1,
            'alert_count':1000,'alert_severity':1}
    if path.endswith('/risk_scorer.py'):
        device['cves']=[cve]
        module['score_device_cves'](device)
        result=device['cves'][0]
    else:
        source=tmp_path/'input.json';output=tmp_path/'output.json'
        source.write_text(json.dumps({'devices':[{'device':device,'cves':[cve]}]}))
        module['process'](str(source),str(output),{})
        result=json.loads(output.read_text())['devices'][0]['cves'][0]
    assert result['score_version']=='cave-ot-3'
    assert result['contributions']['ids']==0

def test_capped_priority_keeps_internal_order():
    a=score_details({'cvss':9,'epss':1,'kev':True},1,{},weighted_alert_count=30,anomaly_score=1)
    b=score_details({'cvss':10,'epss':1,'kev':True},1,{},weighted_alert_count=30,anomaly_score=1)
    assert a['risk_score']==b['risk_score']==10
    assert a['priority_total']<b['priority_total']

def test_live_caller_rechecks_cached_evidence_and_confirmation(tmp_path,monkeypatch):
    import cave_monitor
    source=tmp_path/'vulnerabilities.json'
    source.write_text(json.dumps({'devices':[{'device':{'ip':'192.0.2.1','port':502,'device_type':'PLC','criticality':1},
        'cves':[{'cve_id':'CVE-2026-1000','cvss':7,'epss':0,'kev':False}]}]}))
    (tmp_path/'suricata_context.json').write_text(json.dumps([{'ip':'192.0.2.1','port':502,'risk_alert_count':1000,'risk_alert_severity':1,
        'alert_events':[event(1000000)]}]))
    (tmp_path/'anomaly_results.json').write_text(json.dumps([{'ip':'192.0.2.1','port':502,'anomaly_score':1,'is_anomalous':False}]))
    monkeypatch.setattr(cave_monitor,'CAVE_DIR',str(tmp_path))
    monkeypatch.setattr(cave_monitor,'sync_to_shared',lambda *args:None)
    assert cave_monitor._score_and_display(str(source))
    result=json.loads((tmp_path/'risk_scored_results.json').read_text())['devices'][0]['cves'][0]
    assert result['contributions']['ids']==result['contributions']['confirmed_anomaly']==0
    assert result['score_version']=='cave-ot-3'

def test_risk_provenance_survives_database_ingestion():
    from sync_db import upsert_cve
    cur=MagicMock()
    cve={'cve_id':'CVE-2026-1000','cvss':7,'epss':0,'kev':False}
    result=score_details(cve,1,{})
    upsert_cve(cur,1,cve,result)
    params=cur.execute.call_args.args[1]
    assert params['score_version']=='cave-ot-3'
    assert json.loads(params['risk_evidence'])['cvss_environmental'] is None
    assert params['priority_total']==7
