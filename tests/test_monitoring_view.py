import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'Dashboard'))
from monitoring_view import asset_view
def test_stop_does_not_present_saved_active_as_current():
    stored={'id':1,'status':'ACTIVE','observed_recently':True,'last_seen':'saved timestamp'}
    result=asset_view(stored,False)
    assert result['status']=='NOT_MONITORED' and result['last_observed_status']=='ACTIVE'
    assert result['last_seen']=='saved timestamp' and stored['status']=='ACTIVE'
def test_running_requires_a_recent_observation():
    assert asset_view({'status':'ACTIVE','observed_recently':False},True)['status']=='INACTIVE'
    assert asset_view({'status':'ACTIVE','observed_recently':True},True)['status']=='ACTIVE'
def test_dashboard_is_not_hidden_and_all_pages_have_history_banner():
    import app
    client=app.app.test_client()
    for page in ('/','/assets','/policy','/vulnerabilities','/alerts','/attack_paths','/remediation'):
        r=client.get(page);assert r.status_code==200
        assert b'data-state-banner' in r.data
    assert b'id="dash-live" style="display:none"' not in client.get('/').data
