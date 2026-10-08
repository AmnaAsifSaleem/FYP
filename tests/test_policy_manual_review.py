"""Policy review regressions; live SQL checks opt in through the existing fixture."""
import pytest
from policy_reviews import validate_request,fingerprint
from policy_engine import evaluate,DEFAULT_RULES

ASSET={'id':1,'ip':'192.0.2.1','port':502,'zone':'OT','service':'Modbus','device_type':'PLC',
       'criticality':.97,'encrypted':False,'days_since_patch':1,'firmware_eol':False,'cve_assessment_complete':True}

@pytest.mark.parametrize('bad',[None,[],{}, {'decision':{}},
    {'decision':'APPROVE','reviewer':'x','rationale':'short','assessment_fingerprint':'a'*64}])
def test_manual_review_rejects_invalid_input(bad):
    with pytest.raises(ValueError):validate_request(bad)

def test_policy_fingerprint_changes_with_evidence_not_packet_count():
    initial=evaluate(ASSET,[],DEFAULT_RULES)
    token,_=fingerprint(ASSET,[],DEFAULT_RULES,initial)
    traffic={**ASSET,'packet_count':999,'last_seen':'new time'}
    assert fingerprint(traffic,[],DEFAULT_RULES,evaluate(traffic,[],DEFAULT_RULES))[0]==token
    changed={**ASSET,'encrypted':True}
    assert fingerprint(changed,[],DEFAULT_RULES,evaluate(changed,[],DEFAULT_RULES))[0]!=token

def test_rule_results_remain_separate_from_analyst_choice():
    result=evaluate(ASSET,[],DEFAULT_RULES)
    action,*_=validate_request({'decision':'APPROVE','reviewer':'Analyst','rationale':'Compensating controls need operator validation.',
        'assessment_fingerprint':'a'*64,'acknowledge_findings':True})
    assert action=='APPROVE' and result['decision']=='RESTRICT'
    assert any(c['status']=='FAIL' for c in result['checks'])
