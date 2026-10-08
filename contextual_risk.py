"""FIRST CVSS severity plus explicitly custom operational prioritization.
Full v3.1 vectors permit Environmental scoring. Legacy records retain their
reported CVSS; missing vectors/CIA are never reverse-engineered.
"""
from validation import number
from cvss31 import calculate
from risk_policy import (POLICY_VERSION,CRITICALITY_FLOOR,EPSS_MAX_POINTS,KEV_POINTS,
    IDS_MAX_POINTS,ANOMALY_MAX_POINTS,IDS_WEIGHTED_EVENT_CAPACITY,IDS_SEVERITY_WEIGHT,CVSS_REQUIREMENTS)
VERSION='cave-ot-3'
SEVERITY_WEIGHT=IDS_SEVERITY_WEIGHT

def get_risk_tier(score):
    score=number(score,'risk_score',0,10)
    # FIRST numeric boundaries reused for project priority; zero priority LOW.
    return next(t for limit,t in ((9,'CRITICAL'),(7,'HIGH'),(4,'MEDIUM'),(0,'LOW')) if score>=limit)

def score_details(cve,criticality,cia_lookup,alert_count=0,alert_severity=3,anomaly_score=0,*,weighted_alert_count=None,security_requirements=None):
    cvss=number(cve.get('cvss',0),'cvss',0,10)
    epss=number(cve.get('epss',0),'epss',0,1)
    crit=number(criticality,'criticality',0,1)
    count=number(alert_count,'alert_count',0,1e12)
    anomaly=number(anomaly_score,'anomaly_score',0,1)
    kev=cve.get('kev',False)
    if kev not in (False,True,0,1):raise ValueError('kev must be boolean')
    if alert_severity not in SEVERITY_WEIGHT:raise ValueError('alert_severity must be 1, 2, or 3')
    requirements=({k:v for k,v in CVSS_REQUIREMENTS.items() if v!='X'}
                  if security_requirements is None else security_requirements)
    standard=None;reason='Full CVSS v3.1 vector unavailable; reported CVSS retained'
    vector=cve.get('cvss_vector')
    if isinstance(vector,str) and vector.startswith('CVSS:3.1/'):
        try:
            standard=calculate(vector,requirements)
            reason='FIRST CVSS v3.1 Environmental calculation'
        except ValueError as e:
            reason='Invalid CVSS vector or requirements; reported CVSS retained: '+str(e)
    impacts=standard['impacts'] if standard else cia_lookup.get(cve.get('cve_id'))
    source='cvss_vector' if standard else 'db' if impacts is not None else 'unknown'
    if impacts is not None:
        if len(impacts)!=3:raise ValueError('CIA lookup requires three impacts')
        c,i,a=[number(v,'CIA impact',0,1) for v in impacts]
    else:
        c=i=a=None
    severity=standard['environmental'] if standard else cvss
    base=severity*(CRITICALITY_FLOOR+(1-CRITICALITY_FLOOR)*crit)
    exploit=epss*EPSS_MAX_POINTS+(KEV_POINTS if kev else 0)
    # Live callers supply recent per-event weights. Homogeneous counts are
    # retained for legacy/offline callers, without claiming live freshness.
    weighted=number(weighted_alert_count,'weighted alerts',0,1e12) if weighted_alert_count is not None else count*SEVERITY_WEIGHT[alert_severity]
    ids=min(weighted/IDS_WEIGHTED_EVENT_CAPACITY,1)*IDS_MAX_POINTS
    anomaly_contribution=anomaly*ANOMALY_MAX_POINTS
    total=base+exploit+ids+anomaly_contribution
    score=round(min(total,10),1)
    return {'risk_score':score,'risk_tier':get_risk_tier(score),'priority_total':round(total,6),
            'c_impact':c,'i_impact':i,'a_impact':a,'cia_source':source,'score_version':VERSION,
            'policy_version':POLICY_VERSION,'severity_basis':reason,
            'cvss_environmental':standard['environmental'] if standard else None,
            'cvss_environmental_vector':standard['vector'] if standard else None,
            'cvss_severity_tier':('NONE' if cvss==0 else get_risk_tier(cvss)),
            'contributions':{'base':round(base,3),'exploitation':round(exploit,3),'ids':round(ids,3),'confirmed_anomaly':round(anomaly_contribution,3)}}

def score_cve(cve,criticality,cia_lookup,alert_count=0,alert_severity=3,anomaly_score=0,**kwargs):
    r=score_details(cve,criticality,cia_lookup,alert_count,alert_severity,anomaly_score,**kwargs)
    return r['risk_score'],r['c_impact'],r['i_impact'],r['a_impact'],r['cia_source']
