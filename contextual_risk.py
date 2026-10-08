"""CAVE-OT contextual prioritization, not the official CVSS equation.

Severity is adjusted by OT impact and criticality, then evidence contributes
bounded increments. Formula version is stored with generated snapshots.
"""
from validation import number
VERSION='cave-ot-2'
SEVERITY_WEIGHT={1:1.0,2:.6,3:.3}

def get_risk_tier(score):
    score=number(score,'risk_score',0,10)
    return next(t for limit,t in ((8,'CRITICAL'),(6,'HIGH'),(4,'MEDIUM'),(0,'LOW')) if score>=limit)

def score_details(cve,criticality,cia_lookup,alert_count=0,alert_severity=3,anomaly_score=0):
    cvss=number(cve.get('cvss',0),'cvss',0,10)
    epss=number(cve.get('epss',0),'epss',0,1)
    crit=number(criticality,'criticality',0,1)
    count=number(alert_count,'alert_count',0,1e12)
    anomaly=number(anomaly_score,'anomaly_score',0,1)
    kev=cve.get('kev',False)
    if kev not in (False,True,0,1):raise ValueError('kev must be boolean')
    if alert_severity not in SEVERITY_WEIGHT:raise ValueError('alert_severity must be 1, 2, or 3')
    impacts=cia_lookup.get(cve.get('cve_id'))
    source='db' if impacts is not None else 'unknown'
    if impacts is not None:
        if len(impacts)!=3:raise ValueError('CIA lookup requires three impacts')
        c,i,a=[number(v,'CIA impact',0,1) for v in impacts]
        impact=min(1,(.2*c+.3*i+.5*a)/.56)
    else:
        c=i=a=None
        impact=1 # uncertainty never fabricates CIA observations
    base=cvss*(.7+.3*impact)*(.5+.5*crit)
    exploit=epss*.75+(.75 if kev else 0)
    ids=min(count*SEVERITY_WEIGHT[alert_severity]/30,1)*1.5 if alert_severity<=2 else 0
    score=round(min(base+exploit+ids+anomaly,10),1)
    return {'risk_score':score,'risk_tier':get_risk_tier(score),'c_impact':c,'i_impact':i,'a_impact':a,
            'cia_source':source,'score_version':VERSION,'contributions':{'base':round(base,3),'exploitation':round(exploit,3),'ids':round(ids,3),'confirmed_anomaly':anomaly}}

def score_cve(cve,criticality,cia_lookup,alert_count=0,alert_severity=3,anomaly_score=0):
    r=score_details(cve,criticality,cia_lookup,alert_count,alert_severity,anomaly_score)
    return r['risk_score'],r['c_impact'],r['i_impact'],r['a_impact'],r['cia_source']
