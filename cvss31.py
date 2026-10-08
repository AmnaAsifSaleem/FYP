"""FIRST CVSS v3.1 equations, sections 6-7 and Appendix A.
https://www.first.org/cvss/v3.1/specification-document
Only complete v3.1 vectors are supported; no inference from EPSS or KEV.
"""
import math
ALLOWED = {'AV':'NALP','AC':'LH','PR':'NLH','UI':'NR','S':'UC',
           'C':'HLN','I':'HLN','A':'HLN','E':'XHFPU','RL':'XUWTO','RC':'XCRU',
           'CR':'XHML','IR':'XHML','AR':'XHML','MAV':'XNALP','MAC':'XLH',
           'MPR':'XNLH','MUI':'XNR','MS':'XUC','MC':'XHLN','MI':'XHLN','MA':'XHLN'}
IMPACT = {'N':0.,'L':.22,'H':.56}
REQUIREMENT = {'X':1.,'M':1.,'L':.5,'H':1.5}

def roundup(value):
    scaled = math.floor(value*100000 + .5)
    return scaled/100000 if scaled%10000 == 0 else (scaled//10000+1)/10

def parse(vector):
    if not isinstance(vector,str) or not vector.startswith('CVSS:3.1/'):
        raise ValueError('A complete CVSS:3.1 vector is required')
    result={}
    for item in vector.split('/')[1:]:
        parts=item.split(':')
        if len(parts)!=2:raise ValueError('Invalid CVSS metric')
        key,value=parts
        if key in result or key not in ALLOWED or len(value)!=1 or value not in ALLOWED[key]:
            raise ValueError('Invalid or duplicate CVSS metric: '+key)
        result[key]=value
    if any(key not in result for key in ('AV','AC','PR','UI','S','C','I','A')):
        raise ValueError('CVSS vector is missing base metrics')
    return result

def calculate(vector, requirements=None):
    metrics=parse(vector)
    if requirements is not None:
        if not isinstance(requirements,dict) or set(requirements)-{'CR','IR','AR'}:
            raise ValueError('Security requirements must contain only CR, IR and AR')
        for key,value in requirements.items():
            if not isinstance(value,str) or value not in REQUIREMENT:raise ValueError('Invalid security requirement: '+key)
            metrics[key]=value
    def value(key):return metrics.get(key,'X')
    def modified(key):
        v=value('M'+key)
        return metrics[key] if v=='X' else v
    def exploit(av,ac,pr,ui,scope):
        privileges={'N':.85,'L':.68 if scope=='C' else .62,'H':.5 if scope=='C' else .27}
        return 8.22*{'N':.85,'A':.62,'L':.55,'P':.2}[av]*{'L':.77,'H':.44}[ac]*privileges[pr]*{'N':.85,'R':.62}[ui]
    def impact(iss,scope,environment=False):
        if scope=='U':return 6.42*iss
        if environment:return 7.52*(iss-.029)-3.25*(iss*.9731-.02)**13
        return 7.52*(iss-.029)-3.25*(iss-.02)**15
    def combined(imp,exp,scope):
        return 0. if imp<=0 else roundup(min((1.08 if scope=='C' else 1)*(imp+exp),10))
    c,i,a=[IMPACT[metrics[k]] for k in ('C','I','A')]
    iss=1-(1-c)*(1-i)*(1-a)
    base=combined(impact(iss,metrics['S']),exploit(*(metrics[k] for k in ('AV','AC','PR','UI','S'))),metrics['S'])
    temporal_factor={'X':1,'H':1,'F':.97,'P':.94,'U':.91}[value('E')]*{'X':1,'U':1,'W':.97,'T':.96,'O':.95}[value('RL')]*{'X':1,'C':1,'R':.96,'U':.92}[value('RC')]
    miss=min(1-(1-REQUIREMENT[value('CR')]*IMPACT[modified('C')])*(1-REQUIREMENT[value('IR')]*IMPACT[modified('I')])*(1-REQUIREMENT[value('AR')]*IMPACT[modified('A')]),.915)
    scope=modified('S')
    environmental=roundup(combined(impact(miss,scope,True),exploit(*(modified(k) for k in ('AV','AC','PR','UI','S'))),scope)*temporal_factor)
    return {'base':base,'temporal':roundup(base*temporal_factor),'environmental':environmental,
            'vector':'CVSS:3.1/'+'/'.join(f'{key}:{metrics[key]}' for key in ALLOWED if key in metrics),
            'requirements':{key:value(key) for key in ('CR','IR','AR')},'impacts':(c,i,a)}
