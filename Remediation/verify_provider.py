"""Verify Groq connectivity without printing or storing credentials."""
import os,sys,json,urllib.request,urllib.error
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import remediation_advisor as advisor

def key():
    value=os.environ.get('GROQ_API_KEY','')
    if not value and os.name=='nt':
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,'Environment') as registry:
                value=winreg.QueryValueEx(registry,'GROQ_API_KEY')[0]
        except FileNotFoundError:pass
    return value

def verify(generate=False):
    credential=key()
    req=urllib.request.Request('https://api.groq.com/openai/v1/models',headers={'User-Agent':'Mozilla/5.0'})
    if credential:req.add_header('Authorization','Bearer '+credential)
    try:
        with urllib.request.urlopen(req,timeout=15) as r:models=json.load(r)
    except urllib.error.HTTPError as e:
        return {'reachable':True,'authenticated':False,'http_status':e.code,'key_configured':bool(credential)}
    except urllib.error.URLError as e:
        return {'reachable':False,'authenticated':False,'key_configured':bool(credential),'error':str(e.reason)}
    available={m['id'] for m in models.get('data',[])}
    result={'reachable':True,'authenticated':True,'model_available':advisor.GROQ_MODEL in available,'model':advisor.GROQ_MODEL}
    if generate and result['model_available']:
        os.environ['GROQ_API_KEY']=credential
        prompt='Connectivity test only. Return the required JSON fields. Recommendation: verify vendor evidence before choosing a patch. Rationale: test connection only. OT safety note: no operational change authorized. Maintenance window: true. Confidence: 0.5. References: empty list.'
        response=advisor._parse_response(advisor._call_groq(prompt,attempts=1))
        result['structured_generation_verified']=True
        result['generated_fields']=list(response.model_dump())
    return result

if __name__=='__main__':
    result=verify('--generate' in sys.argv)
    print(json.dumps(result,indent=2))
    sys.exit(0 if result.get('authenticated') else 2)
