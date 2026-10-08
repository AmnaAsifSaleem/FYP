"""Separate, append-only analyst decisions tied to policy evidence snapshots.

Reviewer names are entered by the user in this local prototype; they are not
authenticated identities. Decisions do not change rule outcomes or devices.
"""
import hashlib,json
from policy_engine import evaluate
from policy_gatekeeper import load_active_rules

ACTIONS={'APPROVE','REJECT','RESTRICT','REMEDIATE','DEFER'}
ASSET_FIELDS=('id','ip','port','zone','service','device_type','encrypted','days_since_patch',
              'firmware_eol','cve_assessment_complete','identity_verified','firmware','criticality')
RULE_FIELDS=('rule_name','zone','service','port','encrypted','device_type','cvss_threshold',
             'epss_threshold','days_since_patch_threshold','policy_source')

SQL="""CREATE TABLE IF NOT EXISTS policy_manual_reviews (
 id BIGSERIAL PRIMARY KEY,
 asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
 analyst_decision VARCHAR(12) NOT NULL CHECK (analyst_decision IN ('APPROVE','REJECT','RESTRICT','REMEDIATE','DEFER')),
 reviewer VARCHAR(120) NOT NULL,
 rationale TEXT NOT NULL,
 acknowledged_findings BOOLEAN NOT NULL DEFAULT FALSE,
 system_recommendation VARCHAR(20) NOT NULL,
 assessment_fingerprint CHAR(64) NOT NULL,
 assessment_snapshot JSONB NOT NULL,
 decided_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS policy_manual_review_latest ON policy_manual_reviews(asset_id,decided_at DESC,id DESC);
"""

def fingerprint(asset,cves,rules,result):
    snapshot={'asset':{k:asset.get(k) for k in ASSET_FIELDS},
        'cves':sorted(({k:c.get(k) for k in ('cve_id','cvss','applicability')} for c in cves),key=lambda c:str(c['cve_id'])),
        'rules':sorted(({k:r.get(k) for k in RULE_FIELDS} for r in rules),key=lambda r:str(r['rule_name'])),
        'checks':sorted(result['checks'],key=lambda r:r['rule_name']),
        'system_recommendation':result['decision']}
    encoded=json.dumps(snapshot,sort_keys=True,separators=(',',':'),default=str,allow_nan=False)
    return hashlib.sha256(encoded.encode()).hexdigest(),snapshot

def assess(cur,asset_id,lock=False):
    cur.execute('SELECT * FROM assets WHERE id=%s'+(' FOR UPDATE' if lock else ''),(asset_id,))
    row=cur.fetchone()
    if not row:raise LookupError('Asset not found')
    asset=dict(row)
    cur.execute('SELECT * FROM vulnerabilities WHERE asset_id=%s',(asset_id,))
    cves=[dict(row) for row in cur.fetchall()]
    rules=load_active_rules(cur)
    result=evaluate(asset,cves,rules)
    token,snapshot=fingerprint(asset,cves,rules,result)
    return asset,cves,rules,result,token,snapshot

def validate_request(data):
    if not isinstance(data,dict):raise ValueError('A JSON object is required')
    action=data.get('decision')
    if not isinstance(action,str) or action not in ACTIONS:raise ValueError('Select a valid analyst decision')
    reviewer=data.get('reviewer');rationale=data.get('rationale');token=data.get('assessment_fingerprint')
    if not isinstance(reviewer,str) or not 2<=len(reviewer.strip())<=120:
        raise ValueError('Enter a reviewer name of 2-120 characters')
    if not isinstance(rationale,str) or not 10<=len(rationale.strip())<=4000:
        raise ValueError('Explain the decision in 10-4000 characters')
    if not isinstance(token,str) or len(token)!=64 or any(c not in '0123456789abcdef' for c in token):
        raise ValueError('Load the current assessment before saving a decision')
    ack=data.get('acknowledge_findings',False)
    if not isinstance(ack,bool):raise ValueError('Acknowledgment must be true or false')
    return action,reviewer.strip(),rationale.strip(),token,ack

class EvidenceChanged(Exception):pass

def save_review(conn,asset_id,data):
    import psycopg2.extras
    action,reviewer,rationale,expected,ack=validate_request(data)
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        asset,cves,rules,result,token,snapshot=assess(cur,asset_id,lock=True)
        if expected!=token:raise EvidenceChanged('Evidence changed. Reload and review the current assessment before saving.')
        has_findings=any(c['status'] in ('FAIL','UNKNOWN') for c in result['checks']) or bool(result.get('validation_errors')) or not result['checks']
        if action=='APPROVE' and has_findings and not ack:
            raise ValueError('Approval with failed or missing checks requires explicit acknowledgment and rationale')
        # Save the latest deterministic result independently; never replace it
        # with the analyst choice. Monitoring updates this table, not the audit.
        from policy_service import evaluate_and_save
        evaluate_and_save(cur,asset,rules)
        cur.execute('''INSERT INTO policy_manual_reviews
          (asset_id,analyst_decision,reviewer,rationale,acknowledged_findings,
           system_recommendation,assessment_fingerprint,assessment_snapshot)
          VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
          RETURNING id,asset_id,analyst_decision,reviewer,rationale,acknowledged_findings,system_recommendation,assessment_fingerprint,decided_at''',
          (asset_id,action,reviewer,rationale,ack,result['decision'],token,json.dumps(snapshot,default=str,allow_nan=False)))
        return dict(cur.fetchone())

def public_review(row,current_token):
    if row is None:return None
    result=dict(row)
    result.pop('assessment_snapshot',None)
    result['needs_revalidation']=result['assessment_fingerprint']!=current_token
    if result.get('decided_at'):result['decided_at']=result['decided_at'].isoformat()
    return result
