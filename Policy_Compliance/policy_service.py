"""One transaction-backed evaluator for manual and monitoring checks."""
import json
from policy_engine import evaluate
from policy_gatekeeper import load_active_rules

def evaluate_and_save(cur,asset,rules=None):
    aid=asset['id'];rules=load_active_rules(cur) if rules is None else rules
    cur.execute('SELECT * FROM vulnerabilities WHERE asset_id=%s',(aid,))
    cves=[dict(c) for c in cur.fetchall()]
    result=evaluate(dict(asset),cves,rules)
    from policy_reviews import fingerprint
    result['assessment_fingerprint']=fingerprint(dict(asset),cves,rules,result)[0]
    cur.execute('''INSERT INTO policy_compliance (asset_id,compliance_status,compliance_score,confidence,explanation,key_factors,decision,coverage)
      VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (asset_id) DO UPDATE SET
      compliance_status=EXCLUDED.compliance_status,compliance_score=EXCLUDED.compliance_score,
      confidence=EXCLUDED.confidence,explanation=EXCLUDED.explanation,key_factors=EXCLUDED.key_factors,
      decision=EXCLUDED.decision,coverage=EXCLUDED.coverage,checked_at=NOW() RETURNING id''',
      (aid,result['compliance_status'],result['compliance_score'],result['coverage'],result['explanation'],json.dumps(result),result['decision'],result['coverage']))
    row=cur.fetchone();cid=row['id'] if isinstance(row,dict) else row[0]
    cur.execute('DELETE FROM policy_violations WHERE compliance_id=%s',(cid,))
    cur.execute("DELETE FROM alerts WHERE asset_id=%s AND alert_category='POLICY'",(aid,))
    for rule in result['checks']:
        if rule['status']!='FAIL':continue
        cur.execute('''INSERT INTO policy_violations (compliance_id,violated_policy,policy_source,severity,remediation)
             VALUES (%s,%s,%s,%s,%s)''',(cid,rule['rule_name']+': '+rule['reason'],rule['policy_source'],rule['severity'],rule['action']))
        cur.execute('''INSERT INTO alerts (asset_id,alert_signature,alert_category,severity,protocol,is_active_attack,alert_count)
             VALUES (%s,%s,'POLICY',2,%s,FALSE,1) ON CONFLICT (asset_id,alert_signature) DO UPDATE SET
             alert_count=1,is_active_attack=FALSE''',(aid,'Policy: '+rule['rule_name'],asset.get('service')))
    return result

def run_checks(conn,asset_id=None):
    import psycopg2.extras
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute('SELECT * FROM assets WHERE id=%s' if asset_id is not None else 'SELECT * FROM assets ORDER BY id', (asset_id,) if asset_id is not None else ())
        assets=[dict(a) for a in cur.fetchall()]
        if asset_id is not None and not assets:raise LookupError('Asset not found')
        rules=load_active_rules(cur)
        return [{'asset_id':a['id'],'asset_name':f"{a.get('vendor') or 'Unknown'} {a.get('product') or 'Unknown'}",'prediction':evaluate_and_save(cur,a,rules)} for a in assets]
