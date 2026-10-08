"""Additional non-destructive constraints and remediation audit columns."""
import os,sys
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pipeline_paths import DB_CONFIG
import psycopg2
def apply(conn):
    from Database.migrate_policy_reviews import ensure
    ensure(conn)
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO policy_rules(rule_name,description,policy_source,zone,is_active)
            SELECT 'IT Zone OT Protocol Restriction','Modbus, S7comm, DNP3 and BACnet are prohibited in the plant IT zone; require analyst restriction review','Plant segmentation policy','IT',TRUE
            WHERE NOT EXISTS (SELECT 1 FROM policy_rules WHERE rule_name='IT Zone OT Protocol Restriction')""")
        cur.execute('ALTER TABLE remediation_recommendations ADD COLUMN IF NOT EXISTS context_fingerprint TEXT')
        cur.execute('''CREATE TABLE IF NOT EXISTS remediation_decision_audit(
          id BIGSERIAL PRIMARY KEY,recommendation_id INTEGER REFERENCES remediation_recommendations(id) ON DELETE SET NULL,
          previous_status TEXT,new_status TEXT,decision_note TEXT,gatekeeper_verdict TEXT,decided_at TIMESTAMPTZ DEFAULT NOW())''')
        for table,name,condition in (
          ('assets','asset_port_range','port BETWEEN 1 AND 65535'),
          ('assets','asset_criticality_range','criticality BETWEEN 0 AND 1'),
          ('assets','asset_patch_age_range','days_since_patch IS NULL OR days_since_patch>=0'),
          ('vulnerabilities','vulnerability_score_range','risk_score BETWEEN 0 AND 10'),
          ('vulnerabilities','vulnerability_cvss_range','cvss BETWEEN 0 AND 10'),
          ('vulnerabilities','vulnerability_epss_range','epss BETWEEN 0 AND 1')):
            cur.execute('SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass AND conname=%s',(table,name))
            if not cur.fetchone():cur.execute(f'ALTER TABLE {table} ADD CONSTRAINT {name} CHECK ({condition})')
if __name__=='__main__':
    with psycopg2.connect(**DB_CONFIG) as conn:apply(conn)
    print('Runtime validation constraints and decision audit verified')
