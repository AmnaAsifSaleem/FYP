"""Idempotent repair with preserved before-images; one transaction per version."""
import os,sys,json
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import psycopg2
from pipeline_paths import DB_CONFIG
VERSION='20261006_evidence_policy_v2'
SQL="""
CREATE TABLE IF NOT EXISTS schema_migrations(version TEXT PRIMARY KEY,applied_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS audit_repair_archive(id BIGSERIAL PRIMARY KEY,reason TEXT NOT NULL,source_table TEXT NOT NULL,row_data JSONB NOT NULL,archived_at TIMESTAMPTZ DEFAULT NOW());
ALTER TABLE assets ADD COLUMN IF NOT EXISTS identity_source TEXT DEFAULT 'legacy_inventory';
ALTER TABLE assets ADD COLUMN IF NOT EXISTS identity_verified BOOLEAN DEFAULT FALSE;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS encrypted BOOLEAN;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS days_since_patch INTEGER;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS firmware_eol BOOLEAN;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS cve_assessment_complete BOOLEAN DEFAULT FALSE;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS applicability TEXT NOT NULL DEFAULT 'UNKNOWN';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS applicability_evidence TEXT;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS score_version TEXT DEFAULT 'legacy';
ALTER TABLE policy_compliance ADD COLUMN IF NOT EXISTS decision TEXT DEFAULT 'NEEDS_REVIEW';
ALTER TABLE policy_compliance ADD COLUMN IF NOT EXISTS coverage FLOAT DEFAULT 0;
"""
def migrate(conn):
    with conn.cursor() as cur:
        cur.execute('SELECT pg_advisory_xact_lock(20261006)')
        cur.execute(SQL)
        cur.execute('SELECT 1 FROM schema_migrations WHERE version=%s',(VERSION,))
        if cur.fetchone():
            from runtime_constraints import apply
            apply(conn)
            return False
        # Preserve old verdicts and CVE associations before changing their interpretation.
        for table in ('policy_compliance','vulnerabilities','remediation_recommendations'):
            cur.execute("SELECT to_regclass(%s)",(table,))
            if cur.fetchone()[0]:
                cur.execute(f"INSERT INTO audit_repair_archive(reason,source_table,row_data) SELECT 'pre-evidence-v2 snapshot',%s,to_jsonb(t) FROM {table} t",(table,))
        cur.execute("INSERT INTO audit_repair_archive(reason,source_table,row_data) SELECT 'artificial port-zero asset','assets',to_jsonb(a) FROM assets a WHERE port=0")
        # Orphan/fixture child rows are archived before cleanup.
        cur.execute("INSERT INTO audit_repair_archive(reason,source_table,row_data) SELECT 'detached compliance violation','policy_violations',to_jsonb(v) FROM policy_violations v JOIN policy_compliance p ON p.id=v.compliance_id LEFT JOIN assets a ON a.id=p.asset_id WHERE a.id IS NULL OR a.port=0")
        cur.execute('DELETE FROM policy_violations WHERE compliance_id IN (SELECT p.id FROM policy_compliance p LEFT JOIN assets a ON a.id=p.asset_id WHERE a.id IS NULL OR a.port=0)')
        cur.execute('DELETE FROM policy_compliance WHERE asset_id NOT IN (SELECT id FROM assets WHERE port<>0)')
        cur.execute('DELETE FROM assets WHERE port=0')
        cur.execute("SELECT 1 FROM pg_constraint WHERE conrelid='policy_compliance'::regclass AND contype='f'")
        if not cur.fetchone():cur.execute('ALTER TABLE policy_compliance ADD CONSTRAINT policy_asset_fk FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE')
        cur.execute("INSERT INTO audit_repair_archive(reason,source_table,row_data) SELECT 'duplicate rule','policy_rules',to_jsonb(r) FROM policy_rules r WHERE id NOT IN (SELECT MIN(id) FROM policy_rules GROUP BY rule_name)")
        cur.execute('DELETE FROM policy_rules WHERE id NOT IN (SELECT MIN(id) FROM policy_rules GROUP BY rule_name)')
        cur.execute('CREATE UNIQUE INDEX IF NOT EXISTS policy_rule_name_unique ON policy_rules(rule_name)')
        cur.execute("UPDATE policy_rules SET cvss_threshold=7 WHERE rule_name='High CVSS Alert' AND cvss_threshold IS NULL")
        cur.execute("UPDATE policy_rules SET days_since_patch_threshold=35 WHERE rule_name='Patch Compliance' AND days_since_patch_threshold IS NULL")
        cur.execute("UPDATE vulnerabilities SET applicability='UNKNOWN',applicability_evidence='Legacy similarity association; confirm product and firmware before remediation'")
        cur.execute("UPDATE assets SET identity_source='legacy_configured_inventory',identity_verified=FALSE,encrypted=NULL,days_since_patch=NULL,firmware_eol=NULL,cve_assessment_complete=FALSE")
        cur.execute("UPDATE policy_compliance SET compliance_status='NEEDS_REVIEW',decision='NEEDS_REVIEW',coverage=0,confidence=0,key_factors='{}',explanation='Awaiting deterministic evaluation of observed evidence'")
        cur.execute('INSERT INTO schema_migrations(version) VALUES (%s)',(VERSION,))
    from runtime_constraints import apply
    apply(conn)
    return True

if __name__=='__main__':
    with psycopg2.connect(**DB_CONFIG) as conn:
        changed=migrate(conn)
    print('Migration applied; before-images saved in audit_repair_archive' if changed else 'Migration already applied')
