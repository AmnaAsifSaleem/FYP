"""Compatibility entry point for the shared deterministic policy service."""
import os,sys
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import psycopg2
from pipeline_paths import DB_CONFIG
from policy_service import run_checks
class PolicyComplianceIntegrator:
    def run_compliance_check(self):
        with psycopg2.connect(**DB_CONFIG) as conn:
            results=run_checks(conn)
        print(f"Checked {len(results)} assets with deterministic rules")
        return True
if __name__=='__main__':
    PolicyComplianceIntegrator().run_compliance_check()
