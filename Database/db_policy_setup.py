"""
Policy Compliance Database Setup
Adds policy compliance tables to existing CAVE-OT database
"""

import psycopg2
import os

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "cave_ot",
    "user": "postgres",
    "password": "admin"
}

SCHEMA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "db_schema_policy.sql")

def main():
    print("=" * 60)
    print("CAVE-OT POLICY COMPLIANCE DATABASE SETUP")
    print("=" * 60)

    print("\n[1/3] Reading policy schema file...")
    if not os.path.exists(SCHEMA_FILE):
        print(f"ERROR: db_schema_policy.sql not found")
        return
    with open(SCHEMA_FILE, 'r') as f:
        schema_sql = f.read()
    print("  OK: db_schema_policy.sql loaded")

    print("\n[2/3] Connecting to cave_ot database...")
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = True
        print("  OK: Connected to cave_ot")
    except Exception as e:
        print(f"  ERROR: {e}")
        return

    print("\n[3/3] Creating policy compliance tables...")
    try:
        cur = conn.cursor()
        
        # Execute schema SQL
        cur.execute(schema_sql)
        
        # Verify tables were created
        cur.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema='public' 
            AND table_name LIKE 'policy_%'
            ORDER BY table_name;
        """)
        
        policy_tables = cur.fetchall()
        print(f"  OK: {len(policy_tables)} policy tables created")
        for table in policy_tables:
            print(f"    - {table[0]}")
        
        conn.close()
        print("\nPOLICY COMPLIANCE SETUP COMPLETE")
        print("Tables created: policy_compliance, policy_violations, policy_rules")
        print("View created: compliance_dashboard")
        
    except Exception as e:
        print(f"  ERROR: {e}")
        return

if __name__ == "__main__":
    main()
