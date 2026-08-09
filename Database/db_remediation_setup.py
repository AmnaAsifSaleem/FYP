"""
Remediation Advisor Database Setup
Adds remediation recommendation + gatekeeper audit tables to the CAVE-OT database
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

SCHEMA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "db_schema_remediation.sql")

def main():
    print("=" * 60)
    print("CAVE-OT REMEDIATION ADVISOR DATABASE SETUP")
    print("=" * 60)

    print("\n[1/3] Reading remediation schema file...")
    if not os.path.exists(SCHEMA_FILE):
        print(f"ERROR: db_schema_remediation.sql not found")
        return
    with open(SCHEMA_FILE, 'r') as f:
        schema_sql = f.read()
    print("  OK: db_schema_remediation.sql loaded")

    print("\n[2/3] Connecting to cave_ot database...")
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = True
        print("  OK: Connected to cave_ot")
    except Exception as e:
        print(f"  ERROR: {e}")
        return

    print("\n[3/3] Creating remediation tables...")
    try:
        cur = conn.cursor()

        cur.execute(schema_sql)

        cur.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema='public'
            AND table_name LIKE 'remediation_%'
            ORDER BY table_name;
        """)

        remediation_tables = cur.fetchall()
        print(f"  OK: {len(remediation_tables)} remediation tables created")
        for table in remediation_tables:
            print(f"    - {table[0]}")

        conn.close()
        print("\nREMEDIATION ADVISOR SETUP COMPLETE")
        print("Tables created: remediation_recommendations, remediation_gatekeeper_audit")

    except Exception as e:
        print(f"  ERROR: {e}")
        return

if __name__ == "__main__":
    main()
