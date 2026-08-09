import psycopg2
import os

DB_CONFIG = {
    "host":     "localhost",
    "port":     5432,
    "dbname":   "cave_ot",
    "user":     "postgres",
    "password": "admin"
}

SCHEMA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "db_schema.sql")

def main():
    print("=" * 50)
    print("CAVE-OT DATABASE SETUP")
    print("=" * 50)

    print("\n[1/3] Reading schema file...")
    if not os.path.exists(SCHEMA_FILE):
        print(f"ERROR: db_schema.sql not found")
        return
    with open(SCHEMA_FILE, 'r') as f:
        schema_sql = f.read()
    print("  OK: db_schema.sql loaded")

    print("\n[2/3] Connecting to cave_ot database...")
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = True
        print("  OK: Connected to cave_ot")
    except Exception as e:
        print(f"  ERROR: {e}")
        return

    print("\n[3/3] Creating tables...")
    try:
        cur = conn.cursor()
        cur.execute(schema_sql)
        conn.close()
        print("  OK: All tables created")
    except Exception as e:
        print(f"  ERROR: {e}")
        return

    print("\nSETUP COMPLETE")
    print("Tables created: assets, vulnerabilities, alerts")

if __name__ == "__main__":
    main()
