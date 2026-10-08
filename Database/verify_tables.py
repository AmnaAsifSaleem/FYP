import os
import psycopg2

conn = psycopg2.connect(
    host="localhost", port=5432,
    dbname="cave_ot", user="postgres", password=os.environ.get("CAVE_OT_DB_PASSWORD", "")
)
cur = conn.cursor()
cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name;")
tables = cur.fetchall()
print("Tables in cave_ot database:")
for t in tables:
    print(" -", t[0])

# Check columns of assets table
print("\nColumns in assets table:")
cur.execute("SELECT column_name, data_type FROM information_schema.columns WHERE table_name='assets' ORDER BY ordinal_position;")
for col in cur.fetchall():
    print(f"  {col[0]:<20} {col[1]}")

conn.close()
