import psycopg2

conn = psycopg2.connect(
    host="localhost",
    port=5432,
    dbname="postgres",
    user="postgres",
    password="admin"
)
conn.autocommit = True
cur = conn.cursor()

cur.execute("SELECT 1 FROM pg_database WHERE datname = 'cave_ot';")
exists = cur.fetchone()

if exists:
    print("Database cave_ot already exists!")
else:
    cur.execute("CREATE DATABASE cave_ot;")
    print("Database cave_ot created successfully!")

conn.close()
