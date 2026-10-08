import os
import psycopg2
import sys

try:
    # Try default PostgreSQL configuration
    conn = psycopg2.connect(
        host="localhost",
        database="postgres",  # Try default database first
        user="postgres",
        password=os.environ.get("CAVE_OT_DB_PASSWORD", ""),
        port=5432
    )
    print("✓ Connected to PostgreSQL")
    
    # Check if cave_ot database exists
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM pg_database WHERE datname = 'cave_ot'")
    exists = cursor.fetchone()
    
    if exists:
        print("✓ 'cave_ot' database exists")
    else:
        print("✗ 'cave_ot' database doesn't exist - will need to create it")
        
    cursor.close()
    conn.close()
    
except Exception as e:
    print(f"✗ PostgreSQL connection failed: {e}")
    print("Please ensure PostgreSQL is running with:")
    print("  Host: localhost")
    print("  Port: 5432")
    print("  User: postgres")
    print("  Password: set CAVE_OT_DB_PASSWORD in your environment")