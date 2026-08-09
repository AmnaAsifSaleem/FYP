#!/usr/bin/env python3
"""
Check if policy tables exist in database
"""

import psycopg2
import os
import sys

# Add project root to path
project_root = os.path.join(os.path.dirname(__file__), '..', '..')
sys.path.insert(0, project_root)

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "cave_ot",
    "user": "postgres",
    "password": "CAVEOT"
}

def main():
    print("Checking policy tables in database...")
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        
        # Check for policy tables
        cur.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema='public' 
            AND table_name LIKE 'policy_%'
            ORDER BY table_name;
        """)
        
        tables = cur.fetchall()
        
        if tables:
            print(f"✓ Found {len(tables)} policy tables:")
            for table in tables:
                print(f"  - {table[0]}")
        else:
            print("✗ No policy tables found")
            
        # Check for the view
        cur.execute("""
            SELECT table_name 
            FROM information_schema.views 
            WHERE table_schema='public' 
            AND table_name = 'compliance_dashboard';
        """)
        
        view = cur.fetchone()
        if view:
            print(f"✓ Found view: {view[0]}")
        else:
            print("✗ View 'compliance_dashboard' not found")
            
        conn.close()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()