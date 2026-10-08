"""Idempotent analyst-review ledger setup; preserve all existing decisions."""
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'Policy_Compliance'))
from policy_reviews import SQL

def ensure(conn):
    with conn.cursor() as cur:cur.execute(SQL)

if __name__=='__main__':
    import psycopg2
    from pipeline_paths import DB_CONFIG
    with psycopg2.connect(**DB_CONFIG) as conn:ensure(conn)
    print('Analyst policy review ledger ready; existing decisions preserved.')
