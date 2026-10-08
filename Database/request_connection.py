"""Ensure connections close even when handlers return early or raise."""
import psycopg2
from flask import g,has_request_context
def connect(config):
    conn=psycopg2.connect(**config)
    if has_request_context():
        if not hasattr(g,'caveot_connections'):g.caveot_connections=[]
        g.caveot_connections.append(conn)
    return conn
def close_connections(error=None):
    for conn in g.pop('caveot_connections',[]):
        if not conn.closed:conn.close()
