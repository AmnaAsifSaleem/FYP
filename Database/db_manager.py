"""
CAVE-OT Database Manager
========================
All database read/write functions live here.
Every other db script imports from this file.

Connection config is at the top — change password/host here if needed.
"""

import psycopg2
import psycopg2.extras
import json
from datetime import datetime

# ── Database connection settings ──────────────────────────────
DB_CONFIG = {
    "host":     "localhost",
    "port":     5432,
    "dbname":   "cave_ot",
    "user":     "postgres",
    "password": "admin"
}

# Assets not seen for this many minutes get marked INACTIVE
INACTIVE_AFTER_MINUTES = 10


def get_connection():
    """Open and return a database connection."""
    return psycopg2.connect(**DB_CONFIG)


def test_connection():
    """Test the database connection. Returns True if OK, False if failed."""
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT version();")
        version = cur.fetchone()[0]
        conn.close()
        print(f"  Connected: {version[:60]}")
        return True
    except Exception as e:
        print(f"  Connection failed: {e}")
        return False


# ─────────────────────────────────────────────────────────────
# ASSET FUNCTIONS
# ─────────────────────────────────────────────────────────────

def upsert_asset(conn, asset):
    """
    Save a device to the assets table.

    UPSERT means:
    - If this IP+port does NOT exist yet  → INSERT a new row
    - If this IP+port ALREADY exists      → UPDATE last_seen, status, firmware etc.

    This is how new assets get added and existing ones get updated automatically.
    Returns the asset's database ID (integer).
    """
    sql = """
        INSERT INTO assets (
            ip, port, service, device_type, zone,
            vendor, product, firmware, description,
            criticality, packet_count,
            first_seen, last_seen, status
        )
        VALUES (
            %(ip)s, %(port)s, %(service)s, %(device_type)s, %(zone)s,
            %(vendor)s, %(product)s, %(firmware)s, %(description)s,
            %(criticality)s, %(packet_count)s,
            NOW(), NOW(), 'ACTIVE'
        )
        ON CONFLICT (ip, port) DO UPDATE SET
            service      = EXCLUDED.service,
            device_type  = EXCLUDED.device_type,
            zone         = EXCLUDED.zone,
            vendor       = EXCLUDED.vendor,
            product      = EXCLUDED.product,
            firmware     = EXCLUDED.firmware,
            description  = EXCLUDED.description,
            criticality  = EXCLUDED.criticality,
            packet_count = EXCLUDED.packet_count,
            last_seen    = NOW(),
            status       = 'ACTIVE'
        RETURNING id;
    """
    params = {
        "ip":           asset.get("ip", "0.0.0.0"),
        "port":         asset.get("port", 0),
        "service":      asset.get("service"),
        "device_type":  asset.get("device_type"),
        "zone":         asset.get("zone", "OT"),
        "vendor":       asset.get("vendor"),
        "product":      asset.get("product"),
        "firmware":     asset.get("firmware"),
        "description":  asset.get("description"),
        "criticality":  asset.get("criticality", 0.5),
        "packet_count": asset.get("packet_count", 0),
    }
    cur = conn.cursor()
    cur.execute(sql, params)
    return cur.fetchone()[0]


def get_all_assets(conn, status=None):
    """
    Get all assets from the database.
    Pass status='ACTIVE' or status='INACTIVE' to filter.
    Returns a list of dictionaries.
    """
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    if status:
        cur.execute(
            "SELECT * FROM assets WHERE status = %s ORDER BY last_seen DESC;",
            (status,)
        )
    else:
        cur.execute("SELECT * FROM assets ORDER BY last_seen DESC;")
    return [dict(row) for row in cur.fetchall()]


def update_asset_statuses(conn):
    """
    Mark assets ACTIVE or INACTIVE based on last_seen timestamp.
    Called automatically after every ingest cycle.
    Returns number of rows updated.
    """
    sql = """
        UPDATE assets SET status = CASE
            WHEN last_seen >= NOW() - INTERVAL '10 minutes' THEN 'ACTIVE'
            ELSE 'INACTIVE'
        END;
    """
    cur = conn.cursor()
    cur.execute(sql)
    return cur.rowcount


# ─────────────────────────────────────────────────────────────
# VULNERABILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────

def upsert_vulnerability(conn, asset_id, cve):
    """
    Save a CVE to the vulnerabilities table linked to an asset.

    UPSERT means:
    - If this CVE for this asset does NOT exist → INSERT new row
    - If it ALREADY exists → UPDATE scores (risk_score, epss etc.)

    Returns the vulnerability's database ID.
    """
    sql = """
        INSERT INTO vulnerabilities (
            asset_id, cve_id, cvss, epss, kev,
            c_impact, i_impact, a_impact,
            similarity, risk_score, risk_tier,
            discovered_at, updated_at
        )
        VALUES (
            %(asset_id)s, %(cve_id)s, %(cvss)s, %(epss)s, %(kev)s,
            %(c_impact)s, %(i_impact)s, %(a_impact)s,
            %(similarity)s, %(risk_score)s, %(risk_tier)s,
            NOW(), NOW()
        )
        ON CONFLICT (asset_id, cve_id) DO UPDATE SET
            cvss       = EXCLUDED.cvss,
            epss       = EXCLUDED.epss,
            kev        = EXCLUDED.kev,
            c_impact   = EXCLUDED.c_impact,
            i_impact   = EXCLUDED.i_impact,
            a_impact   = EXCLUDED.a_impact,
            similarity = EXCLUDED.similarity,
            risk_score = EXCLUDED.risk_score,
            risk_tier  = EXCLUDED.risk_tier,
            updated_at = NOW()
        RETURNING id;
    """
    params = {
        "asset_id":   asset_id,
        "cve_id":     cve.get("cve_id"),
        "cvss":       float(cve.get("cvss", 0.0)),
        "epss":       float(cve.get("epss", 0.0)),
        "kev":        bool(cve.get("kev", False)),
        "c_impact":   float(cve.get("c_impact", 0.0)),
        "i_impact":   float(cve.get("i_impact", 0.0)),
        "a_impact":   float(cve.get("a_impact", 0.0)),
        "similarity": float(cve.get("similarity", 0.0)),
        "risk_score": float(cve.get("risk_score", 0.0)),
        "risk_tier":  cve.get("risk_tier", "LOW"),
    }
    cur = conn.cursor()
    cur.execute(sql, params)
    return cur.fetchone()[0]


def get_vulnerabilities_for_asset(conn, asset_id):
    """Get all CVEs for a specific asset, sorted by risk score."""
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT * FROM vulnerabilities WHERE asset_id = %s ORDER BY risk_score DESC;",
        (asset_id,)
    )
    return [dict(row) for row in cur.fetchall()]


def get_critical_vulnerabilities(conn, limit=50):
    """Get top CRITICAL and HIGH vulnerabilities across all assets."""
    sql = """
        SELECT
            v.cve_id, v.cvss, v.epss, v.kev,
            v.risk_score, v.risk_tier,
            a.ip, a.port, a.vendor, a.product,
            a.device_type, a.zone, a.status
        FROM vulnerabilities v
        JOIN assets a ON a.id = v.asset_id
        WHERE v.risk_tier IN ('CRITICAL', 'HIGH')
        ORDER BY v.risk_score DESC
        LIMIT %s;
    """
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(sql, (limit,))
    return [dict(row) for row in cur.fetchall()]


# ─────────────────────────────────────────────────────────────
# ALERT FUNCTIONS
# ─────────────────────────────────────────────────────────────

def insert_alert(conn, asset_id, alert, vulnerability_id=None):
    """
    Save a Suricata alert to the alerts table.
    Returns the alert's database ID.
    """
    sql = """
        INSERT INTO alerts (
            asset_id, vulnerability_id,
            alert_signature, alert_category, severity,
            protocol, src_ip, dst_ip, src_port, dst_port,
            is_active_attack, alert_count, raw_event, detected_at
        )
        VALUES (
            %(asset_id)s, %(vulnerability_id)s,
            %(alert_signature)s, %(alert_category)s, %(severity)s,
            %(protocol)s, %(src_ip)s, %(dst_ip)s, %(src_port)s, %(dst_port)s,
            %(is_active_attack)s, %(alert_count)s, %(raw_event)s, NOW()
        )
        RETURNING id;
    """
    params = {
        "asset_id":         asset_id,
        "vulnerability_id": vulnerability_id,
        "alert_signature":  alert.get("alert_signature"),
        "alert_category":   alert.get("alert_category"),
        "severity":         int(alert.get("severity", 3)),
        "protocol":         alert.get("protocol"),
        "src_ip":           alert.get("src_ip"),
        "dst_ip":           alert.get("dst_ip"),
        "src_port":         alert.get("src_port"),
        "dst_port":         alert.get("dst_port"),
        "is_active_attack": bool(alert.get("is_active_attack", False)),
        "alert_count":      int(alert.get("alert_count", 1)),
        "raw_event":        json.dumps(alert.get("raw_event", {})),
    }
    cur = conn.cursor()
    cur.execute(sql, params)
    return cur.fetchone()[0]


# ─────────────────────────────────────────────────────────────
# DASHBOARD SUMMARY
# ─────────────────────────────────────────────────────────────

def get_dashboard_summary(conn):
    """Returns counts of everything for a dashboard."""
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM assets;")
    total_assets = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM assets WHERE status = 'ACTIVE';")
    active_assets = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM vulnerabilities;")
    total_cves = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM vulnerabilities WHERE risk_tier = 'CRITICAL';")
    critical_cves = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM vulnerabilities WHERE risk_tier = 'HIGH';")
    high_cves = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM vulnerabilities WHERE kev = TRUE;")
    kev_cves = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM alerts;")
    total_alerts = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM alerts WHERE is_active_attack = TRUE;")
    active_attacks = cur.fetchone()[0]

    return {
        "total_assets":   total_assets,
        "active_assets":  active_assets,
        "total_cves":     total_cves,
        "critical_cves":  critical_cves,
        "high_cves":      high_cves,
        "kev_cves":       kev_cves,
        "total_alerts":   total_alerts,
        "active_attacks": active_attacks,
        "generated_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ─────────────────────────────────────────────────────────────
# BULK LOAD — used by db_ingestor.py
# ─────────────────────────────────────────────────────────────

def load_devices_into_db(devices):
    """
    Takes a list of device dicts and saves all assets + CVEs to the database.
    Returns stats dict with counts of what was saved.
    """
    stats = {"assets_saved": 0, "cves_saved": 0, "errors": []}

    conn = get_connection()
    try:
        for device in devices:
            try:
                asset_id = upsert_asset(conn, device)
                stats["assets_saved"] += 1
                for cve in device.get("cves", []):
                    upsert_vulnerability(conn, asset_id, cve)
                    stats["cves_saved"] += 1
            except Exception as e:
                stats["errors"].append(
                    f"{device.get('ip')}:{device.get('port')} - {str(e)}"
                )

        update_asset_statuses(conn)
        conn.commit()

    except Exception as e:
        conn.rollback()
        stats["errors"].append(f"Transaction error: {str(e)}")
    finally:
        conn.close()

    return stats


# ─────────────────────────────────────────────────────────────
# RUN DIRECTLY TO TEST CONNECTION
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print("CAVE-OT DB MANAGER — Connection Test")
    print("=" * 50)
    print("\nTesting connection...")
    if test_connection():
        conn = get_connection()
        s = get_dashboard_summary(conn)
        conn.close()
        print("\nDatabase Summary:")
        for key, val in s.items():
            print(f"  {key:<20}: {val}")
