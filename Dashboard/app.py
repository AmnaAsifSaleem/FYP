"""
CAVE-OT Dashboard — Flask Application
======================================
Run with: python Dashboard/app.py
Then open: http://localhost:5000
"""

import sys
import os
import subprocess
import json
import threading
import time

# Windows consoles default to cp1252, which can't encode the checkmark/warning
# characters used in a few startup print() calls (e.g. policy_api.py's
# "✓ Policy compliance API registered") — that raised UnicodeEncodeError
# and killed the whole app before it ever bound to a port. Force UTF-8 stdout.
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Allow importing from Database/ folder
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'Database'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'Policy_Compliance'))

from flask import Flask, render_template, jsonify, request
import psycopg2
import psycopg2.extras

app = Flask(__name__)

# ── DB Config ─────────────────────────────────────────────────
DB_CONFIG = {
    "host":     "localhost",
    "port":     5432,
    "dbname":   "cave_ot",
    "user":     "postgres",
    "password": "admin"
}

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_conn():
    return psycopg2.connect(**DB_CONFIG)


# ─────────────────────────────────────────────────────────────
# PAGE ROUTES
# ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/assets')
def assets_page():
    return render_template('assets.html')


@app.route('/vulnerabilities')
def vulnerabilities_page():
    return render_template('vulnerabilities.html')


@app.route('/alerts')
def alerts_page():
    return render_template('alerts.html')


@app.route('/policy')
def policy_page():
    return render_template('policy.html')


@app.route('/attack_paths')
def attack_paths_page():
    return render_template('attack_paths.html')


@app.route('/remediation')
def remediation_page():
    return render_template('remediation.html')


# ─────────────────────────────────────────────────────────────
# API — ATTACK PATHS
# ─────────────────────────────────────────────────────────────

@app.route('/api/attack_paths')
def api_attack_paths():
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT entry_asset, target_asset, hops, cost, max_risk_on_path,
                   path_json, computed_at
            FROM attack_paths
            ORDER BY cost ASC;
        """)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        for r in rows:
            if r.get('computed_at'):
                r['computed_at'] = r['computed_at'].isoformat()
        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/attack_path_nodes')
def api_attack_path_nodes():
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT device_name, zone, criticality, vendor, product,
                   risk_score, is_attacked,
                   top_cve_id, top_cve_cvss, top_cve_tier, top_cve_desc,
                   updated_at
            FROM attack_path_nodes;
        """)
        rows = {r['device_name']: dict(r) for r in cur.fetchall()}
        conn.close()
        for r in rows.values():
            del r['device_name']
            if r.get('updated_at'):
                r['updated_at'] = r['updated_at'].isoformat()
        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────
# API — DASHBOARD SUMMARY
# ─────────────────────────────────────────────────────────────

@app.route('/api/summary')
def api_summary():
    try:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM assets;")
        total_assets = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM assets WHERE status = 'ACTIVE';")
        active_assets = cur.fetchone()[0]

        # CVE/alert totals only count vulnerabilities and alerts belonging to
        # currently ACTIVE assets — an asset that's gone quiet shouldn't keep
        # inflating the headline numbers with stale findings.
        cur.execute("""
            SELECT COUNT(*) FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id WHERE a.status = 'ACTIVE';
        """)
        total_cves = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            WHERE a.status = 'ACTIVE' AND v.risk_tier = 'CRITICAL';
        """)
        critical_cves = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            WHERE a.status = 'ACTIVE' AND v.risk_tier = 'HIGH';
        """)
        high_cves = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            WHERE a.status = 'ACTIVE' AND v.risk_tier = 'MEDIUM';
        """)
        medium_cves = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            WHERE a.status = 'ACTIVE' AND v.risk_tier = 'LOW';
        """)
        low_cves = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            WHERE a.status = 'ACTIVE' AND v.kev = TRUE;
        """)
        kev_cves = cur.fetchone()[0]

        cur.execute("""
            SELECT v.cve_id, v.risk_score, a.vendor, a.product, a.ip, a.device_type
            FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            WHERE a.status = 'ACTIVE' AND v.kev = TRUE
            ORDER BY v.risk_score DESC
            LIMIT 5;
        """)
        kev_details = [
            {"cve_id": r[0], "risk_score": r[1], "vendor": r[2], "product": r[3],
             "ip": r[4], "device_type": r[5]}
            for r in cur.fetchall()
        ]

        cur.execute("""
            SELECT COUNT(*) FROM alerts al
            JOIN assets a ON a.id = al.asset_id WHERE a.status = 'ACTIVE';
        """)
        total_alerts = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM alerts al
            JOIN assets a ON a.id = al.asset_id
            WHERE a.status = 'ACTIVE' AND al.is_active_attack = TRUE;
        """)
        active_attacks = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM assets a
            WHERE a.status = 'ACTIVE' AND a.is_anomalous = TRUE;
        """)
        anomalous_assets = cur.fetchone()[0]

        conn.close()
        return jsonify({
            "total_assets":   total_assets,
            "active_assets":  active_assets,
            "inactive_assets": total_assets - active_assets,
            "total_cves":     total_cves,
            "critical_cves":  critical_cves,
            "high_cves":      high_cves,
            "medium_cves":    medium_cves,
            "low_cves":       low_cves,
            "kev_cves":       kev_cves,
            "kev_details":    kev_details,
            "total_alerts":   total_alerts,
            "active_attacks": active_attacks,
            "anomalous_assets": anomalous_assets,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────
# API — ASSETS
# ─────────────────────────────────────────────────────────────

@app.route('/api/assets')
def api_assets():
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT
                a.*,
                COUNT(v.id) AS total_cves,
                COUNT(CASE WHEN v.risk_tier = 'CRITICAL' THEN 1 END) AS critical_cves,
                COUNT(CASE WHEN v.risk_tier = 'HIGH' THEN 1 END) AS high_cves,
                MAX(v.risk_score) AS max_risk_score
            FROM assets a
            LEFT JOIN vulnerabilities v ON v.asset_id = a.id
            GROUP BY a.id
            ORDER BY max_risk_score DESC NULLS LAST;
        """)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        # Convert datetime to string
        for r in rows:
            for k in ['first_seen', 'last_seen']:
                if r.get(k):
                    r[k] = r[k].strftime('%Y-%m-%d %H:%M:%S')
        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/assets/<int:asset_id>/cves')
def api_asset_cves(asset_id):
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT v.*, a.vendor, a.product, a.ip
            FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            WHERE v.asset_id = %s
            ORDER BY v.risk_score DESC;
        """, (asset_id,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        for r in rows:
            for k in ['discovered_at', 'updated_at']:
                if r.get(k):
                    r[k] = r[k].strftime('%Y-%m-%d %H:%M:%S')
        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────
# API — VULNERABILITIES
# ─────────────────────────────────────────────────────────────

@app.route('/api/vulnerabilities')
def api_vulnerabilities():
    try:
        tier   = request.args.get('tier', '')
        limit  = int(request.args.get('limit', 200))
        conn = get_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        where = "WHERE v.risk_tier = %s" if tier else ""
        params = (tier, limit) if tier else (limit,)

        cur.execute(f"""
            SELECT
                v.id, v.cve_id, v.cvss, v.epss, v.kev,
                v.risk_score, v.risk_tier,
                v.c_impact, v.i_impact, v.a_impact,
                v.discovered_at,
                a.ip, a.port, a.vendor, a.product,
                a.device_type, a.zone, a.status AS asset_status,
                a.criticality
            FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            {where}
            ORDER BY v.risk_score DESC
            LIMIT %s;
        """, params)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        for r in rows:
            if r.get('discovered_at'):
                r['discovered_at'] = r['discovered_at'].strftime('%Y-%m-%d %H:%M:%S')
            r['kev'] = bool(r['kev'])
        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────
# API — ALERTS
# ─────────────────────────────────────────────────────────────

@app.route('/api/alerts')
def api_alerts():
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT al.*, a.ip, a.vendor, a.product, a.zone
            FROM alerts al
            JOIN assets a ON a.id = al.asset_id
            ORDER BY al.detected_at DESC
            LIMIT 100;
        """)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        for r in rows:
            if r.get('detected_at'):
                r['detected_at'] = r['detected_at'].strftime('%Y-%m-%d %H:%M:%S')
        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────
# API — CHART DATA
# ─────────────────────────────────────────────────────────────

@app.route('/api/charts/cves_per_device')
def chart_cves_per_device():
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT
                a.vendor || ' ' || a.product AS device,
                COUNT(v.id) AS total,
                COUNT(CASE WHEN v.risk_tier = 'CRITICAL' THEN 1 END) AS critical,
                COUNT(CASE WHEN v.risk_tier = 'HIGH' THEN 1 END) AS high,
                COUNT(CASE WHEN v.risk_tier = 'MEDIUM' THEN 1 END) AS medium,
                COUNT(CASE WHEN v.risk_tier = 'LOW' THEN 1 END) AS low
            FROM assets a
            LEFT JOIN vulnerabilities v ON v.asset_id = a.id
            WHERE a.status = 'ACTIVE'
            GROUP BY a.id, a.vendor, a.product
            ORDER BY total DESC;
        """)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/charts/risk_distribution')
def chart_risk_distribution():
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
            SELECT v.risk_tier, COUNT(*) as count
            FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            WHERE a.status = 'ACTIVE'
            GROUP BY v.risk_tier
            ORDER BY CASE v.risk_tier
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
            END;
        """)
        rows = cur.fetchall()
        conn.close()
        return jsonify([{"tier": r[0], "count": r[1]} for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/charts/cvss_distribution')
def chart_cvss_distribution():
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
            SELECT
                CASE
                    WHEN v.cvss >= 9.0 THEN '9-10 Critical'
                    WHEN v.cvss >= 7.0 THEN '7-9 High'
                    WHEN v.cvss >= 4.0 THEN '4-7 Medium'
                    ELSE '0-4 Low'
                END AS range,
                COUNT(*) AS count
            FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            WHERE a.status = 'ACTIVE'
            GROUP BY range
            ORDER BY MIN(v.cvss) DESC;
        """)
        rows = cur.fetchall()
        conn.close()
        return jsonify([{"range": r[0], "count": r[1]} for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/charts/zone_risk')
def chart_zone_risk():
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT
                a.zone,
                COUNT(v.id) AS total_cves,
                ROUND(AVG(v.risk_score)::numeric, 2) AS avg_risk,
                COUNT(CASE WHEN v.risk_tier = 'CRITICAL' THEN 1 END) AS critical
            FROM assets a
            LEFT JOIN vulnerabilities v ON v.asset_id = a.id
            WHERE a.status = 'ACTIVE'
            GROUP BY a.zone;
        """)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────
# API — PIPELINE TRIGGER (Docker passive-scan control)
# ─────────────────────────────────────────────────────────────

DOCKER_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docker")


def _scan_running():
    """True if the caveot-engine container is currently Up."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=caveot-engine",
             "--filter", "status=running", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10
        )
        return "caveot-engine" in result.stdout
    except Exception:
        return False


def _docker_daemon_ready():
    """True if the Docker daemon is reachable (Docker Desktop fully started, not just launched)."""
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
        return result.returncode == 0
    except Exception:
        return False


def _find_docker_desktop_exe():
    for path in (
        os.path.expandvars(r"%ProgramFiles%\Docker\Docker\Docker Desktop.exe"),
        os.path.expandvars(r"%LocalAppData%\Docker\Docker Desktop.exe"),
        r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
    ):
        if os.path.isfile(path):
            return path
    return None


def _ensure_docker_desktop_and_start():
    """
    Background-thread target for /api/scan/start. `docker compose up` fails
    outright (no retry) if the daemon isn't reachable yet, so a plain Popen
    call at click-time silently no-ops whenever Docker Desktop isn't already
    running — the user has to notice, open it themselves, and click again.
    This launches Docker Desktop if needed and waits for the daemon to
    actually answer before running compose, so one click is enough either way.
    """
    if not _docker_daemon_ready():
        exe = _find_docker_desktop_exe()
        if exe:
            try:
                subprocess.Popen([exe], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        # Docker Desktop cold start is commonly 30-90s (see docker/README.md
        # troubleshooting section) — poll rather than fixed-sleep.
        deadline = time.time() + 150
        while time.time() < deadline:
            if _docker_daemon_ready():
                break
            time.sleep(3)
        else:
            return  # daemon never came up — nothing more to do here
    subprocess.Popen(
        ["docker", "compose", "up", "-d", "--build"],
        cwd=DOCKER_DIR,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )


@app.route('/api/scan/status')
def api_scan_status():
    return jsonify({"running": _scan_running()})


@app.route('/api/scan/start', methods=['POST'])
def api_scan_start():
    if _scan_running():
        return jsonify({"success": True, "message": "Already running"})
    try:
        daemon_was_ready = _docker_daemon_ready()
        threading.Thread(target=_ensure_docker_desktop_and_start, daemon=True).start()
        if daemon_was_ready:
            return jsonify({"success": True, "message": "Starting passive scan..."})
        return jsonify({
            "success": True,
            "message": "Docker Desktop isn't running — launching it, then starting the scan "
                        "(can take up to ~2 minutes on a cold start)"
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/scan/stop', methods=['POST'])
def api_scan_stop():
    try:
        subprocess.Popen(
            ["docker", "compose", "down"],
            cwd=DOCKER_DIR,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return jsonify({"success": True, "message": "Stopping passive scan..."})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# ─────────────────────────────────────────────────────────────
# POLICY COMPLIANCE API REGISTRATION
# ─────────────────────────────────────────────────────────────

try:
    from policy_api import register_policy_api
    register_policy_api(app)
    print("✓ Policy compliance API registered")
except ImportError as e:
    print(f"⚠ Policy API not available: {e}")
except Exception as e:
    print(f"⚠ Failed to register policy API: {e}")

# ─────────────────────────────────────────────────────────────
# REMEDIATION ADVISOR API REGISTRATION
# ─────────────────────────────────────────────────────────────

try:
    from remediation_api import register_remediation_api
    register_remediation_api(app)
    print("✓ Remediation advisor API registered")
except ImportError as e:
    print(f"⚠ Remediation advisor API not available: {e}")
except Exception as e:
    print(f"⚠ Failed to register remediation advisor API: {e}")

if __name__ == '__main__':
    print("=" * 55)
    print("  CAVE-OT Dashboard")
    print("  http://localhost:5000")
    print("=" * 55)

    # On startup, mark all assets INACTIVE and clear runtime alerts so the
    # dashboard reflects reality when the VM pipeline is not running.
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("TRUNCATE alerts RESTART IDENTITY;")
        cur.execute("UPDATE assets SET status = 'INACTIVE';")
        conn.commit()
        conn.close()
        print("  Assets reset to INACTIVE, alerts cleared (will update when VM syncs)")
    except Exception as e:
        print(f"  Could not reset on startup: {e}")

    app.run(debug=True, host='0.0.0.0', port=5000)
