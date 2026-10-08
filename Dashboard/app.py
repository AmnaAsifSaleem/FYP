import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pipeline_paths import DB_CONFIG
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
from request_connection import close_connections
app.teardown_appcontext(close_connections)

# ── DB Config ─────────────────────────────────────────────────


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_conn():
    from request_connection import connect
    return connect(DB_CONFIG)


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
    except ValueError as e:
        return jsonify(error=str(e)),422
    except psycopg2.Error:
        return jsonify(error='Database unavailable; previous results preserved'),503
    except Exception:
        return jsonify(error='Unable to complete request'),500


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
    except ValueError as e:
        return jsonify(error=str(e)),422
    except psycopg2.Error:
        return jsonify(error='Database unavailable; previous results preserved'),503
    except Exception:
        return jsonify(error='Unable to complete request'),500


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

        cur.execute("SELECT COUNT(*) FROM assets WHERE status = 'ACTIVE' AND last_seen >= NOW()-INTERVAL '3 minutes';")
        active_assets = cur.fetchone()[0]
        monitoring_running=_scan_running()
        if not monitoring_running:active_assets=0

        # Show saved candidate/confirmed findings in both live and historical mode.
        # Device availability is represented separately, without discarding history.
        cur.execute("""
            SELECT COUNT(*) FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id WHERE v.applicability IN ('CONFIRMED','POTENTIAL');
        """)
        total_cves = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            WHERE v.applicability IN ('CONFIRMED','POTENTIAL') AND v.risk_tier = 'CRITICAL';
        """)
        critical_cves = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            WHERE v.applicability IN ('CONFIRMED','POTENTIAL') AND v.risk_tier = 'HIGH';
        """)
        high_cves = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            WHERE v.applicability IN ('CONFIRMED','POTENTIAL') AND v.risk_tier = 'MEDIUM';
        """)
        medium_cves = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            WHERE v.applicability IN ('CONFIRMED','POTENTIAL') AND v.risk_tier = 'LOW';
        """)
        low_cves = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*) FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            WHERE v.applicability IN ('CONFIRMED','POTENTIAL') AND v.kev = TRUE;
        """)
        kev_cves = cur.fetchone()[0]

        cur.execute("""
            SELECT v.cve_id, v.risk_score, a.vendor, a.product, a.ip, a.device_type
            FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            WHERE v.applicability IN ('CONFIRMED','POTENTIAL') AND v.kev = TRUE
            ORDER BY v.risk_score DESC
            LIMIT 5;
        """)
        kev_details = [
            {"cve_id": r[0], "risk_score": r[1], "vendor": r[2], "product": r[3],
             "ip": r[4], "device_type": r[5]}
            for r in cur.fetchall()
        ]

        cur.execute("""
            SELECT COALESCE(SUM(al.alert_count), 0) FROM alerts al
            JOIN assets a ON a.id = al.asset_id WHERE TRUE;
        """)
        total_alerts = int(cur.fetchone()[0])

        cur.execute("""
            SELECT COALESCE(SUM(al.alert_count), 0) FROM alerts al
            JOIN assets a ON a.id = al.asset_id
            WHERE al.is_active_attack = TRUE;
        """)
        active_attacks = int(cur.fetchone()[0])

        cur.execute("""
            SELECT COUNT(*) FROM assets a
            WHERE a.is_anomalous = TRUE;
        """)
        anomalous_assets = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM vulnerabilities WHERE applicability='CONFIRMED';")
        confirmed_cves = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM vulnerabilities WHERE applicability='POTENTIAL';")
        potential_cves = cur.fetchone()[0]
        cur.execute("SELECT COUNT(DISTINCT al.asset_id) FROM alerts al JOIN assets a ON a.id=al.asset_id WHERE al.alert_count>0;")
        affected_assets = cur.fetchone()[0]
        conn.close()
        return jsonify({
            "monitoring_running":monitoring_running,
            "data_mode":"LIVE" if monitoring_running else "HISTORICAL",
            "total_assets":   total_assets,
            "active_assets":  active_assets,
            "inactive_assets": total_assets - active_assets if monitoring_running else 0,
            "not_monitored_assets":0 if monitoring_running else total_assets,
            "total_cves": total_cves, "confirmed_cves": confirmed_cves, "potential_cves": potential_cves,
            "critical_cves":  critical_cves,
            "high_cves":      high_cves,
            "medium_cves":    medium_cves,
            "low_cves":       low_cves,
            "kev_cves":       kev_cves,
            "kev_details":    kev_details,
            "total_alerts":   total_alerts,
            "affected_assets": affected_assets,
            "active_attacks": active_attacks,
            "anomalous_assets": anomalous_assets,
        })
    except ValueError as e:
        return jsonify(error=str(e)),422
    except psycopg2.Error:
        return jsonify(error='Database unavailable; previous results preserved'),503
    except Exception:
        return jsonify(error='Unable to complete request'),500


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
                a.*, (a.last_seen >= NOW()-INTERVAL '3 minutes') AS observed_recently,
                COUNT(v.id) AS total_cves,
                COUNT(CASE WHEN v.risk_tier = 'CRITICAL' THEN 1 END) AS critical_cves,
                COUNT(CASE WHEN v.risk_tier = 'HIGH' THEN 1 END) AS high_cves,
                MAX(v.risk_score) AS max_risk_score
            FROM assets a
            LEFT JOIN vulnerabilities v ON v.asset_id = a.id
            GROUP BY a.id
            ORDER BY max_risk_score DESC NULLS LAST;
        """)
        from monitoring_view import asset_view
        running=_scan_running()
        rows = [asset_view(r,running) for r in cur.fetchall()]
        conn.close()
        # Convert datetime to string
        for r in rows:
            for k in ['first_seen', 'last_seen']:
                if r.get(k):
                    r[k] = r[k].strftime('%Y-%m-%d %H:%M:%S')
        return jsonify(rows)
    except ValueError as e:
        return jsonify(error=str(e)),422
    except psycopg2.Error:
        return jsonify(error='Database unavailable; previous results preserved'),503
    except Exception:
        return jsonify(error='Unable to complete request'),500


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
    except ValueError as e:
        return jsonify(error=str(e)),422
    except psycopg2.Error:
        return jsonify(error='Database unavailable; previous results preserved'),503
    except Exception:
        return jsonify(error='Unable to complete request'),500


# ─────────────────────────────────────────────────────────────
# API — VULNERABILITIES
# ─────────────────────────────────────────────────────────────

@app.route('/api/vulnerabilities')
def api_vulnerabilities():
    try:
        tier   = request.args.get('tier', '')
        try: limit=int(request.args.get('limit',200))
        except ValueError:return jsonify(error='limit must be an integer'),422
        if not 1<=limit<=1000:return jsonify(error='limit must be between 1 and 1000'),422
        if tier and tier not in ('LOW','MEDIUM','HIGH','CRITICAL'):return jsonify(error='Invalid risk tier'),422
        conn = get_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        where = "WHERE v.risk_tier = %s" if tier else ""
        params = (tier, limit) if tier else (limit,)

        cur.execute(f"""
            SELECT
                v.id, v.cve_id, v.cvss, v.epss, v.kev,
                v.risk_score, v.risk_tier, v.applicability, v.applicability_evidence, v.score_version,
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
    except ValueError as e:
        return jsonify(error=str(e)),422
    except psycopg2.Error:
        return jsonify(error='Database unavailable; previous results preserved'),503
    except Exception:
        return jsonify(error='Unable to complete request'),500


# ─────────────────────────────────────────────────────────────
# API — ALERTS
# ─────────────────────────────────────────────────────────────

@app.route('/api/alerts')
def api_alerts():
    try:
        conn = get_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT al.*, a.ip, a.port AS asset_port, a.vendor, a.product, a.zone
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
    except ValueError as e:
        return jsonify(error=str(e)),422
    except psycopg2.Error:
        return jsonify(error='Database unavailable; previous results preserved'),503
    except Exception:
        return jsonify(error='Unable to complete request'),500


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
            LEFT JOIN vulnerabilities v ON v.asset_id = a.id AND v.applicability IN ('CONFIRMED','POTENTIAL')
            WHERE TRUE
            GROUP BY a.id, a.vendor, a.product
            ORDER BY total DESC;
        """)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify(rows)
    except ValueError as e:
        return jsonify(error=str(e)),422
    except psycopg2.Error:
        return jsonify(error='Database unavailable; previous results preserved'),503
    except Exception:
        return jsonify(error='Unable to complete request'),500


@app.route('/api/charts/risk_distribution')
def chart_risk_distribution():
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
            SELECT v.risk_tier, COUNT(*) as count
            FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            WHERE v.applicability IN ('CONFIRMED','POTENTIAL')
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
    except ValueError as e:
        return jsonify(error=str(e)),422
    except psycopg2.Error:
        return jsonify(error='Database unavailable; previous results preserved'),503
    except Exception:
        return jsonify(error='Unable to complete request'),500


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
            WHERE v.applicability IN ('CONFIRMED','POTENTIAL')
            GROUP BY range
            ORDER BY MIN(v.cvss) DESC;
        """)
        rows = cur.fetchall()
        conn.close()
        return jsonify([{"range": r[0], "count": r[1]} for r in rows])
    except ValueError as e:
        return jsonify(error=str(e)),422
    except psycopg2.Error:
        return jsonify(error='Database unavailable; previous results preserved'),503
    except Exception:
        return jsonify(error='Unable to complete request'),500


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
            LEFT JOIN vulnerabilities v ON v.asset_id = a.id AND v.applicability IN ('CONFIRMED','POTENTIAL')
            WHERE TRUE
            GROUP BY a.zone;
        """)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify(rows)
    except ValueError as e:
        return jsonify(error=str(e)),422
    except psycopg2.Error:
        return jsonify(error='Database unavailable; previous results preserved'),503
    except Exception:
        return jsonify(error='Unable to complete request'),500


# ─────────────────────────────────────────────────────────────
# API — PIPELINE TRIGGER (Docker passive-scan control)
# ─────────────────────────────────────────────────────────────

DOCKER_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docker")


def _scan_running():
    from monitoring_view import scan_running
    return scan_running()


def _docker_daemon_ready():
    """True if the Docker daemon is reachable (Docker Desktop fully started, not just launched)."""
    try:
        result = subprocess.run(__import__("docker_backend").command("info"), capture_output=True, timeout=10)
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
    """Start the configured backend and raise actionable failures to the controller."""
    from docker_backend import settings, prepare, command
    if not _docker_daemon_ready():
        if settings()[0] == "wsl":
            prepare()
        else:
            exe = _find_docker_desktop_exe()
            if not exe:
                raise RuntimeError('Docker is unavailable. Start your configured container engine and retry.')
            subprocess.Popen([exe], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 150
        while not _docker_daemon_ready():
            if time.monotonic() >= deadline:
                raise RuntimeError('Container engine did not become ready. Check Docker/WSL and retry.')
            time.sleep(3)
    result = subprocess.run(command('compose', 'up', '-d', '--build'), cwd=DOCKER_DIR,
                            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=900)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or 'Container startup failed')[-2000:])
    # Invalidate the short status cache after changing container state.
    import monitoring_view
    monitoring_view._expires = 0
    if not _scan_running():
        raise RuntimeError('Monitoring container exited during startup. Check engine logs and retry.')


_scan_lock = threading.Lock()
_scan_operation = {'state': 'IDLE', 'message': '', 'error': None}


def _scan_worker(action):
    try:
        if action == 'start':
            _ensure_docker_desktop_and_start()
        else:
            from docker_backend import command, release_keeper
            result = subprocess.run(command('compose', 'down'), cwd=DOCKER_DIR,
                                    capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
            if result.returncode:
                raise RuntimeError((result.stderr or result.stdout or 'Container shutdown failed')[-2000:])
            release_keeper()
        import monitoring_view
        monitoring_view._expires = 0
        with _scan_lock:
            _scan_operation.update(state='IDLE', message='Monitoring started.' if action == 'start' else 'Monitoring stopped.', error=None)
    except Exception as exc:
        message = str(exc) or type(exc).__name__
        print('[scan] ' + action + ' failed: ' + message)
        with _scan_lock:
            _scan_operation.update(state='FAILED', message=message, error=message)


@app.route('/api/scan/status')
def api_scan_status():
    with _scan_lock:
        operation = dict(_scan_operation)
    running = _scan_running()
    if operation['state'] == 'IDLE':
        operation['state'] = 'RUNNING' if running else 'STOPPED'
    return jsonify(running=running, busy=operation['state'] in ('STARTING', 'STOPPING'), **operation)


def _request_scan_action(action):
    with _scan_lock:
        if _scan_operation['state'] in ('STARTING', 'STOPPING'):
            return jsonify(success=False, message='A monitoring operation is already in progress.'), 409
        _scan_operation.update(state='STARTING' if action == 'start' else 'STOPPING', error=None,
                               message='Building and starting monitoring...' if action == 'start' else 'Stopping monitoring...')
    try:
        threading.Thread(target=_scan_worker, args=(action,), daemon=True).start()
    except Exception as exc:
        with _scan_lock:
            _scan_operation.update(state='FAILED', error=str(exc), message=str(exc))
        return jsonify(success=False, message=str(exc)), 500
    return jsonify(success=True, message='Monitoring operation accepted.'), 202


@app.route('/api/scan/start', methods=['POST'])
def api_scan_start():
    return _request_scan_action('start')


@app.route('/api/scan/stop', methods=['POST'])
def api_scan_stop():
    return _request_scan_action('stop')


# ─────────────────────────────────────────────────────────────
# API — PIPELINE (DB sync trigger)
# ─────────────────────────────────────────────────────────────

@app.route('/api/pipeline/run', methods=['POST'])
def api_pipeline_run():
    """Trigger sync_db.py and return its output line by line."""
    try:
        sync_script = os.path.join(BASE_DIR, "Database", "sync_db.py")
        if not os.path.exists(sync_script):
            return jsonify({"success": False, "output": ["ERROR: sync_db.py not found"]}), 500

        result = subprocess.run(
            [sys.executable, sync_script],
            capture_output=True, text=True, timeout=120,
            cwd=BASE_DIR
        )

        lines = []
        if result.stdout:
            lines += result.stdout.splitlines()
        if result.stderr:
            lines += [f"[stderr] {l}" for l in result.stderr.splitlines() if l.strip()]

        success = result.returncode == 0
        return jsonify({"success": success, "output": lines, "returncode": result.returncode})

    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "output": ["ERROR: sync timed out after 120s"]}), 500
    except Exception as e:
        return jsonify({"success": False, "output": [f"ERROR: {str(e)}"]}), 500

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

def _start_automated_background_services():
    """
    Background services started on Dashboard launch:
    1. Runs initial sync_db.py to ingest existing JSON files into PostgreSQL immediately.
    2. Launches file_watcher.py in background so any new/modified JSON files are auto-synced to DB.

    NOTE: Docker is NOT started automatically. Use the "Start Passive Scan" button
    on the dashboard to start the Docker container stack manually.
    """
    # Versioned evidence migration runs before any ingest.
    migration=subprocess.run([sys.executable,os.path.join(BASE_DIR,'Database','migrate_audit_fixes.py')],capture_output=True,text=True)
    if migration.returncode:
        print('Database migration failed: '+migration.stderr)
        return
    # 1. Initial DB sync
    try:
        sync_script = os.path.join(BASE_DIR, "Database", "sync_db.py")
        print("  [Auto-Start] Running initial Database sync...")
        subprocess.run([sys.executable, sync_script], capture_output=True, text=True)
        print("✓ [Auto-Start] Initial Database sync attempted; watcher retries until a complete snapshot is available")
    except Exception as e:
        print(f"⚠ [Auto-Start] Initial DB sync warning: {e}")

    # 1b. Ensure remediation tables exist (idempotent — safe to run every time)
    try:
        remediation_setup = os.path.join(BASE_DIR, "Database", "db_remediation_setup.py")
        if os.path.exists(remediation_setup):
            subprocess.run([sys.executable, remediation_setup], capture_output=True, text=True)
            print("✓ [Auto-Start] Remediation tables verified")
    except Exception as e:
        print(f"⚠ [Auto-Start] Remediation table setup warning: {e}")

    # 2. Launch file_watcher.py in background if not already running
    try:
        file_watcher_script = os.path.join(BASE_DIR, "file_watcher.py")
        if os.path.exists(file_watcher_script):
            subprocess.Popen(
                [sys.executable, file_watcher_script],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            print("✓ [Auto-Start] File Watcher background process active")
    except Exception as e:
        print(f"⚠ [Auto-Start] Could not launch File Watcher: {e}")

    print("  [Auto-Start] Docker not started — press 'Start Passive Scan' on the dashboard to begin scanning.")


if __name__ == '__main__':
    print("=" * 55)
    print("  CAVE-OT Dashboard")
    print("  http://localhost:5000")
    print("=" * 55)

    # Avoid duplicate background thread spawning when Werkzeug reloader is active
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
        _start_automated_background_services()

    app.run(debug=False, host=os.environ.get("CAVE_OT_BIND","127.0.0.1"), port=5000)
