import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pipeline_paths import DB_CONFIG
"""
Remediation Advisor API Extension for CAVE-OT Dashboard
Adds LLM remediation + policy gatekeeper endpoints to the Flask app.

Every recommendation is generated strictly on-demand (a human clicks
Generate) and cached per (asset_id, cve_id) — nothing here calls the LLM
automatically or on a schedule. Nothing here ever changes device state;
the only writes are Postgres rows an analyst can Approve/Reject/Defer.
"""

import sys
import os
import json
import threading

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'Policy_Compliance'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'Remediation'))

from flask import Blueprint, jsonify, request
import psycopg2
import psycopg2.extras
import policy_gatekeeper
import remediation_advisor

# Lazy-load the predictor — same pattern as policy_api.py so a missing model
# doesn't prevent remediation routes from registering at all.
_predictor_instance = None
_predictor_error = None

def _get_predictor():
    global _predictor_instance, _predictor_error
    if _predictor_instance is not None:
        return _predictor_instance, None
    if _predictor_error is not None:
        return None, _predictor_error
    try:
        from policy_predictor import PolicyCompliancePredictor
        _predictor_instance = PolicyCompliancePredictor()
        return _predictor_instance, None
    except Exception as e:
        _predictor_error = str(e)
        return None, _predictor_error

remediation_bp = Blueprint('remediation', __name__, url_prefix='/api/remediation')




def get_db_connection():
    from request_connection import connect
    return connect(DB_CONFIG)


# ── Bulk-generation progress state (in-memory — mirrors the docker-scan
# status-poll pattern already used by /api/scan/status) ────────────────────
_gen_lock = threading.Lock()
_gen_state = {"running": False, "total": 0, "completed": 0, "current_asset": None, "errors": []}


def _asset_dict(row):
    return {
        "device_type": row["device_type"], "vendor": row["vendor"], "product": row["product"],
        "firmware": row.get("firmware"), "zone": row["zone"], "criticality": row["criticality"],
        "service": row["service"], "port": row.get("port"),
        "encrypted":row.get("encrypted"),"days_since_patch":row.get("days_since_patch"),"firmware_eol":row.get("firmware_eol"),
    }


def _cve_dict(row, description):
    return {
        "cve_id": row["cve_id"], "cvss": row["cvss"], "epss": row["epss"], "kev": row["kev"],
        "risk_score": row["risk_score"], "risk_tier": row["risk_tier"], "description": description,
    }


def _attack_path_info(cur, device_type):
    cur.execute("""
        SELECT entry_asset, hops, cost FROM attack_paths
        WHERE target_asset = %s ORDER BY cost ASC LIMIT 1;
    """, (device_type,))
    row = cur.fetchone()
    if not row:
        return None
    return {"entry": row["entry_asset"], "hops": row["hops"], "cost": row["cost"], "is_target": True}


def _policy_context(cur, asset_id):
    cur.execute("""
        SELECT compliance_status, compliance_score, explanation
        FROM policy_compliance WHERE asset_id = %s;
    """, (asset_id,))
    row = cur.fetchone()
    if not row:
        return None, None
    ml_signal = None
    context_str = f"{row['compliance_status']} (rule pass fraction {row['compliance_score']:.2f}) — {row['explanation']}"
    return context_str, ml_signal


def _generate_one(cur, conn, asset_id, cve_id, force=False):
    """Generate (or return cached) recommendation for one (asset, cve) pair.
    Returns the full remediation_recommendations row as a dict."""
    cur.execute("SELECT * FROM assets WHERE id = %s;", (asset_id,))
    asset_row = cur.fetchone()
    if not asset_row:
        raise ValueError(f"Asset {asset_id} not found")

    cur.execute("SELECT * FROM vulnerabilities WHERE asset_id = %s AND cve_id = %s;", (asset_id, cve_id))
    vuln_row = cur.fetchone()
    if not vuln_row:
        raise ValueError(f"No vulnerability row for asset {asset_id} / {cve_id}")

    if vuln_row.get('applicability')!='CONFIRMED':raise ValueError('Confirm CVE applicability before requesting remediation')
    description=remediation_advisor.get_cve_description(cve_id)
    asset=_asset_dict(asset_row);cve=_cve_dict(vuln_row,description)
    attack_path_info=_attack_path_info(cur,asset_row['device_type'])
    policy_context,ml_signal=_policy_context(cur,asset_id)
    policy_rules=policy_gatekeeper.load_active_rules(cur)
    import hashlib
    fingerprint=hashlib.sha256(json.dumps({'asset':asset,'cve':cve,'path':attack_path_info,'policy':policy_context,'rules':policy_rules},sort_keys=True,default=str).encode()).hexdigest()
    if not force:
        cur.execute('SELECT * FROM remediation_recommendations WHERE asset_id=%s AND cve_id=%s AND context_fingerprint=%s',(asset_id,cve_id,fingerprint))
        cached=cur.fetchone()
        if cached:return dict(cached),True

    result, context_chunks, model_used = remediation_advisor.generate_remediation(
        asset, cve, attack_path_info, policy_context
    )

    policy_rules = policy_gatekeeper.load_active_rules(cur)
    verdict = policy_gatekeeper.check(asset, cve, result, attack_path_info, policy_rules, ml_signal)

    cur.execute("""
        INSERT INTO remediation_recommendations
            (asset_id, cve_id, risk_score_at_generation, risk_tier_at_generation,
             recommendation, rationale, ot_safety_note, requires_maintenance_window,
             llm_confidence, llm_model, retrieved_context,
             gatekeeper_verdict, gatekeeper_reasons, gatekeeper_matched_rules, ml_confidence_signal,
             status, context_fingerprint, generated_at, updated_at)
        VALUES (%(asset_id)s, %(cve_id)s, %(risk_score)s, %(risk_tier)s,
                %(recommendation)s, %(rationale)s, %(ot_safety_note)s, %(requires_window)s,
                %(confidence)s, %(model)s, %(context)s,
                %(verdict)s, %(reasons)s, %(matched_rules)s, %(ml_signal)s,
                'PENDING', %(fingerprint)s, NOW(), NOW())
        ON CONFLICT (asset_id, cve_id) DO UPDATE SET
            risk_score_at_generation = EXCLUDED.risk_score_at_generation,
            risk_tier_at_generation  = EXCLUDED.risk_tier_at_generation,
            recommendation           = EXCLUDED.recommendation,
            rationale                = EXCLUDED.rationale,
            ot_safety_note           = EXCLUDED.ot_safety_note,
            requires_maintenance_window = EXCLUDED.requires_maintenance_window,
            llm_confidence           = EXCLUDED.llm_confidence,
            llm_model                = EXCLUDED.llm_model,
            retrieved_context        = EXCLUDED.retrieved_context,
            gatekeeper_verdict       = EXCLUDED.gatekeeper_verdict,
            gatekeeper_reasons       = EXCLUDED.gatekeeper_reasons,
            gatekeeper_matched_rules = EXCLUDED.gatekeeper_matched_rules,
            ml_confidence_signal     = EXCLUDED.ml_confidence_signal,
            status                   = 'PENDING',
            context_fingerprint=EXCLUDED.context_fingerprint,
            decision_note            = NULL,
            decided_at               = NULL,
            updated_at               = NOW()
        RETURNING id;
    """, {
        "asset_id": asset_id, "cve_id": cve_id, "fingerprint":fingerprint,
        "risk_score": vuln_row["risk_score"], "risk_tier": vuln_row["risk_tier"],
        "recommendation": result.recommendation, "rationale": result.rationale,
        "ot_safety_note": result.ot_safety_note, "requires_window": result.requires_maintenance_window,
        "confidence": result.confidence, "model": model_used,
        "context": json.dumps(context_chunks),
        "verdict": verdict["verdict"], "reasons": json.dumps(verdict["reasons"]),
        "matched_rules": json.dumps(verdict["matched_rules"]), "ml_signal": json.dumps(ml_signal),
    })
    rec_id = cur.fetchone()["id"]

    cur.execute("""
        INSERT INTO remediation_gatekeeper_audit
            (recommendation_id, asset_id, verdict, reasons, matched_rules, ml_confidence_signal)
        VALUES (%s, %s, %s, %s, %s, %s);
    """, (rec_id, asset_id, verdict["verdict"], json.dumps(verdict["reasons"]),
          json.dumps(verdict["matched_rules"]), json.dumps(ml_signal)))

    conn.commit()

    cur.execute("SELECT * FROM remediation_recommendations WHERE id = %s;", (rec_id,))
    return dict(cur.fetchone()), False


@remediation_bp.route('/', methods=['GET'])
def list_recommendations():
    try:
        status = request.args.get('status')
        show_blocked = request.args.get('show_blocked', '0') == '1'

        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        where = []
        params = []
        if not show_blocked:
            where.append("r.gatekeeper_verdict != 'BLOCK'")
        if status:
            where.append("r.status = %s")
            params.append(status)
        where_sql = ("WHERE " + " AND ".join(where)) if where else ""

        cur.execute(f"""
            SELECT r.*, a.vendor, a.product, a.ip, a.port, a.zone, a.device_type, a.criticality
            FROM remediation_recommendations r
            JOIN assets a ON a.id = r.asset_id
            {where_sql}
            ORDER BY r.risk_score_at_generation DESC, r.generated_at DESC;
        """, params)

        rows = []
        for row in cur.fetchall():
            d = dict(row)
            for key in ("generated_at", "updated_at", "decided_at"):
                if d.get(key):
                    d[key] = d[key].strftime('%Y-%m-%d %H:%M:%S')
            rows.append(d)

        conn.close()
        return jsonify(rows)
    except Exception as e:
        import traceback
        print(f"[remediation /api/remediation ERROR] {e}\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500


@remediation_bp.route('/candidates', methods=['GET'])
def list_candidates():
    """CRITICAL/HIGH-tier assets (top CVE only) with NO recommendation at
    all yet — one candidate per device, not per CVE.

    Deliberately asset-level, not (asset,cve)-level: risk_score has live
    components (Suricata alert count, anomaly score) that shift every
    ~10-15s cycle, so which CVE ranks "#1" for a device churns even when
    the device's overall risk hasn't meaningfully changed. Gating staleness
    on an exact CVE-id match caused a device to reappear as a "candidate"
    almost immediately after being reviewed, just because two of its CVEs
    swapped rank — not genuinely new information. A device counts as
    reviewed once it has any current recommendation; regenerating for a
    newly-different top CVE is still possible via generate's force=true,
    just not auto-surfaced as a nagging candidate."""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        cur.execute("""
            WITH ranked AS (
                SELECT a.id AS asset_id, a.device_type, a.vendor, a.product, a.ip,
                       a.port, a.service, a.zone, a.criticality,
                       v.cve_id, v.cvss, v.epss, v.kev, v.risk_score, v.risk_tier,
                       ROW_NUMBER() OVER (PARTITION BY a.id ORDER BY v.risk_score DESC) AS rn
                FROM vulnerabilities v
                JOIN assets a ON a.id = v.asset_id
                WHERE a.status = 'ACTIVE' AND v.applicability='CONFIRMED' AND v.risk_tier IN ('CRITICAL', 'HIGH')
            )
            SELECT r.* FROM ranked r
            WHERE r.rn = 1
            AND NOT EXISTS (
                SELECT 1 FROM remediation_recommendations rr
                WHERE rr.asset_id = r.asset_id
            )
            ORDER BY r.risk_score DESC;
        """)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@remediation_bp.route('/generate', methods=['POST'])
def generate_one():
    try:
        body = request.get_json(silent=True)
        if not isinstance(body,dict):return jsonify(success=False,message="JSON object required"),400
        asset_id = body.get("asset_id")
        cve_id = body.get("cve_id")
        force = body.get("force", False)
        if not isinstance(force,bool) or isinstance(asset_id,bool) or not isinstance(asset_id,int) or asset_id<1:return jsonify(success=False,message="Positive integer asset_id and boolean force required"),422
        if not asset_id or not cve_id:
            return jsonify({"success": False, "message": "asset_id and cve_id are required"}), 400

        from validation import validate_cve
        validate_cve({'cve_id':cve_id})
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        record, cached = _generate_one(cur, conn, asset_id, cve_id, force=force)
        conn.close()

        return jsonify({"success": True, "cached": cached, "recommendation": record})
    except ValueError as e:
        return jsonify(success=False,message=str(e)),422
    except psycopg2.Error:
        return jsonify(success=False,message='Remediation database unavailable'),503
    except Exception:
        return jsonify(success=False,message='Remediation generation failed; verify provider configuration'),502


def _run_bulk_generation():
    global _gen_state
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            WITH ranked AS (
                SELECT a.id AS asset_id, a.device_type, v.cve_id, v.risk_score, v.risk_tier,
                       ROW_NUMBER() OVER (PARTITION BY a.id ORDER BY v.risk_score DESC) AS rn
                FROM vulnerabilities v JOIN assets a ON a.id = v.asset_id
                WHERE a.status = 'ACTIVE' AND v.applicability='CONFIRMED' AND v.risk_tier IN ('CRITICAL', 'HIGH')
            )
            SELECT r.asset_id, r.device_type, r.cve_id FROM ranked r
            WHERE r.rn = 1
            AND NOT EXISTS (
                SELECT 1 FROM remediation_recommendations rr
                WHERE rr.asset_id = r.asset_id
            );
        """)
        candidates = cur.fetchall()

        with _gen_lock:
            _gen_state.update({"running": True, "total": len(candidates), "completed": 0,
                                "current_asset": None, "errors": []})

        for c in candidates:
            with _gen_lock:
                _gen_state["current_asset"] = c["device_type"]
            try:
                _generate_one(cur, conn, c["asset_id"], c["cve_id"], force=False)
            except Exception as e:
                err_msg = str(e)
                with _gen_lock:
                    _gen_state["errors"].append(f"{c['device_type']}: {err_msg}")
                # Rate limit — stop bulk generation, don't burn remaining quota
                if "429" in err_msg or "rate" in err_msg.lower() or "quota" in err_msg.lower():
                    print(f"  [bulk gen] Rate limited on {c['device_type']} — stopping bulk. Try again later.")
                    break
            with _gen_lock:
                _gen_state["completed"] += 1

        conn.close()
    except Exception as e:
        with _gen_lock:
            _gen_state["errors"].append(f"Fatal: {e}")
    finally:
        with _gen_lock:
            _gen_state["running"] = False
            _gen_state["current_asset"] = None


@remediation_bp.route('/generate/all', methods=['POST'])
def generate_all():
    with _gen_lock:
        if _gen_state["running"]:
            return jsonify({"success": True, "message": "Already running"})
    threading.Thread(target=_run_bulk_generation, daemon=True).start()
    return jsonify({"success": True, "message": "Bulk generation started"})


@remediation_bp.route('/generate/status', methods=['GET'])
def generate_status():
    with _gen_lock:
        return jsonify(dict(_gen_state))


def _decide(rec_id,new_status):
    conn=None
    try:
        body=request.get_json(silent=True)
        if not isinstance(body,dict):return jsonify(success=False,message='JSON object required'),400
        note=body.get('note','')
        if not isinstance(note,str) or len(note)>2000:return jsonify(success=False,message='Note must be text up to 2000 characters'),422
        conn=get_db_connection()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute('SELECT * FROM remediation_recommendations WHERE id=%s FOR UPDATE',(rec_id,))
            row=cur.fetchone()
            if not row:return jsonify(success=False,message='Recommendation not found'),404
            if row['status']!='PENDING':return jsonify(success=False,message='Only pending recommendations can be decided'),409
            if new_status=='APPROVED':
                if row['gatekeeper_verdict']=='BLOCK':return jsonify(success=False,message='Blocked recommendations cannot be approved'),409
                if row['gatekeeper_verdict']=='NEEDS_REVIEW' and not note.strip():return jsonify(success=False,message='Review note required'),422
                cur.execute('SELECT * FROM assets WHERE id=%s',(row['asset_id'],));asset=cur.fetchone()
                cur.execute('SELECT * FROM vulnerabilities WHERE asset_id=%s AND cve_id=%s',(row['asset_id'],row['cve_id']));cve=cur.fetchone()
                if not asset or not cve or cve.get('applicability')!='CONFIRMED':return jsonify(success=False,message='Current applicability evidence is missing'),409
                from types import SimpleNamespace
                rec=SimpleNamespace(recommendation=row['recommendation'],requires_maintenance_window=row['requires_maintenance_window'],confidence=row['llm_confidence'])
                verdict=policy_gatekeeper.check(dict(asset),dict(cve),rec,_attack_path_info(cur,asset['device_type']),policy_gatekeeper.load_active_rules(cur))
                if verdict['verdict']=='BLOCK':return jsonify(success=False,message='Current safety checks block approval',reasons=verdict['reasons']),409
                if verdict['verdict']=='NEEDS_REVIEW' and not note.strip():return jsonify(success=False,message='Current checks require a review note'),422
            cur.execute('UPDATE remediation_recommendations SET status=%s,decision_note=%s,decided_at=NOW(),updated_at=NOW() WHERE id=%s',(new_status,note,rec_id))
            cur.execute('INSERT INTO remediation_decision_audit(recommendation_id,previous_status,new_status,decision_note,gatekeeper_verdict) VALUES (%s,%s,%s,%s,%s)',(rec_id,row['status'],new_status,note,row['gatekeeper_verdict']))
        conn.commit()
        return jsonify(success=True,message=f'Marked {new_status}; no device configuration changed')
    except psycopg2.Error:
        if conn:conn.rollback()
        return jsonify(success=False,message='Decision database unavailable'),503
    finally:
        if conn:conn.close()


@remediation_bp.route('/<int:rec_id>/approve', methods=['POST'])
def approve(rec_id):
    return _decide(rec_id, "APPROVED")


@remediation_bp.route('/<int:rec_id>/reject', methods=['POST'])
def reject(rec_id):
    return _decide(rec_id, "REJECTED")


@remediation_bp.route('/<int:rec_id>/defer', methods=['POST'])
def defer(rec_id):
    return _decide(rec_id, "DEFERRED")


@remediation_bp.route('/audit/<int:rec_id>', methods=['GET'])
def audit(rec_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT * FROM remediation_gatekeeper_audit
            WHERE recommendation_id = %s ORDER BY evaluated_at DESC;
        """, (rec_id,))
        rows = []
        for row in cur.fetchall():
            d = dict(row)
            if d.get("evaluated_at"):
                d["evaluated_at"] = d["evaluated_at"].strftime('%Y-%m-%d %H:%M:%S')
            rows.append(d)
        conn.close()
        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def register_remediation_api(app):
    app.register_blueprint(remediation_bp)
    print("✓ Remediation advisor API registered at /api/remediation/")
