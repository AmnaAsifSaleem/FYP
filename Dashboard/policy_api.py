import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pipeline_paths import DB_CONFIG
"""
Policy Compliance API Extension for CAVE-OT Dashboard
Adds policy compliance endpoints to the Flask app
"""

import sys
import os
import json

# Add Policy_Compliance to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'Policy_Compliance'))

from flask import Blueprint, jsonify, request
import psycopg2

# Lazy-load the predictor so a missing/corrupt model file doesn't prevent
# the entire blueprint from registering — individual endpoints return a
# clear 503 instead of every /api/policy/* route being a silent 404.
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

# Create Blueprint for policy API
policy_bp = Blueprint('policy', __name__, url_prefix='/api/policy')



def get_db_connection():
    """Get database connection"""
    from request_connection import connect
    return connect(DB_CONFIG)

@policy_bp.route('/summary', methods=['GET'])
def policy_summary():
    """Get policy compliance summary"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Get compliance statistics
        cur.execute("""
            SELECT 
                COUNT(*) as total_assets,
                COUNT(pc.id) as checked_assets,
                SUM(CASE WHEN pc.compliance_status = 'COMPLIANT' THEN 1 ELSE 0 END) as compliant_count,
                SUM(CASE WHEN pc.compliance_status = 'NON_COMPLIANT' THEN 1 ELSE 0 END) as non_compliant_count,
                AVG(pc.compliance_score) as avg_score,
                MAX(pc.checked_at) as last_check
            FROM assets a
            LEFT JOIN policy_compliance pc ON a.id = pc.asset_id
        """)
        
        stats = cur.fetchone()
        
        # Get compliance by zone
        cur.execute("""
            SELECT 
                a.zone,
                COUNT(*) as total,
                SUM(CASE WHEN pc.compliance_status = 'COMPLIANT' THEN 1 ELSE 0 END) as compliant,
                AVG(pc.compliance_score) as avg_score
            FROM assets a
            LEFT JOIN policy_compliance pc ON a.id = pc.asset_id
            GROUP BY a.zone
            ORDER BY avg_score ASC
        """)
        
        zones = []
        for row in cur.fetchall():
            zones.append({
                'zone': row[0],
                'total': row[1],
                'compliant': row[2] or 0,
                'avg_score': float(row[3] or 0)
            })
        
        # Get top non-compliant assets
        cur.execute("""
            SELECT 
                a.id, a.ip, a.port, a.vendor, a.product, a.device_type, a.zone, a.service,
                pc.compliance_status, pc.compliance_score, pc.confidence, pc.explanation
            FROM policy_compliance pc
            JOIN assets a ON a.id = pc.asset_id
            WHERE pc.compliance_status = 'NON_COMPLIANT'
            ORDER BY pc.compliance_score ASC
            LIMIT 10
        """)
        
        non_compliant = []
        columns = [desc[0] for desc in cur.description]
        
        for row in cur.fetchall():
            non_compliant.append(dict(zip(columns, row)))
        
        conn.close()
        
        return jsonify({
            'statistics': {
                'total_assets': stats[0],
                'checked_assets': stats[1],
                'compliant_count': stats[2] or 0,
                'non_compliant_count': stats[3] or 0,
                'avg_compliance_score': float(stats[4] or 0),
                'needs_review_count': (stats[1] or 0)-(stats[2] or 0)-(stats[3] or 0),
                'last_check': stats[5]
            },
            'zones': zones,
            'top_non_compliant': non_compliant
        })
        
    except ValueError as e:
        return jsonify(error=str(e)),422
    except psycopg2.Error:
        return jsonify(error='Database unavailable; previous results preserved'),503
    except Exception:
        return jsonify(error='Unable to complete request'),500

@policy_bp.route('/assets', methods=['GET'])
def policy_assets():
    """Get all assets with compliance status"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cur.execute("""
            SELECT 
                a.*, (a.last_seen >= NOW()-INTERVAL '3 minutes') AS observed_recently,
                pc.compliance_status,
                pc.compliance_score,
                pc.confidence,
                pc.explanation,
                pc.checked_at,
                pc.key_factors,
                COUNT(pv.id) as violation_count
            FROM assets a
            LEFT JOIN policy_compliance pc ON a.id = pc.asset_id
            LEFT JOIN policy_violations pv ON pc.id = pv.compliance_id
            GROUP BY a.id, pc.id
            ORDER BY pc.compliance_score ASC NULLS LAST, a.criticality DESC
        """)
        
        assets = cur.fetchall()
        from policy_reviews import fingerprint,public_review
        from policy_engine import evaluate
        from policy_gatekeeper import load_active_rules
        rules=load_active_rules(cur)
        cur.execute('SELECT asset_id,cve_id,cvss,applicability FROM vulnerabilities')
        cves_by_asset={}
        for cve in cur.fetchall():cves_by_asset.setdefault(cve['asset_id'],[]).append(dict(cve))
        cur.execute("""SELECT DISTINCT ON (asset_id)
            id,asset_id,analyst_decision,reviewer,rationale,acknowledged_findings,
            system_recommendation,assessment_fingerprint,decided_at
            FROM policy_manual_reviews ORDER BY asset_id,decided_at DESC,id DESC""")
        latest={row['asset_id']:dict(row) for row in cur.fetchall()}
        for asset in assets:
            current=evaluate(dict(asset),cves_by_asset.get(asset['id'],[]),rules)
            token,_=fingerprint(dict(asset),cves_by_asset.get(asset['id'],[]),rules,current)
            asset['analyst_review']=public_review(latest.get(asset['id']),token)
        
        # Convert to list of dicts
        from monitoring_view import asset_view,scan_running
        running=scan_running()
        assets_list = []
        for asset in assets:
            asset_dict = asset_view(asset,running)
            # Convert datetime to string
            for key in ['first_seen', 'last_seen', 'checked_at']:
                if asset_dict.get(key):
                    asset_dict[key] = asset_dict[key].strftime('%Y-%m-%d %H:%M:%S')
            assets_list.append(asset_dict)
        
        conn.close()
        
        return jsonify(assets_list)
        
    except ValueError as e:
        return jsonify(error=str(e)),422
    except psycopg2.Error:
        return jsonify(error='Database unavailable; previous results preserved'),503
    except Exception:
        return jsonify(error='Unable to complete request'),500

@policy_bp.route('/check/<int:asset_id>', methods=['POST'])
def check_asset_compliance(asset_id):
    from policy_service import run_checks
    conn=None
    try:
        conn=get_db_connection()
        result=run_checks(conn,asset_id)[0]
        conn.commit()
        return jsonify(result)
    except LookupError as e:
        if conn:conn.rollback()
        return jsonify(error=str(e)),404
    except ValueError as e:
        if conn:conn.rollback()
        return jsonify(error=str(e)),422
    except psycopg2.Error:
        if conn:conn.rollback()
        return jsonify(error='Policy database unavailable; previous results preserved'),503
    finally:
        if conn:conn.close()

@policy_bp.route('/check/all', methods=['POST'])
def check_all_compliance():
    from policy_service import run_checks
    conn=None
    try:
        conn=get_db_connection();results=run_checks(conn);conn.commit()
        return jsonify(success=True,message=f'Checked {len(results)} assets',results=results)
    except psycopg2.Error:
        if conn:conn.rollback()
        return jsonify(success=False,message='Policy database unavailable; previous results preserved'),503
    finally:
        if conn:conn.close()


@policy_bp.route('/rules', methods=['GET'])
def get_policy_rules():
    """Get all policy rules"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cur.execute("""
            SELECT * FROM policy_rules 
            WHERE is_active = TRUE
            ORDER BY zone, service
        """)
        
        rules = cur.fetchall()
        conn.close()
        
        return jsonify([dict(rule) for rule in rules])
        
    except ValueError as e:
        return jsonify(error=str(e)),422
    except psycopg2.Error:
        return jsonify(error='Database unavailable; previous results preserved'),503
    except Exception:
        return jsonify(error='Unable to complete request'),500

@policy_bp.route('/violations', methods=['GET'])
def get_violations():
    """Get all policy violations"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cur.execute("""
            SELECT 
                pv.*,
                a.vendor, a.product, a.ip, a.port, a.zone, a.service,
                pc.compliance_score
            FROM policy_violations pv
            JOIN policy_compliance pc ON pv.compliance_id = pc.id
            JOIN assets a ON pc.asset_id = a.id
            ORDER BY pv.detected_at DESC
            LIMIT 50
        """)
        
        violations = cur.fetchall()
        
        # Convert to list of dicts
        violations_list = []
        for violation in violations:
            violation_dict = dict(violation)
            if violation_dict.get('detected_at'):
                violation_dict['detected_at'] = violation_dict['detected_at'].strftime('%Y-%m-%d %H:%M:%S')
            violations_list.append(violation_dict)
        
        conn.close()
        
        return jsonify(violations_list)
        
    except ValueError as e:
        return jsonify(error=str(e)),422
    except psycopg2.Error:
        return jsonify(error='Database unavailable; previous results preserved'),503
    except Exception:
        return jsonify(error='Unable to complete request'),500

# Function to register blueprint in main app
def register_policy_api(app):
    """Register policy API blueprint with Flask app"""
    app.register_blueprint(policy_bp)
    print("✓ Policy compliance API registered at /api/policy/")


@policy_bp.route('/review/<int:asset_id>',methods=['GET','POST'])
def analyst_review(asset_id):
    import psycopg2.extras
    from policy_reviews import assess,save_review,public_review,EvidenceChanged
    if request.method=='POST':
        if request.headers.get('Origin') and request.headers['Origin'].rstrip('/')!=request.host_url.rstrip('/'):
            return jsonify(error='Cross-origin decisions are not permitted'),403
        if not request.is_json:return jsonify(error='Submit a JSON decision'),415
    conn=None
    try:
        conn=get_db_connection()
        if request.method=='POST':
            row=save_review(conn,asset_id,request.get_json(silent=True))
            conn.commit()
            return jsonify(review=public_review(row,row['assessment_fingerprint'])),201
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            asset,cves,rules,result,token,snapshot=assess(cur,asset_id)
            cur.execute("""SELECT id,asset_id,analyst_decision,reviewer,rationale,acknowledged_findings,
                system_recommendation,assessment_fingerprint,decided_at
                FROM policy_manual_reviews WHERE asset_id=%s ORDER BY decided_at DESC,id DESC LIMIT 20""",(asset_id,))
            history=[public_review(row,token) for row in cur.fetchall()]
        return jsonify(asset={'id':asset['id'],'vendor':asset.get('vendor'),'product':asset.get('product'),'ip':asset['ip'],'port':asset['port']},
            assessment=result,assessment_fingerprint=token,history=history,
            reviewer_identity='Self-reported name; local prototype has no user authentication',enforcement='ADVISORY')
    except EvidenceChanged as e:
        if conn:conn.rollback()
        return jsonify(error=str(e)),409
    except LookupError as e:
        if conn:conn.rollback()
        return jsonify(error=str(e)),404
    except ValueError as e:
        if conn:conn.rollback()
        return jsonify(error=str(e)),422
    except psycopg2.Error:
        if conn:conn.rollback()
        return jsonify(error='Review database unavailable; previous decisions preserved'),503
    finally:
        if conn:conn.close()
