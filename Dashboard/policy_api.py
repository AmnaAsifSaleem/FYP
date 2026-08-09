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
from policy_predictor import PolicyCompliancePredictor

# Create Blueprint for policy API
policy_bp = Blueprint('policy', __name__, url_prefix='/api/policy')

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "cave_ot",
    "user": "postgres",
    "password": "admin"
}

def get_db_connection():
    """Get database connection"""
    return psycopg2.connect(**DB_CONFIG)

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
                'last_check': stats[5]
            },
            'zones': zones,
            'top_non_compliant': non_compliant
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@policy_bp.route('/assets', methods=['GET'])
def policy_assets():
    """Get all assets with compliance status"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cur.execute("""
            SELECT 
                a.*,
                pc.compliance_status,
                pc.compliance_score,
                pc.confidence,
                pc.explanation,
                pc.checked_at,
                COUNT(pv.id) as violation_count
            FROM assets a
            LEFT JOIN policy_compliance pc ON a.id = pc.asset_id
            LEFT JOIN policy_violations pv ON pc.id = pv.compliance_id
            GROUP BY a.id, pc.id
            ORDER BY pc.compliance_score ASC NULLS LAST, a.criticality DESC
        """)
        
        assets = cur.fetchall()
        
        # Convert to list of dicts
        assets_list = []
        for asset in assets:
            asset_dict = dict(asset)
            # Convert datetime to string
            for key in ['first_seen', 'last_seen', 'checked_at']:
                if asset_dict.get(key):
                    asset_dict[key] = asset_dict[key].strftime('%Y-%m-%d %H:%M:%S')
            assets_list.append(asset_dict)
        
        conn.close()
        
        return jsonify(assets_list)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@policy_bp.route('/check/<int:asset_id>', methods=['POST'])
def check_asset_compliance(asset_id):
    """Check policy compliance for a specific asset"""
    try:
        # Get asset from database
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        cur.execute("""
            SELECT * FROM assets WHERE id = %s
        """, (asset_id,))
        
        asset = cur.fetchone()
        if not asset:
            return jsonify({"error": "Asset not found"}), 404
        
        # Initialize predictor
        predictor = PolicyCompliancePredictor()
        
        # Prepare asset for prediction
        asset_features = {
            'device_type': asset.get('device_type', 'Unknown'),
            'vendor': asset.get('vendor', 'Unknown'),
            'zone': asset.get('zone', 'OT'),
            'service': asset.get('service', 'Unknown'),
            'port': asset.get('port', 0),
            'encrypted': 1 if asset.get('service') in ('HTTPS', 'SSH') else 0,
            'cvss': 0.0,
            'epss': 0.0,
            'kev': 0,
            'c_impact': 0.0,
            'i_impact': 0.0,
            'a_impact': 0.0,
            'criticality': asset.get('criticality', 0.5),
            'days_since_patch': 30,
            'firmware_eol': 0,
            'alert_count': 0
        }
        
        # Get CVE data for this asset
        cur.execute("""
            SELECT 
                AVG(cvss) as avg_cvss,
                AVG(epss) as avg_epss,
                MAX(CASE WHEN kev = TRUE THEN 1 ELSE 0 END) as has_kev,
                AVG(c_impact) as avg_c_impact,
                AVG(i_impact) as avg_i_impact,
                AVG(a_impact) as avg_a_impact,
                COUNT(*) as cve_count
            FROM vulnerabilities 
            WHERE asset_id = %s
        """, (asset_id,))
        
        cve_result = cur.fetchone()
        if cve_result and cve_result['cve_count'] > 0:
            asset_features['cvss'] = float(cve_result['avg_cvss'] or 0.0)
            asset_features['epss'] = float(cve_result['avg_epss'] or 0.0)
            asset_features['kev'] = int(cve_result['has_kev'] or 0)
            asset_features['c_impact'] = float(cve_result['avg_c_impact'] or 0.0)
            asset_features['i_impact'] = float(cve_result['avg_i_impact'] or 0.0)
            asset_features['a_impact'] = float(cve_result['avg_a_impact'] or 0.0)
        
        # Predict compliance
        result = predictor.predict(asset_features)[0]
        
        # Save to database
        key_factors = {
            'zone': result.get('explanation', ''),
            'confidence': result['confidence'],
            'compliance_score': result['compliance_score']
        }
        
        cur.execute("""
            INSERT INTO policy_compliance 
            (asset_id, compliance_status, compliance_score, confidence, explanation, key_factors)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (asset_id) 
            DO UPDATE SET 
                compliance_status = EXCLUDED.compliance_status,
                compliance_score = EXCLUDED.compliance_score,
                confidence = EXCLUDED.confidence,
                explanation = EXCLUDED.explanation,
                key_factors = EXCLUDED.key_factors,
                checked_at = NOW()
        """, (
            asset_id,
            result['compliance_status'],
            float(result['compliance_score']),
            float(result['confidence']),
            result['explanation'],
            json.dumps(key_factors)
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'asset_id': asset_id,
            'asset_name': f"{asset['vendor']} {asset['product']}",
            'prediction': result,
            'features_used': asset_features
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@policy_bp.route('/check/all', methods=['POST'])
def check_all_compliance():
    """Check policy compliance for all assets and save to DB."""
    try:
        import pandas as pd
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM assets ORDER BY id")
        assets = [dict(a) for a in cur.fetchall()]

        predictor = PolicyCompliancePredictor()
        checked = 0

        for asset in assets:
            # enrich with avg CVE data
            cur.execute("""
                SELECT AVG(cvss) avg_cvss, AVG(epss) avg_epss,
                       MAX(CASE WHEN kev THEN 1 ELSE 0 END) has_kev,
                       AVG(c_impact) avg_c, AVG(i_impact) avg_i,
                       AVG(a_impact) avg_a, COUNT(*) cnt
                FROM vulnerabilities WHERE asset_id = %s
            """, (asset['id'],))
            cv = cur.fetchone()

            features = {
                'device_type':      asset.get('device_type', 'Unknown'),
                'vendor':           asset.get('vendor', 'Unknown'),
                'zone':             asset.get('zone', 'OT'),
                'service':          asset.get('service', 'Unknown'),
                'port':             asset.get('port', 0),
                'encrypted':        1 if asset.get('service') in ('HTTPS', 'SSH') else 0,
                'cvss':             float(cv['avg_cvss'] or 0) if cv and cv['cnt'] else 0.0,
                'epss':             float(cv['avg_epss'] or 0) if cv and cv['cnt'] else 0.0,
                'kev':              int(cv['has_kev'] or 0)    if cv and cv['cnt'] else 0,
                'c_impact':         float(cv['avg_c'] or 0)    if cv and cv['cnt'] else 0.0,
                'i_impact':         float(cv['avg_i'] or 0)    if cv and cv['cnt'] else 0.0,
                'a_impact':         float(cv['avg_a'] or 0)    if cv and cv['cnt'] else 0.0,
                'criticality':      asset.get('criticality', 0.5),
                'days_since_patch': 30,
                'firmware_eol':     0,
                'alert_count':      0,
            }

            result = predictor.predict(pd.DataFrame([features]))[0]

            cur.execute("""
                INSERT INTO policy_compliance
                    (asset_id, compliance_status, compliance_score, confidence, explanation, key_factors)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (asset_id) DO UPDATE SET
                    compliance_status = EXCLUDED.compliance_status,
                    compliance_score  = EXCLUDED.compliance_score,
                    confidence        = EXCLUDED.confidence,
                    explanation       = EXCLUDED.explanation,
                    key_factors       = EXCLUDED.key_factors,
                    checked_at        = NOW()
            """, (
                asset['id'],
                result['compliance_status'],
                float(result['compliance_score']),
                float(result['confidence']),
                result['explanation'],
                json.dumps({'explanation': result['explanation']}),
            ))
            checked += 1

        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': f'Checked {checked} assets'})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

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
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Function to register blueprint in main app
def register_policy_api(app):
    """Register policy API blueprint with Flask app"""
    app.register_blueprint(policy_bp)
    print("✓ Policy compliance API registered at /api/policy/")
