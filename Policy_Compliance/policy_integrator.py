"""
Policy Compliance Integrator
Integrates policy compliance checking with existing CAVE-OT system
"""

import sys
import os
import json
import psycopg2
from policy_predictor import PolicyCompliancePredictor
import pandas as pd

# Add parent directory to path to import database modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "cave_ot",
    "user": "postgres",
    "password": "admin"
}

class PolicyComplianceIntegrator:
    """
    Integrates policy compliance checking with CAVE-OT database
    """
    
    def __init__(self):
        self.predictor = PolicyCompliancePredictor()
        self.db_conn = None
    
    def connect_db(self):
        """Connect to PostgreSQL database"""
        try:
            self.db_conn = psycopg2.connect(**DB_CONFIG)
            return True
        except Exception as e:
            print(f"✗ Database connection error: {e}")
            return False
    
    def get_all_assets(self):
        """Get all assets from database"""
        if not self.db_conn:
            if not self.connect_db():
                return None
        
        try:
            cur = self.db_conn.cursor()
            cur.execute("""
                SELECT 
                    id, ip, port, service, device_type, zone, 
                    vendor, product, firmware, criticality,
                    description, status
                FROM assets
                ORDER BY id
            """)
            
            columns = [desc[0] for desc in cur.description]
            assets = []
            
            for row in cur.fetchall():
                asset = dict(zip(columns, row))
                assets.append(asset)
            
            return assets
            
        except Exception as e:
            print(f"✗ Error fetching assets: {e}")
            return None
    
    def prepare_asset_for_prediction(self, asset):
        """
        Prepare database asset for policy compliance prediction
        Adds default values for missing features
        """
        # Map database asset to model features
        asset_features = {
            'device_type': asset.get('device_type', 'Unknown'),
            'vendor': asset.get('vendor', 'Unknown'),
            'zone': asset.get('zone', 'OT'),
            'service': asset.get('service', 'Unknown'),
            'port': asset.get('port', 0),
            'encrypted': 0,  # Default: not encrypted (we don't have this data)
            'cvss': 0.0,     # Will be updated with CVE data if available
            'epss': 0.0,
            'kev': 0,
            'c_impact': 0.0,
            'i_impact': 0.0,
            'a_impact': 0.0,
            'criticality': asset.get('criticality', 0.5),
            'days_since_patch': 30,  # Default: 30 days since patch
            'firmware_eol': 0,       # Default: firmware not EOL
            'alert_count': 0         # Default: no alerts
        }
        
        # Try to get CVE data for this asset
        self._enhance_with_cve_data(asset, asset_features)
        
        return asset_features
    
    def _enhance_with_cve_data(self, asset, asset_features):
        """Enhance asset features with CVE data if available"""
        if not self.db_conn:
            return
        
        try:
            cur = self.db_conn.cursor()
            
            # Get average CVSS and EPSS for this asset's CVEs
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
            """, (asset['id'],))
            
            result = cur.fetchone()
            if result and result[6] > 0:  # If there are CVEs
                asset_features['cvss'] = float(result[0] or 0.0)
                asset_features['epss'] = float(result[1] or 0.0)
                asset_features['kev'] = int(result[2] or 0)
                asset_features['c_impact'] = float(result[3] or 0.0)
                asset_features['i_impact'] = float(result[4] or 0.0)
                asset_features['a_impact'] = float(result[5] or 0.0)
            
            # Get alert count
            cur.execute("""
                SELECT COUNT(*) as alert_count
                FROM alerts
                WHERE asset_id = %s
            """, (asset['id'],))
            
            alert_result = cur.fetchone()
            if alert_result:
                asset_features['alert_count'] = int(alert_result[0] or 0)
                
        except Exception as e:
            print(f"  Warning: Could not enhance with CVE data: {e}")
    
    def save_compliance_results(self, asset_id, prediction_result):
        """Save compliance results to database"""
        if not self.db_conn:
            return False
        
        try:
            cur = self.db_conn.cursor()
            
            # Convert key factors to JSON
            key_factors = {
                'zone': prediction_result.get('explanation', ''),
                'confidence': prediction_result['confidence'],
                'compliance_score': prediction_result['compliance_score']
            }
            
            # Insert or update compliance record
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
                RETURNING id
            """, (
                asset_id,
                prediction_result['compliance_status'],
                prediction_result['compliance_score'],
                prediction_result['confidence'],
                prediction_result['explanation'],
                json.dumps(key_factors)
            ))
            
            compliance_id = cur.fetchone()[0]
            self.db_conn.commit()
            
            # If non-compliant, add a violation record
            if prediction_result['compliance_status'] == 'NON_COMPLIANT':
                self._add_violation_record(compliance_id, prediction_result)
            
            return True
            
        except Exception as e:
            print(f"✗ Error saving compliance results: {e}")
            self.db_conn.rollback()
            return False
    
    def _add_violation_record(self, compliance_id, prediction_result):
        """Add violation record for non-compliant assets"""
        try:
            cur = self.db_conn.cursor()
            
            # Create violation based on prediction
            violated_policy = "Policy compliance check failed"
            if "encrypted" in prediction_result['explanation']:
                violated_policy = "Encryption requirement not met"
            elif "zone" in prediction_result['explanation']:
                violated_policy = "Zone policy violation"
            
            cur.execute("""
                INSERT INTO policy_violations 
                (compliance_id, violated_policy, policy_source, severity, remediation)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                compliance_id,
                violated_policy,
                "NIST SP 800-82r3; CISA DiD",
                "HIGH" if prediction_result['compliance_score'] < 0.3 else "MEDIUM",
                "Review device configuration and security controls"
            ))
            
            self.db_conn.commit()
            
        except Exception as e:
            print(f"  Warning: Could not add violation record: {e}")
    
    def run_compliance_check(self):
        """Run compliance check for all assets"""
        print("=" * 60)
        print("RUNNING POLICY COMPLIANCE CHECK")
        print("=" * 60)
        
        # Connect to database
        if not self.connect_db():
            return False
        
        # Get all assets
        assets = self.get_all_assets()
        if not assets:
            print("✗ No assets found in database")
            return False
        
        print(f"Found {len(assets)} assets to check")
        
        # Prepare assets for prediction
        asset_features_list = []
        asset_ids = []
        for asset in assets:
            asset_features = self.prepare_asset_for_prediction(asset)
            asset_features_list.append(asset_features)
            asset_ids.append(asset['id'])
        
        # Convert to DataFrame
        assets_df = pd.DataFrame(asset_features_list)
        
        # Predict compliance
        print("\nPredicting policy compliance...")
        results = self.predictor.predict(assets_df)
        
        # Save results
        print("\nSaving results to database...")
        success_count = 0
        
        for i, result in enumerate(results):
            asset_id = asset_ids[i]
            asset_name = f"{assets[i]['vendor']} {assets[i]['product']}"
            
            if self.save_compliance_results(asset_id, result):
                success_count += 1
                status_icon = "✅" if result['compliance_status'] == 'COMPLIANT' else "❌"
                print(f"  {status_icon} {asset_name}: {result['compliance_status']} "
                      f"(Score: {result['compliance_score']:.3f})")
            else:
                print(f"  ✗ Failed to save results for {asset_name}")
        
        # Generate summary
        print("\n" + "=" * 60)
        print("COMPLIANCE CHECK SUMMARY")
        print("=" * 60)
        
        compliant_count = sum(1 for r in results if r['compliance_status'] == 'COMPLIANT')
        non_compliant_count = len(results) - compliant_count
        
        print(f"Assets checked: {len(results)}")
        print(f"Compliant: {compliant_count} ({compliant_count/len(results)*100:.1f}%)")
        print(f"Non-compliant: {non_compliant_count} ({non_compliant_count/len(results)*100:.1f}%)")
        print(f"Results saved: {success_count}/{len(results)}")
        
        # Show top non-compliant assets
        if non_compliant_count > 0:
            print("\nTop Non-Compliant Assets:")
            non_compliant_results = [(assets[i], r) for i, r in enumerate(results) 
                                    if r['compliance_status'] == 'NON_COMPLIANT']
            non_compliant_results.sort(key=lambda x: x[1]['compliance_score'])
            
            for asset, result in non_compliant_results[:5]:  # Top 5
                print(f"  • {asset['vendor']} {asset['product']}: "
                      f"Score {result['compliance_score']:.3f} - {result['explanation']}")
        
        return True
    
    def get_compliance_summary(self):
        """Get compliance summary from database"""
        if not self.connect_db():
            return None
        
        try:
            cur = self.db_conn.cursor()
            
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
            
            # Get recent compliance results
            cur.execute("""
                SELECT 
                    a.vendor, a.product, a.zone, a.service,
                    pc.compliance_status, pc.compliance_score, pc.confidence,
                    pc.explanation, pc.checked_at
                FROM policy_compliance pc
                JOIN assets a ON a.id = pc.asset_id
                ORDER BY pc.checked_at DESC
                LIMIT 10
            """)
            
            recent_results = []
            columns = [desc[0] for desc in cur.description]
            
            for row in cur.fetchall():
                recent_results.append(dict(zip(columns, row)))
            
            return {
                'statistics': {
                    'total_assets': stats[0],
                    'checked_assets': stats[1],
                    'compliant_count': stats[2] or 0,
                    'non_compliant_count': stats[3] or 0,
                    'avg_compliance_score': float(stats[4] or 0),
                    'last_check': stats[5]
                },
                'recent_results': recent_results
            }
            
        except Exception as e:
            print(f"✗ Error getting compliance summary: {e}")
            return None

def main():
    """Main function to run compliance check"""
    integrator = PolicyComplianceIntegrator()
    
    # Run compliance check
    if integrator.run_compliance_check():
        # Get and display summary
        summary = integrator.get_compliance_summary()
        
        if summary:
            stats = summary['statistics']
            print("\n" + "=" * 60)
            print("DATABASE COMPLIANCE STATUS")
            print("=" * 60)
            print(f"Total Assets: {stats['total_assets']}")
            print(f"Checked Assets: {stats['checked_assets']}")
            print(f"Compliant: {stats['compliant_count']}")
            print(f"Non-compliant: {stats['non_compliant_count']}")
            print(f"Average Compliance Score: {stats['avg_compliance_score']:.3f}")
            print(f"Last Check: {stats['last_check']}")
            
            if summary['recent_results']:
                print("\nRecent Compliance Results:")
                for result in summary['recent_results'][:3]:
                    status_icon = "✅" if result['compliance_status'] == 'COMPLIANT' else "❌"
                    print(f"  {status_icon} {result['vendor']} {result['product']}: "
                          f"{result['compliance_status']} (Score: {result['compliance_score']:.3f})")
    
    print("\n" + "=" * 60)
    print("POLICY COMPLIANCE INTEGRATION COMPLETE")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Run Database/db_policy_setup.py to create policy tables")
    print("2. Update Flask dashboard to show compliance results")
    print("3. Add API endpoints for compliance checking")

if __name__ == "__main__":
    main()
