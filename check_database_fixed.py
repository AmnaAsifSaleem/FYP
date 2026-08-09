"""
Check database state and verify CVE counts - Fixed version
"""
import psycopg2
import json
import os

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "cave_ot",
    "user": "postgres",
    "password": "admin"
}

def check_database():
    """Check database state and CVE counts"""
    print("=" * 60)
    print("DATABASE VERIFICATION CHECK")
    print("=" * 60)
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        
        # 1. Check total CVE count
        cur.execute("SELECT COUNT(*) FROM vulnerabilities")
        total_cves = cur.fetchone()[0]
        print(f"1. Total CVE records in database: {total_cves}")
        
        # 2. Check unique CVE count
        cur.execute("SELECT COUNT(DISTINCT cve_id) FROM vulnerabilities")
        unique_cves = cur.fetchone()[0]
        print(f"2. Unique CVEs in database: {unique_cves}")
        
        # 3. Check CVE count per asset
        print("\n3. CVEs per asset:")
        cur.execute("""
            SELECT a.vendor, a.product, COUNT(v.id) as cve_count
            FROM assets a
            LEFT JOIN vulnerabilities v ON a.id = v.asset_id
            GROUP BY a.id, a.vendor, a.product
            ORDER BY cve_count DESC
        """)
        
        for row in cur.fetchall():
            print(f"   {row[0]} {row[1]}: {row[2]} CVEs")
        
        # 4. Check for duplicate CVEs per asset
        print("\n4. Checking for duplicate CVEs per asset...")
        cur.execute("""
            SELECT asset_id, cve_id, COUNT(*) as duplicate_count
            FROM vulnerabilities 
            GROUP BY asset_id, cve_id 
            HAVING COUNT(*) > 1
            ORDER BY duplicate_count DESC
        """)
        
        duplicates = cur.fetchall()
        if duplicates:
            print(f"   WARNING: Found {len(duplicates)} duplicate CVE records!")
            for dup in duplicates[:5]:  # Show first 5
                print(f"   Asset {dup[0]}, CVE {dup[1]}: {dup[2]} duplicates")
        else:
            print("   ✓ No duplicate CVEs per asset (good!)")
        
        # 5. Check CVSS distribution (simplified query)
        print("\n5. CVSS severity distribution:")
        cur.execute("""
            SELECT 
                severity,
                COUNT(*) as count
            FROM (
                SELECT 
                    CASE 
                        WHEN cvss >= 9.0 THEN 'CRITICAL'
                        WHEN cvss >= 7.0 THEN 'HIGH'
                        WHEN cvss >= 4.0 THEN 'MEDIUM'
                        ELSE 'LOW'
                    END as severity
                FROM vulnerabilities
            ) as severity_table
            GROUP BY severity
            ORDER BY 
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                END
        """)
        
        for row in cur.fetchall():
            print(f"   {row[0]}: {row[1]} CVEs")
        
        # 6. Check recent updates
        print("\n6. Recent CVE updates:")
        cur.execute("""
            SELECT COUNT(*) as recent_cves
            FROM vulnerabilities
            WHERE updated_at > NOW() - INTERVAL '1 hour'
        """)
        recent = cur.fetchone()[0]
        print(f"   CVEs updated in last hour: {recent}")
        
        # 7. Check JSON file vs database
        print("\n7. Comparing JSON file with database...")
        json_path = os.path.join("..", "Assets", "vulnerability_scan_results.json")
        if os.path.exists(json_path):
            with open(json_path, 'r') as f:
                data = json.load(f)
            
            json_cves = data['scan_summary']['total_cves_found']
            json_devices = data['scan_summary']['total_devices']
            
            print(f"   JSON file: {json_devices} devices, {json_cves} CVE mappings")
            print(f"   Database: {total_cves} CVE records")
            
            if json_cves == total_cves:
                print("   ✓ JSON and database counts match")
            else:
                print(f"   ⚠ Mismatch: JSON={json_cves}, DB={total_cves}")
        
        # 8. Check policy compliance data
        print("\n8. Policy compliance status:")
        cur.execute("""
            SELECT 
                COUNT(*) as total_assets,
                COUNT(pc.id) as checked_assets,
                SUM(CASE WHEN pc.compliance_status = 'COMPLIANT' THEN 1 ELSE 0 END) as compliant,
                SUM(CASE WHEN pc.compliance_status = 'NON_COMPLIANT' THEN 1 ELSE 0 END) as non_compliant,
                AVG(pc.compliance_score) as avg_score
            FROM assets a
            LEFT JOIN policy_compliance pc ON a.id = pc.asset_id
        """)
        
        policy_stats = cur.fetchone()
        print(f"   Total assets: {policy_stats[0]}")
        print(f"   Checked assets: {policy_stats[1]}")
        print(f"   Compliant: {policy_stats[2] or 0}")
        print(f"   Non-compliant: {policy_stats[3] or 0}")
        print(f"   Average compliance score: {policy_stats[4] or 0:.3f}")
        
        # 9. Check asset details with compliance
        print("\n9. Asset compliance details:")
        cur.execute("""
            SELECT 
                a.vendor, a.product, a.zone, a.service,
                pc.compliance_status, pc.compliance_score, pc.explanation
            FROM assets a
            LEFT JOIN policy_compliance pc ON a.id = pc.asset_id
            ORDER BY pc.compliance_score ASC NULLS LAST
            LIMIT 3
        """)
        
        for row in cur.fetchall():
            status = row[4] or "NOT CHECKED"
            score = row[5] or 0
            explanation = row[6] or "No explanation"
            print(f"   {row[0]} {row[1]} ({row[2]}, {row[3]}): {status} (Score: {score:.3f})")
            if explanation and len(explanation) > 0:
                print(f"     Explanation: {explanation[:80]}...")
        
        conn.close()
        
        print("\n" + "=" * 60)
        print("ANALYSIS")
        print("=" * 60)
        
        # Calculate statistics
        avg_cves = total_cves / 6  # We know there are 6 assets
        cve_ratio = unique_cves / total_cves if total_cves > 0 else 0
        
        print(f"• Total CVE records: {total_cves}")
        print(f"• Unique CVEs: {unique_cves}")
        print(f"• Average CVEs per asset: {avg_cves:.1f}")
        print(f"• Unique CVE ratio: {cve_ratio:.1%}")
        
        # Issues found
        issues = []
        
        if avg_cves > 20:
            issues.append("High CVE count per asset (>20) - possible over-matching")
        
        if cve_ratio < 0.7:
            issues.append(f"Low unique CVE ratio ({cve_ratio:.1%}) - many shared CVEs")
        
        # Check specific assets
        if total_cves > 250:
            issues.append("Very high total CVE count - may include historical/inapplicable CVEs")
        
        if issues:
            print("\n⚠ POTENTIAL ISSUES:")
            for issue in issues:
                print(f"  • {issue}")
        else:
            print("\n✓ Database appears to be in good state")
        
        print("\n" + "=" * 60)
        print("RECOMMENDATIONS")
        print("=" * 60)
        
        print("1. Review CVE matching logic - 25+ CVEs per device is high")
        print("2. Consider filtering CVEs with CVSS < 4.0")
        print("3. Verify firmware version matching is accurate")
        print("4. Run policy compliance check to see current status")
        print("5. Check dashboard for visual verification")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    check_database()
