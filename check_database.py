"""
Check database state and verify CVE counts
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
        
        # 5. Check CVSS distribution
        print("\n5. CVSS severity distribution:")
        cur.execute("""
            SELECT 
                CASE 
                    WHEN cvss >= 9.0 THEN 'CRITICAL'
                    WHEN cvss >= 7.0 THEN 'HIGH'
                    WHEN cvss >= 4.0 THEN 'MEDIUM'
                    ELSE 'LOW'
                END as severity,
                COUNT(*) as count
            FROM vulnerabilities
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
        
        conn.close()
        
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        
        # Calculate average CVEs per device
        cur2 = conn.cursor()
        cur2.execute("SELECT COUNT(*) FROM assets")
        asset_count = cur2.fetchone()[0]
        avg_cves = total_cves / asset_count if asset_count > 0 else 0
        
        print(f"Assets: {asset_count}")
        print(f"Total CVE records: {total_cves}")
        print(f"Unique CVEs: {unique_cves}")
        print(f"Average CVEs per asset: {avg_cves:.1f}")
        
        if avg_cves > 20:
            print("⚠ WARNING: High CVE count per asset (>20)")
            print("   This may indicate over-matching or including historical CVEs")
        
        if unique_cves < total_cves * 0.7:
            print("⚠ WARNING: Low unique CVE ratio")
            print("   Many CVEs are shared across multiple assets")
        
        cur2.close()
        conn.close()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_database()
