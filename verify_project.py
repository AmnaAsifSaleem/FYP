import requests
import json
import subprocess
import sys

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

def run_command(cmd):
    """Run a command and return output"""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip()

def test_database():
    print("1. Testing Database...")
    
    # Check database connection
    db_check = run_command("python Database/db_query.py")
    if "CAVE-OT DATABASE SUMMARY" in db_check:
        print("   ✓ Database connection working")
        
        # Extract key metrics
        lines = db_check.split('\n')
        for line in lines:
            if 'Total assets' in line:
                print(f"   {line.strip()}")
            elif 'Total CVEs' in line:
                print(f"   {line.strip()}")
            elif 'Critical CVEs' in line:
                print(f"   {line.strip()}")
    else:
        print("   ✗ Database connection failed")
        return False
    return True

def test_api():
    print("\n2. Testing Dashboard API...")
    
    try:
        # Test summary endpoint
        response = requests.get('http://localhost:5000/api/summary', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print("   ✓ API Summary endpoint working")
            print(f"   - Total assets: {data.get('total_assets', 0)}")
            print(f"   - Total CVEs: {data.get('total_cves', 0)}")
            print(f"   - Critical CVEs: {data.get('critical_cves', 0)}")
            print(f"   - High CVEs: {data.get('high_cves', 0)}")
            print(f"   - Medium CVEs: {data.get('medium_cves', 0)}")
            print(f"   - Low CVEs: {data.get('low_cves', 0)}")
        else:
            print(f"   ✗ API Summary failed: {response.status_code}")
            return False
            
        # Test assets endpoint
        response = requests.get('http://localhost:5000/api/assets', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"   ✓ Assets endpoint working: {len(data)} assets")
        else:
            print(f"   ✗ Assets endpoint failed: {response.status_code}")
            return False
            
        # Test vulnerabilities endpoint
        response = requests.get('http://localhost:5000/api/vulnerabilities', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"   ✓ Vulnerabilities endpoint working: {len(data)} vulnerabilities")
        else:
            print(f"   ✗ Vulnerabilities endpoint failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"   ✗ API test failed: {e}")
        return False
    return True

def test_pipeline():
    print("\n3. Testing Pipeline Components...")
    
    # Check if model files exist
    import os
    model_files = [
        'model/general_vectorizer.pkl',
        'model/general_matrix.pkl', 
        'model/cve_database.pkl',
        'model/ot_vectorizer.pkl',
        'model/ot_matrix.pkl',
        'model/ot_cve_database.pkl'
    ]
    
    all_exist = True
    for file in model_files:
        if os.path.exists(file):
            print(f"   ✓ {file}")
        else:
            print(f"   ✗ {file} - MISSING")
            all_exist = False
    
    if not all_exist:
        print("   ⚠ Some model files missing, CVE mapping may not work")
    
    # Check asset files
    asset_files = ['docker/shared/assets.json', 'docker/shared/risk_scored_results.json']
    for file in asset_files:
        if os.path.exists(file):
            print(f"   ✓ {file}")
        else:
            print(f"   ✗ {file} - MISSING")
            all_exist=False
    
    return all_exist

def main():
    print("=" * 60)
    print("CAVE-OT PROJECT VERIFICATION")
    print("=" * 60)
    
    all_passed = True
    
    # Test database
    if not test_database():
        all_passed = False
    
    # Test API
    if not test_api():
        all_passed = False
    
    # Test pipeline
    if not test_pipeline():all_passed=False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✅ PROJECT VERIFICATION PASSED")
        print("\nDashboard is running at: http://localhost:5000")
        print("Counts are read from the current database; candidate applicability is shown separately.")

    else:
        print("❌ PROJECT VERIFICATION FAILED")
        print("Some tests failed. Check the errors above.")
    
    print("=" * 60)

    return all_passed

if __name__ == "__main__":
    import sys
    sys.exit(0 if main() else 1)