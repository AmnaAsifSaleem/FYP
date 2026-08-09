"""
Quick test script to validate the CAVE-OT pipeline
Creates sample test data and runs the full pipeline
"""

import json
import os
import subprocess
import sys

def create_test_data():
    """Create test model_input.json with sample OT devices"""
    test_devices = [
        {
            "ip": "192.168.1.10",
            "port": 502,
            "service": "Modbus",
            "device_type": "PLC",
            "zone": "OT",
            "vendor": "Schneider Electric",
            "product": "Modicon M340",
            "firmware": "2.39",
            "alert_count": 0,
            "alert_severity": 3
        },
        {
            "ip": "192.168.1.20",
            "port": 102,
            "service": "S7comm",
            "device_type": "PLC",
            "zone": "OT",
            "vendor": "Siemens",
            "product": "SIMATIC S7-300",
            "firmware": "3.2",
            "alert_count": 2,
            "alert_severity": 1
        },
        {
            "ip": "192.168.1.30",
            "port": 44818,
            "service": "EtherNet/IP",
            "device_type": "PLC",
            "zone": "OT",
            "vendor": "Rockwell Automation",
            "product": "ControlLogix 1756",
            "firmware": "20.11",
            "alert_count": 0,
            "alert_severity": 3
        }
    ]
    
    with open('test_input.json', 'w') as f:
        json.dump(test_devices, f, indent=2)
    
    print("✓ Created test_input.json with 3 sample devices")

def run_pipeline():
    """Run the CVE mapper and risk scorer"""
    print("\n" + "=" * 60)
    print("Running CVE Mapper...")
    print("=" * 60)
    result = subprocess.run([sys.executable, 'cve_mapper.py', 'test_input.json'])
    if result.returncode != 0:
        print("✗ CVE Mapper failed")
        return False
    
    print("\n" + "=" * 60)
    print("Running Risk Scorer...")
    print("=" * 60)
    result = subprocess.run([sys.executable, 'risk_scorer.py', 'test_input.json'])
    if result.returncode != 0:
        print("✗ Risk Scorer failed")
        return False
    
    return True

def display_results():
    """Display the final results"""
    with open('test_input.json', 'r') as f:
        devices = json.load(f)
    
    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    
    for device in devices:
        print(f"\n{device['ip']} - {device['vendor']} {device['product']}")
        print(f"Device Type: {device['device_type']} | Zone: {device['zone']}")
        
        cves = device.get('cves', [])
        if not cves:
            print("  No CVEs found")
            continue
        
        print(f"  Total CVEs: {len(cves)}")
        print(f"\n  Top 5 Risks:")
        for i, cve in enumerate(cves[:5], 1):
            print(f"    {i}. {cve['cve_id']:<20} "
                  f"CVSS:{cve['cvss']:<4} "
                  f"Risk:{cve['risk_score']:<4} "
                  f"{cve['risk_emoji']} {cve['risk_tier']}")

def main():
    print("=" * 60)
    print("CAVE-OT PIPELINE TEST")
    print("=" * 60)
    
    # Check if models exist
    model_folder = r"D:\Downloads\CAVE-OT Datasets\model"
    if not os.path.exists(f"{model_folder}/ot_vectorizer.pkl"):
        print("\n✗ Models not found. Run model_trainer.py first:")
        print("  python model_trainer.py")
        sys.exit(1)
    
    print("\n[1/3] Creating test data...")
    create_test_data()
    
    print("\n[2/3] Running pipeline...")
    if not run_pipeline():
        sys.exit(1)
    
    print("\n[3/3] Displaying results...")
    display_results()
    
    print("\n" + "=" * 60)
    print("✓ TEST COMPLETE")
    print("=" * 60)
    print("\nTest results saved to: test_input.json")

if __name__ == "__main__":
    main()
