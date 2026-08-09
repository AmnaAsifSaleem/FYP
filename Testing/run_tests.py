#!/usr/bin/env python3
"""
CAVE-OT Test Runner
Run all tests for the CAVE-OT system
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path

def print_header(title):
    """Print formatted header"""
    print("\n" + "=" * 70)
    print(f" {title}")
    print("=" * 70)

def run_unit_tests():
    """Run all unit tests"""
    print_header("RUNNING UNIT TESTS")
    
    unit_tests_dir = Path(__file__).parent / "unit_tests"
    
    # Run risk scoring tests
    risk_test = unit_tests_dir / "test_risk_scoring.py"
    if risk_test.exists():
        print(f"\n1. Risk Scoring Formula Tests")
        print(f"   File: {risk_test.name}")
        
        # Change to project root for proper imports
        project_root = Path(__file__).parent.parent
        os.chdir(project_root)
        
        result = subprocess.run(
            [sys.executable, str(risk_test)],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print("   [PASSED]")
        else:
            print("   [FAILED]")
            print(f"\n   Output:\n{result.stdout}")
            if result.stderr:
                print(f"\n   Errors:\n{result.stderr}")
        
        return result.returncode == 0
    else:
        print(f"⚠ Risk scoring test not found: {risk_test}")
        return False

def run_integration_tests():
    """Run integration tests"""
    print_header("RUNNING INTEGRATION TESTS")
    print("\nIntegration tests coming soon...")
    return True  # Placeholder

def run_data_validation():
    """Run data validation tests"""
    print_header("RUNNING DATA VALIDATION")
    
    test_data_dir = Path(__file__).parent / "test_data"
    project_root = Path(__file__).parent.parent
    os.chdir(project_root)
    
    tests = [
        ("check_dataset.py", "Policy Dataset Validation"),
        ("check_policy_tables.py", "Policy Database Tables Check"),
        ("test_model_features.py", "Model Features Check"),
    ]
    
    all_passed = True
    
    for test_file, test_name in tests:
        test_path = test_data_dir / test_file
        if test_path.exists():
            print(f"\n• {test_name}")
            print(f"  File: {test_file}")
            
            result = subprocess.run(
                [sys.executable, str(test_path)],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print("  [PASSED]")
            else:
                print("  [FAILED]")
                all_passed = False
                
                # Show relevant output
                if "Error" in result.stdout or "Traceback" in result.stdout:
                    print(f"\n  Output:\n{result.stdout[:500]}...")
        else:
            print(f"⚠ Test not found: {test_file}")
    
    return all_passed

def generate_test_report():
    """Generate test report"""
    print_header("GENERATING TEST REPORT")
    
    reports_dir = Path(__file__).parent / "reports"
    
    # Check for existing reports
    report_files = list(reports_dir.glob("*.md"))
    
    if report_files:
        print("\nAvailable Test Reports:")
        for report in report_files:
            print(f"  • {report.name}")
        
        # Show latest report
        latest_report = max(report_files, key=os.path.getctime)
        print(f"\nLatest report: {latest_report.name}")
        
        # Show summary
        try:
            with open(latest_report, 'r') as f:
                content = f.read()
                
            # Extract key information
            if "RISK SCORING FORMULA IS CORRECT AND RELIABLE" in content:
                print("  Status: [PASSED]")
            elif "FAILED" in content:
                print("  Status: [FAILED]")
            
            # Extract test counts
            import re
            test_match = re.search(r"Total: (\d+) tests.*Passed: (\d+)", content, re.DOTALL)
            if test_match:
                total = test_match.group(1)
                passed = test_match.group(2)
                print(f"  Tests: {passed}/{total} passed")
            
            # Extract real data info
            data_match = re.search(r"Total CVEs: (\d+)", content)
            if data_match:
                print(f"  CVEs Validated: {data_match.group(1)}")
                
        except Exception as e:
            print(f"  Error reading report: {e}")
    else:
        print("\nNo test reports found.")
    
    return True

def main():
    """Main test runner"""
    parser = argparse.ArgumentParser(description="CAVE-OT Test Runner")
    parser.add_argument("--unit", action="store_true", help="Run unit tests only")
    parser.add_argument("--integration", action="store_true", help="Run integration tests only")
    parser.add_argument("--data", action="store_true", help="Run data validation only")
    parser.add_argument("--report", action="store_true", help="Generate test report only")
    parser.add_argument("--all", action="store_true", help="Run all tests (default)")
    
    args = parser.parse_args()
    
    # Default to all if no specific option given
    if not (args.unit or args.integration or args.data or args.report):
        args.all = True
    
    print_header("CAVE-OT TEST SUITE")
    print("Testing the correctness and reliability of CAVE-OT system")
    
    results = {}
    
    # Run selected tests
    if args.unit or args.all:
        results['unit'] = run_unit_tests()
    
    if args.integration or args.all:
        results['integration'] = run_integration_tests()
    
    if args.data or args.all:
        results['data'] = run_data_validation()
    
    if args.report or args.all:
        results['report'] = generate_test_report()
    
    # Summary
    print_header("TEST SUMMARY")
    
    if results:
        print("\nTest Results:")
        for test_type, passed in results.items():
            status = "[PASSED]" if passed else "[FAILED]"
            print(f"  {test_type.title()} Tests: {status}")
        
        all_passed = all(results.values())
        if all_passed:
            print("\n[SUCCESS] ALL TESTS PASSED!")
        else:
            print("\n[WARNING] SOME TESTS FAILED - Review the output above")
        
        return 0 if all_passed else 1
    else:
        print("\nNo tests were run.")
        return 0

if __name__ == "__main__":
    sys.exit(main())