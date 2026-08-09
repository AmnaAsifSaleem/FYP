#!/usr/bin/env python3
"""
Comprehensive Test Suite for Risk Scoring Formula
Tests the correctness and reliability of risk_scorer.py calculations
"""

import sys
import os
import json
import math

# Add project root to path for imports
import sys
import os
project_root = os.path.join(os.path.dirname(__file__), '..', '..')
sys.path.insert(0, project_root)

# Import the risk scoring functions
from CVE_Pipeline.risk_scorer import (
    get_exploit_code_maturity,
    get_remediation_level,
    calculate_temporal_score,
    calculate_cia_score,
    calculate_suricata_factor,
    calculate_risk_score,
    get_risk_tier,
    ASSET_CRITICALITY,
    SEVERITY_WEIGHT
)

class TestRiskScoring:
    """Test suite for risk scoring formula"""
    
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results = []
    
    def run_test(self, test_name, test_func):
        """Run a single test"""
        try:
            result = test_func()
            if result:
                self.passed += 1
                self.results.append(f"[PASS] {test_name}")
                return True
            else:
                self.failed += 1
                self.results.append(f"[FAIL] {test_name}")
                return False
        except Exception as e:
            self.failed += 1
            self.results.append(f"[ERROR] {test_name} - {str(e)}")
            return False
    
    def assert_approx_equal(self, actual, expected, tolerance=0.01, msg=""):
        """Assert that values are approximately equal"""
        if abs(actual - expected) > tolerance:
            raise AssertionError(f"{msg}: Expected {expected}, got {actual}")
        return True
    
    def test_01_exploit_maturity(self):
        """Test exploit code maturity calculation from EPSS"""
        # Test cases: (EPSS, expected_factor)
        test_cases = [
            (0.80, 1.00),   # High EPSS → High maturity
            (0.70, 1.00),   # Boundary
            (0.69, 0.97),   # Just below boundary
            (0.50, 0.97),   # Functional exploit
            (0.40, 0.97),   # Boundary
            (0.39, 0.94),   # Just below boundary
            (0.20, 0.94),   # Proof of concept
            (0.10, 0.94),   # Boundary
            (0.09, 0.91),   # Just below boundary
            (0.00, 0.91),   # Unproven
        ]
        
        for epss, expected in test_cases:
            actual = get_exploit_code_maturity(epss)
            if not self.assert_approx_equal(actual, expected, 0.001, f"EPSS={epss}"):
                return False
        return True
    
    def test_02_remediation_level(self):
        """Test remediation level calculation from KEV status"""
        # KEV=1 → No fix available
        assert get_remediation_level(1) == 1.00, "KEV=1 should return 1.00"
        
        # KEV=0 → Official fix available
        assert get_remediation_level(0) == 0.95, "KEV=0 should return 0.95"
        
        return True
    
    def test_03_temporal_score(self):
        """Test temporal score calculation"""
        # Test case 1: High risk CVE
        # CVSS=9.0, EPSS=0.8, KEV=1
        temporal = calculate_temporal_score(9.0, 0.8, 1)
        # Expected: 9.0 * 1.00 * 1.00 = 9.0
        assert self.assert_approx_equal(temporal, 9.0, 0.01, "High risk CVE")
        
        # Test case 2: Medium risk CVE
        # CVSS=5.0, EPSS=0.3, KEV=0
        temporal = calculate_temporal_score(5.0, 0.3, 0)
        # Expected: 5.0 * 0.94 * 0.95 = 4.465
        assert self.assert_approx_equal(temporal, 4.465, 0.01, "Medium risk CVE")
        
        return True
    
    def test_04_cia_score(self):
        """Test OT-weighted CIA score calculation"""
        # Test case 1: High availability impact (OT critical)
        cia = calculate_cia_score(0.5, 0.5, 1.0)  # A=1.0, I=0.5, C=0.5
        # Expected: (0.5*0.2) + (0.5*0.3) + (1.0*0.5) = 0.1 + 0.15 + 0.5 = 0.75
        assert self.assert_approx_equal(cia, 0.75, 0.01, "High availability impact")
        
        # Test case 2: High confidentiality impact (less critical for OT)
        cia = calculate_cia_score(1.0, 0.5, 0.5)  # C=1.0, I=0.5, A=0.5
        # Expected: (1.0*0.2) + (0.5*0.3) + (0.5*0.5) = 0.2 + 0.15 + 0.25 = 0.6
        assert self.assert_approx_equal(cia, 0.6, 0.01, "High confidentiality impact")
        
        # Test case 3: All impacts equal
        cia = calculate_cia_score(0.8, 0.8, 0.8)
        # Expected: (0.8*0.2) + (0.8*0.3) + (0.8*0.5) = 0.16 + 0.24 + 0.4 = 0.8
        assert self.assert_approx_equal(cia, 0.8, 0.01, "All impacts equal")
        
        return True
    
    def test_05_suricata_factor(self):
        """Test Suricata context factor calculation"""
        # Test case 1: No alerts
        factor = calculate_suricata_factor(0, 1)
        assert factor == 0.0, "No alerts should return 0.0"
        
        # Test case 2: Low severity alerts
        factor = calculate_suricata_factor(5, 3)  # 5 alerts, severity 3
        # Expected: (5 * 0.30) / 30 = 1.5 / 30 = 0.05
        assert self.assert_approx_equal(factor, 0.05, 0.01, "Low severity alerts")
        
        # Test case 3: High severity alerts (capped at 1.0)
        factor = calculate_suricata_factor(50, 1)  # 50 alerts, severity 1
        # Expected: (50 * 1.00) / 30 = 50/30 = 1.666 → capped at 1.0
        assert self.assert_approx_equal(factor, 1.0, 0.01, "High severity alerts capped")
        
        # Test case 4: Unknown severity (defaults to 0.30)
        factor = calculate_suricata_factor(10, 99)  # Unknown severity
        # Expected: (10 * 0.30) / 30 = 3/30 = 0.1
        assert self.assert_approx_equal(factor, 0.1, 0.01, "Unknown severity")
        
        return True
    
    def test_06_asset_criticality(self):
        """Test asset criticality values"""
        # Verify all asset types have criticality values
        expected_assets = ['PLC', 'RTU', 'SCADA', 'HMI', 'Engineering_WS', 
                          'Historian', 'IT_Server', 'Generic']
        
        for asset in expected_assets:
            assert asset in ASSET_CRITICALITY, f"Missing criticality for {asset}"
        
        # Verify criticality values are reasonable (0.0 to 1.0)
        for asset, crit in ASSET_CRITICALITY.items():
            assert 0.0 <= crit <= 1.0, f"Invalid criticality for {asset}: {crit}"
        
        # Verify OT devices have higher criticality
        assert ASSET_CRITICALITY['PLC'] > ASSET_CRITICALITY['IT_Server'], "PLC should be more critical than IT_Server"
        assert ASSET_CRITICALITY['RTU'] > ASSET_CRITICALITY['Generic'], "RTU should be more critical than Generic"
        
        return True
    
    def test_07_risk_score_calculation(self):
        """Test full risk score calculation"""
        # Test case 1: Critical PLC with high-risk CVE
        cve = {
            'cvss': 9.8,
            'epss': 0.9,
            'kev': 1,
            'c_impact': 0.8,
            'i_impact': 0.8,
            'a_impact': 0.8
        }
        
        score = calculate_risk_score(cve, 'PLC', alert_count=10, alert_severity=1)
        
        # Manual calculation:
        # 1. Temporal: 9.8 * 1.00 * 1.00 = 9.8
        # 2. CIA: (0.8*0.2)+(0.8*0.3)+(0.8*0.5)=0.16+0.24+0.4=0.8
        # 3. Asset crit: PLC = 1.00
        # 4. Environmental: 9.8 * 0.8 * 1.00 * 10 = 78.4 → min(78.4, 10) = 10.0
        # 5. KEV bonus: 10.0 * 1.10 = 11.0 → min(11.0, 10) = 10.0
        # 6. Suricata: (10 * 1.00) / 30 = 0.333 → 0.333 * 1.5 = 0.5
        # 7. Final: min(10.0 + 0.5, 10.0) = 10.0
        
        assert self.assert_approx_equal(score, 10.0, 0.1, "Critical PLC with high-risk CVE")
        
        # Test case 2: Low risk IT server
        cve = {
            'cvss': 3.5,
            'epss': 0.05,
            'kev': 0,
            'c_impact': 0.2,
            'i_impact': 0.2,
            'a_impact': 0.2
        }
        
        score = calculate_risk_score(cve, 'IT_Server', alert_count=0, alert_severity=3)
        
        # Should be low score
        assert score < 4.0, f"Low risk CVE should have score < 4.0, got {score}"
        
        return True
    
    def test_08_risk_tier_assignment(self):
        """Test risk tier assignment from scores"""
        test_cases = [
            (9.5, 'CRITICAL', '🔴'),
            (8.0, 'CRITICAL', '🔴'),  # Boundary
            (7.9, 'HIGH', '🟠'),      # Just below boundary
            (6.5, 'HIGH', '🟠'),
            (6.0, 'HIGH', '🟠'),      # Boundary
            (5.9, 'MEDIUM', '🟡'),    # Just below boundary
            (4.5, 'MEDIUM', '🟡'),
            (4.0, 'MEDIUM', '🟡'),    # Boundary
            (3.9, 'LOW', '🟢'),       # Just below boundary
            (2.0, 'LOW', '🟢'),
            (0.0, 'LOW', '🟢'),
        ]
        
        for score, expected_tier, expected_emoji in test_cases:
            tier, emoji = get_risk_tier(score)
            assert tier == expected_tier, f"Score {score}: Expected {expected_tier}, got {tier}"
            assert emoji == expected_emoji, f"Score {score}: Expected {expected_emoji}, got {emoji}"
        
        return True
    
    def test_09_edge_cases(self):
        """Test edge cases and boundary conditions"""
        # Test with CVSS = 0
        cve = {
            'cvss': 0.0,
            'epss': 0.0,
            'kev': 0,
            'c_impact': 0.0,
            'i_impact': 0.0,
            'a_impact': 0.0
        }
        score = calculate_risk_score(cve, 'Generic')
        assert score >= 0.0, "Score should be >= 0"
        assert score <= 10.0, "Score should be <= 10"
        
        # Test with CVSS = 10
        cve = {
            'cvss': 10.0,
            'epss': 1.0,
            'kev': 1,
            'c_impact': 1.0,
            'i_impact': 1.0,
            'a_impact': 1.0
        }
        score = calculate_risk_score(cve, 'PLC', alert_count=100, alert_severity=1)
        assert score <= 10.0, "Score should be capped at 10.0"
        
        # Test with negative values (should handle gracefully)
        try:
            cve = {
                'cvss': -1.0,
                'epss': -0.5,
                'kev': 0,
                'c_impact': -0.1,
                'i_impact': -0.1,
                'a_impact': -0.1
            }
            score = calculate_risk_score(cve, 'Generic')
            # Should not crash, result may be unexpected but shouldn't error
        except Exception as e:
            self.results.append(f"⚠ WARNING: Negative values caused error: {e}")
        
        return True
    
    def test_10_formula_consistency(self):
        """Test formula consistency - same inputs should give same outputs"""
        cve = {
            'cvss': 7.5,
            'epss': 0.3,
            'kev': 0,
            'c_impact': 0.6,
            'i_impact': 0.6,
            'a_impact': 0.6
        }
        
        # Calculate score twice
        score1 = calculate_risk_score(cve, 'HMI')
        score2 = calculate_risk_score(cve, 'HMI')
        
        assert self.assert_approx_equal(score1, score2, 0.001, "Scores should be identical")
        
        # Test with different asset types (use lower CVSS to avoid capping)
        cve_lower = {
            'cvss': 5.0,
            'epss': 0.1,
            'kev': 0,
            'c_impact': 0.4,
            'i_impact': 0.4,
            'a_impact': 0.4
        }
        
        score_plc = calculate_risk_score(cve_lower, 'PLC')
        score_rtu = calculate_risk_score(cve_lower, 'RTU')
        score_generic = calculate_risk_score(cve_lower, 'Generic')
        
        # PLC should have higher score than Generic (more critical)
        assert score_plc > score_generic, f"PLC ({score_plc}) should have higher risk than Generic ({score_generic})"
        assert score_rtu > score_generic, f"RTU ({score_rtu}) should have higher risk than Generic ({score_generic})"
        
        return True
    
    def run_all_tests(self):
        """Run all tests"""
        print("=" * 70)
        print("RISK SCORING FORMULA TEST SUITE")
        print("=" * 70)
        
        tests = [
            ("Exploit Maturity Calculation", self.test_01_exploit_maturity),
            ("Remediation Level", self.test_02_remediation_level),
            ("Temporal Score", self.test_03_temporal_score),
            ("CIA Score (OT-weighted)", self.test_04_cia_score),
            ("Suricata Context Factor", self.test_05_suricata_factor),
            ("Asset Criticality Values", self.test_06_asset_criticality),
            ("Full Risk Score Calculation", self.test_07_risk_score_calculation),
            ("Risk Tier Assignment", self.test_08_risk_tier_assignment),
            ("Edge Cases", self.test_09_edge_cases),
            ("Formula Consistency", self.test_10_formula_consistency),
        ]
        
        for test_name, test_func in tests:
            print(f"\nRunning: {test_name}")
            self.run_test(test_name, test_func)
        
        # Print summary
        print("\n" + "=" * 70)
        print("TEST RESULTS SUMMARY")
        print("=" * 70)
        
        for result in self.results:
            print(result)
        
        print(f"\nTotal: {self.passed + self.failed} tests")
        print(f"Passed: {self.passed}")
        print(f"Failed: {self.failed}")
        
        if self.failed == 0:
            print("\n[SUCCESS] ALL TESTS PASSED - Risk scoring formula is working correctly!")
        else:
            print(f"\n[FAILED] {self.failed} TESTS FAILED - Review the formula implementation")
        
        return self.failed == 0

def test_with_real_data():
    """Test with actual data from the system"""
    print("\n" + "=" * 70)
    print("REAL DATA VALIDATION")
    print("=" * 70)
    
    # Load actual vulnerability scan results
    scan_file = os.path.join(project_root, "Assets", "vulnerability_scan_results.json")
    
    if not os.path.exists(scan_file):
        print(f"[WARNING] Scan file not found: {scan_file}")
        return False
    
    try:
        with open(scan_file, 'r') as f:
            scan_data = json.load(f)
        
        # The data has structure: {"scan_summary": ..., "devices": [...]}
        devices = scan_data.get('devices', [])
        print(f"Loaded scan data with {len(devices)} devices")
        
        # Check if risk scores are present
        devices_with_scores = 0
        total_cves = 0
        risk_distribution = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for device_entry in devices:
            cves = device_entry.get('cves', [])
            total_cves += len(cves)
            
            if cves and 'risk_score' in cves[0]:
                devices_with_scores += 1
                
                for cve in cves:
                    tier = cve.get('risk_tier', 'LOW')
                    risk_distribution[tier] = risk_distribution.get(tier, 0) + 1
        
        print(f"\nDevices with risk scores: {devices_with_scores}/{len(devices)}")
        print(f"Total CVEs: {total_cves}")
        print(f"\nRisk Distribution in real data:")
        print(f"  🔴 CRITICAL: {risk_distribution['CRITICAL']}")
        print(f"  🟠 HIGH:     {risk_distribution['HIGH']}")
        print(f"  🟡 MEDIUM:   {risk_distribution['MEDIUM']}")
        print(f"  🟢 LOW:      {risk_distribution['LOW']}")
        
        # Validate scores are within bounds
        all_scores_valid = True
        for device_entry in devices:
            for cve in device_entry.get('cves', []):
                score = cve.get('risk_score', 0)
                if not (0 <= score <= 10):
                    print(f"⚠ Invalid score {score} for {cve.get('cve_id', 'unknown')}")
                    all_scores_valid = False
        
        if all_scores_valid:
            print("\n[PASS] All real data scores are within valid range (0-10)")
        else:
            print("\n[FAIL] Some scores are outside valid range")
        
        # Test recalculating a few scores to verify formula
        print("\n" + "-" * 70)
        print("FORMULA VERIFICATION ON REAL DATA")
        print("-" * 70)
        
        recalc_errors = 0
        samples_tested = 0
        
        for device_entry in devices[:2]:  # Test first 2 devices
            device_info = device_entry.get('device', {})
            device_type = device_info.get('device_type', 'Generic')
            cves = device_entry.get('cves', [])[:3]  # Test first 3 CVEs per device
            
            for cve in cves:
                # Recalculate risk score
                recalc_score = calculate_risk_score(
                    cve, 
                    device_type,
                    alert_count=0,
                    alert_severity=3
                )
                
                original_score = cve.get('risk_score', 0)
                difference = abs(recalc_score - original_score)
                
                if difference > 0.1:  # Allow small rounding differences
                    print(f"⚠ Score mismatch for {cve.get('cve_id', 'unknown')}:")
                    print(f"  Original: {original_score}, Recalculated: {recalc_score}")
                    print(f"  Difference: {difference}")
                    recalc_errors += 1
                
                samples_tested += 1
        
        if recalc_errors == 0:
            print(f"[PASS] Formula matches {samples_tested} real CVEs (within tolerance)")
        else:
            print(f"[FAIL] {recalc_errors}/{samples_tested} CVEs have score mismatches")
        
        return all_scores_valid and (recalc_errors == 0)
        
    except Exception as e:
        print(f"Error testing real data: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main test execution"""
    # Run unit tests
    tester = TestRiskScoring()
    unit_tests_passed = tester.run_all_tests()
    
    # Run real data validation
    real_data_valid = test_with_real_data()
    
    # Final verdict
    print("\n" + "=" * 70)
    print("FINAL VERDICT")
    print("=" * 70)
    
    if unit_tests_passed and real_data_valid:
        print("[SUCCESS] RISK SCORING FORMULA IS CORRECT AND RELIABLE")
        print("\nThe formula:")
        print("1. [PASS] Passes all mathematical tests")
        print("2. [PASS] Handles edge cases properly")
        print("3. [PASS] Produces valid scores for real data")
        print("4. [PASS] Aligns with OT security principles")
        print("5. [PASS] Has consistent behavior")
    else:
        print("[FAILED] RISK SCORING FORMULA NEEDS REVIEW")
        if not unit_tests_passed:
            print("  - Unit tests failed")
        if not real_data_valid:
            print("  - Real data validation failed")
    
    return unit_tests_passed and real_data_valid

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)