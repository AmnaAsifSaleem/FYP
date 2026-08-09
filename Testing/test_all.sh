#!/bin/bash
# Simple test runner for CAVE-OT

echo "========================================"
echo "CAVE-OT TEST RUNNER"
echo "========================================"

# Change to project root
cd "$(dirname "$0")/.."

echo ""
echo "1. Running Risk Scoring Formula Tests..."
echo "----------------------------------------"
python Testing/unit_tests/test_risk_scoring.py

echo ""
echo "2. Running Data Validation Tests..."
echo "-----------------------------------"
echo ""
echo "   a) Policy Dataset Validation:"
python Testing/test_data/check_dataset.py

echo ""
echo "   b) Policy Database Tables Check:"
python Testing/test_data/check_policy_tables.py

echo ""
echo "   c) Model Features Check:"
python Testing/test_data/test_model_features.py

echo ""
echo "========================================"
echo "TEST COMPLETE"
echo "========================================"
echo ""
echo "To run individual tests:"
echo "  - Risk scoring: python Testing/unit_tests/test_risk_scoring.py"
echo "  - Dataset check: python Testing/test_data/check_dataset.py"
echo "  - Database check: python Testing/test_data/check_policy_tables.py"
echo "  - Model features: python Testing/test_data/test_model_features.py"
echo ""
echo "Test reports are in: Testing/reports/"