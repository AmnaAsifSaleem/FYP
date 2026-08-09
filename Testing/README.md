# CAVE-OT Testing Framework

## Overview
This directory contains the comprehensive testing framework for the CAVE-OT (Context-Aware Vulnerability Engine for OT) system. The framework includes unit tests, integration tests, data validation, and test reports.

## Directory Structure
```
Testing/
├── unit_tests/          # Unit tests for individual components
│   └── test_risk_scoring.py
├── integration_tests/   # Integration tests (coming soon)
├── test_data/          # Data validation and test utilities
│   ├── check_dataset.py
│   ├── check_policy_tables.py
│   └── test_model_features.py
├── reports/            # Test reports and documentation
│   └── RISK_SCORING_TEST_REPORT.md
├── run_tests.py        # Main test runner script
└── README.md           # This file
```

## How to Run Tests

### 1. Run All Tests (Windows)
```bash
# Using batch file (recommended)
Testing\test_all.bat

# Or using Python directly
cd CAVE-OT Datasets_KIRO\CAVE-OT Datasets
python Testing\run_tests.py --all
```

### 2. Run All Tests (Linux/Mac)
```bash
# Using shell script
chmod +x Testing/test_all.sh
Testing/test_all.sh

# Or using Python directly
cd "CAVE-OT Datasets_KIRO/CAVE-OT Datasets"
python Testing/run_tests.py --all
```

### 3. Run Specific Test Types
```bash
# Run unit tests only
python Testing/run_tests.py --unit

# Run data validation only
python Testing/run_tests.py --data

# Generate test report only
python Testing/run_tests.py --report
```

### 3. Run Individual Test Files
```bash
# Run risk scoring tests
python Testing/unit_tests/test_risk_scoring.py

# Check policy dataset
python Testing/test_data/check_dataset.py

# Check policy database tables
python Testing/test_data/check_policy_tables.py

# Check model features
python Testing/test_data/test_model_features.py
```

## Available Tests

### ✅ Unit Tests
**`test_risk_scoring.py`** - Comprehensive tests for the risk scoring formula:
- Exploit maturity calculation from EPSS
- Remediation level from KEV status
- Temporal score calculation
- OT-weighted CIA score
- Suricata context factor
- Asset criticality values
- Full risk score calculation
- Risk tier assignment
- Edge cases and boundary conditions
- Formula consistency

### ✅ Data Validation Tests
**`check_dataset.py`** - Validates policy dataset structure and content
**`check_policy_tables.py`** - Checks if policy database tables exist
**`test_model_features.py`** - Tests model feature expectations

### 📊 Test Reports
**`RISK_SCORING_TEST_REPORT.md`** - Detailed report of risk scoring formula validation

## Test Results

### Latest Test Run (Risk Scoring)
- **Status**: ✅ ALL TESTS PASSED
- **Tests**: 10/10 passed
- **Real Data**: 157 CVEs validated
- **Formula**: Mathematically correct and OT-aligned

### Key Findings
1. **Risk scoring formula is correct** - All calculations verified
2. **OT weighting applied properly** - Availability (50%) > Integrity (30%) > Confidentiality (20%)
3. **Scores bounded correctly** - All scores between 0.0 and 10.0
4. **Risk tiers assigned correctly** - CRITICAL ≥8.0, HIGH ≥6.0, MEDIUM ≥4.0, LOW ≥0.0

## Adding New Tests

### 1. Unit Tests
Place new unit test files in `unit_tests/` directory:
- Test individual functions and classes
- Use descriptive names (e.g., `test_policy_predictor.py`)
- Follow the pattern in `test_risk_scoring.py`

### 2. Integration Tests
Place integration tests in `integration_tests/` directory:
- Test interactions between components
- Test full pipelines and workflows
- Use real or simulated data

### 3. Data Validation
Place data validation scripts in `test_data/` directory:
- Validate data structures and formats
- Check data quality and consistency
- Verify database schemas

## Test Coverage

### Currently Tested Components
- ✅ Risk scoring formula (`CVE_Pipeline/risk_scorer.py`)
- ✅ Policy dataset structure
- ✅ Policy database tables
- ✅ Model feature expectations

### Components Needing Tests
- ⬜ Policy compliance predictor
- ⬜ CVE mapper
- ⬜ Database ingestor
- ⬜ Flask API endpoints
- ⬜ Dashboard templates

## Continuous Testing

### Manual Testing
```bash
# Run the full test suite
python Testing/run_tests.py --all

# Check specific component
python Testing/run_tests.py --unit
```

### Test Automation (Future)
- Add to CI/CD pipeline
- Run on code changes
- Generate automated reports
- Track test coverage

## Troubleshooting

### Common Issues

1. **Import errors when running tests**
   ```bash
   # Run from project root directory
   cd CAVE-OT\ Datasets_KIRO\CAVE-OT\ Datasets
   python Testing/run_tests.py
   ```

2. **Missing test data files**
   - Ensure `Assets/vulnerability_scan_results.json` exists
   - Ensure `Datasets/policy_dataset.csv` exists
   - Run the pipeline to generate test data if needed

3. **Database connection errors**
   - Ensure PostgreSQL is running
   - Verify database credentials in test files
   - Check if policy tables exist

### Getting Help
- Check test output for specific error messages
- Review the test reports in `reports/` directory
- Verify test data files exist and are accessible

## Best Practices

1. **Write tests before fixing bugs** - Reproduce the bug in a test first
2. **Test edge cases** - Include boundary values and error conditions
3. **Use real data** - Validate with actual system data when possible
4. **Keep tests independent** - Each test should run independently
5. **Document test results** - Update reports after significant changes

## Contributing

When adding new features to CAVE-OT:
1. Add corresponding tests in the appropriate directory
2. Run the test suite to ensure nothing breaks
3. Update test documentation if needed
4. Generate new test reports for significant changes