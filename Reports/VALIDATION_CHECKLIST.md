# CAVE-OT Validation Checklist

Use this checklist to verify your CAVE-OT ML pipeline is working correctly.

## Pre-Training Validation

- [ ] Python 3.8+ installed (`python --version`)
- [ ] All dependencies installed (`pip list | grep -E "pandas|numpy|sklearn|joblib|tqdm"`)
- [ ] training_ready.csv exists (206,553 rows)
- [ ] ot_training_ready.csv exists (5,991 rows)
- [ ] Dataset folder accessible: `D:\Downloads\CAVE-OT Datasets\`

## Training Validation

Run: `python model_trainer.py`

- [ ] Training completes without errors
- [ ] Takes 5-10 minutes (normal)
- [ ] Creates model folder: `D:\Downloads\CAVE-OT Datasets\model\`
- [ ] Creates 6 .pkl files (total ~620 MB)
- [ ] Shows validation test results
- [ ] Test 1 (Schneider M340) returns CVEs
- [ ] Test 2 (Siemens S7-300) returns CVEs
- [ ] Test 3 (Rockwell ControlLogix) returns CVEs
- [ ] Final message: "✓ TRAINING COMPLETE"

## CVE Mapper Validation

Run: `python test_pipeline.py` or `python cve_mapper.py`

- [ ] Loads models successfully
- [ ] Processes all devices
- [ ] Maps CVEs to each device
- [ ] Shows similarity scores (0.15-1.0)
- [ ] Filters by firmware version
- [ ] Updates model_input.json
- [ ] No Python errors or warnings

## Risk Scorer Validation

Run: `python risk_scorer.py`

- [ ] Reads model_input.json with CVEs
- [ ] Calculates risk scores (0.0-10.0)
- [ ] Assigns risk tiers (CRITICAL/HIGH/MEDIUM/LOW)
- [ ] Adds risk emojis (🔴🟠🟡🟢)
- [ ] Sorts CVEs by risk (highest first)
- [ ] Updates model_input.json
- [ ] Shows summary statistics

## Output Validation

Check `model_input.json` after full pipeline:

- [ ] Each device has "cves" array
- [ ] Each CVE has all required fields:
  - [ ] cve_id
  - [ ] cvss
  - [ ] epss
  - [ ] kev
  - [ ] c_impact, i_impact, a_impact
  - [ ] similarity
  - [ ] risk_score
  - [ ] risk_tier
  - [ ] risk_emoji
- [ ] CVEs sorted by risk_score (descending)
- [ ] Risk scores are reasonable (0.0-10.0)
- [ ] Risk tiers match scores:
  - [ ] CRITICAL: 8.0+
  - [ ] HIGH: 6.0-7.9
  - [ ] MEDIUM: 4.0-5.9
  - [ ] LOW: 0.0-3.9

## Functional Tests

### Test 1: Known OT Device

Input:
```json
{
  "vendor": "Schneider Electric",
  "product": "Modicon M340",
  "firmware": "2.39",
  "device_type": "PLC",
  "zone": "OT"
}
```

Expected:
- [ ] Finds multiple CVEs (>5)
- [ ] Top CVE has high similarity (>0.8)
- [ ] Risk scores reflect PLC criticality
- [ ] At least one CRITICAL or HIGH risk

### Test 2: Generic IT Device

Input:
```json
{
  "vendor": "Microsoft",
  "product": "Windows Server",
  "firmware": "2019",
  "device_type": "IT_Server",
  "zone": "IT"
}
```

Expected:
- [ ] Uses general model (not OT)
- [ ] Finds CVEs
- [ ] Risk scores lower than equivalent OT device
- [ ] Reflects lower asset criticality

### Test 3: Unknown Device

Input:
```json
{
  "vendor": "Unknown",
  "product": "Unknown",
  "firmware": "",
  "device_type": "Generic",
  "zone": "IT"
}
```

Expected:
- [ ] Handles gracefully (no crash)
- [ ] Returns empty CVE list or low-confidence matches
- [ ] No Python exceptions

### Test 4: Device with Suricata Alerts

Input:
```json
{
  "vendor": "Siemens",
  "product": "SIMATIC S7-300",
  "device_type": "PLC",
  "zone": "OT",
  "alert_count": 5,
  "alert_severity": 1
}
```

Expected:
- [ ] Risk scores higher than without alerts
- [ ] Suricata factor applied correctly
- [ ] More CRITICAL tier CVEs

## Performance Validation

- [ ] Training: 5-10 minutes
- [ ] CVE mapping: <2 seconds per device
- [ ] Risk scoring: <1 second per device
- [ ] Memory usage: <2GB during training
- [ ] Memory usage: <500MB at runtime

## Edge Cases

- [ ] Empty firmware field handled
- [ ] Missing alert_count defaults to 0
- [ ] Missing alert_severity defaults to 3
- [ ] No CVEs found returns empty array []
- [ ] Invalid version format handled gracefully
- [ ] Special characters in vendor/product handled

## Integration Validation

- [ ] model_input.json format matches discover.py output
- [ ] All fields preserved through pipeline
- [ ] JSON structure valid after each step
- [ ] Can be read by dashboard/frontend

## Final Checklist

- [ ] All scripts run without errors
- [ ] Output format matches specification
- [ ] Risk scores are contextually appropriate
- [ ] Documentation is clear and complete
- [ ] Test pipeline passes all checks
- [ ] Ready for production use

## Troubleshooting

If any checks fail:

1. Run `python check_setup.py` to diagnose
2. Check error messages in console output
3. Verify dataset paths and file permissions
4. Review SETUP_GUIDE.md for detailed instructions
5. Check FORMULAS.md for scoring algorithm details

## Sign-Off

- [ ] All validation checks passed
- [ ] Tested with real OT devices
- [ ] Output reviewed and approved
- [ ] Ready for integration with discover.py
- [ ] Documentation complete

**Validated by:** _______________  
**Date:** _______________  
**Version:** 1.0
