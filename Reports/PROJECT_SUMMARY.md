> Historical summary: formula and standards attributions below are retired. Use [FORMULAS.md](FORMULAS.md) and the current README for cave-ot-3 behavior.

# CAVE-OT ML Pipeline - Project Summary

## What Was Built

Complete machine learning pipeline for CAVE-OT vulnerability management system with 3 core scripts and supporting documentation.

## Core Scripts

1. **model_trainer.py** - Two-stage TF-IDF training (206k + 6k CVEs)
2. **cve_mapper.py** - Runtime CVE similarity matching
3. **risk_scorer.py** - Contextual risk calculation with CVSS v3.1

## Algorithm

TF-IDF + Cosine Similarity for device-to-CVE mapping with version filtering and OT-specific fine-tuning.

## Risk Formula

CVSS v3.1 Environmental + NIST SP 800-82 CIA weighting + IEC 62443 asset criticality + Suricata alerts.

## Files Created

- model_trainer.py (training script)
- cve_mapper.py (CVE mapping)
- risk_scorer.py (risk scoring)
- requirements.txt (dependencies)
- test_pipeline.py (validation)
- check_setup.py (setup verification)
- run_pipeline.bat (Windows runner)
- README.md (quick start)
- SETUP_GUIDE.md (detailed setup)
- FORMULAS.md (mathematical reference)
- model_input.json (sample data)

## Usage

```bash
pip install -r requirements.txt
python model_trainer.py
python cve_mapper.py
python risk_scorer.py
```

## Output

JSON with CVEs sorted by contextual risk score (0-10) with tier classification (CRITICAL/HIGH/MEDIUM/LOW).
