# CAVE-OT File Manifest

Complete listing of all files in the ML pipeline with descriptions.

## Core Pipeline Scripts

| File | Purpose | When to Run |
|------|---------|-------------|
| model_trainer.py | Train TF-IDF models | Once during setup |
| cve_mapper.py | Map devices to CVEs | Every scan |
| risk_scorer.py | Calculate risk scores | Every scan |

## Utility Scripts

| File | Purpose |
|------|---------|
| test_pipeline.py | Test with sample devices |
| check_setup.py | Verify installation |
| run_pipeline.bat | Windows batch runner |

## Configuration Files

| File | Purpose |
|------|---------|
| requirements.txt | Python dependencies |
| model_input.json | Sample input data |

## Documentation

| File | Content |
|------|---------|
| README.md | Quick start guide |
| SETUP_GUIDE.md | Detailed setup instructions |
| FORMULAS.md | Mathematical reference |
| QUICKSTART.txt | One-page quick start |
| PIPELINE_FLOW.txt | Visual flow diagram |
| PROJECT_SUMMARY.md | Project overview |
| FILE_MANIFEST.md | This file |

## Input Datasets (Required)

Location: `D:\Downloads\CAVE-OT Datasets\`

| File | Rows | Description |
|------|------|-------------|
| training_ready.csv | 206,553 | General CVE dataset |
| ot_training_ready.csv | 5,991 | OT/ICS CVE dataset |

## Model Files (Generated)

Location: `D:\Downloads\CAVE-OT Datasets\model\`

| File | Size | Description |
|------|------|-------------|
| general_vectorizer.pkl | ~50 MB | TF-IDF vectorizer (general) |
| general_matrix.pkl | ~400 MB | TF-IDF matrix (206k × 50k) |
| cve_database.pkl | ~100 MB | Full CVE dataframe |
| ot_vectorizer.pkl | ~50 MB | TF-IDF vectorizer (OT) |
| ot_matrix.pkl | ~20 MB | TF-IDF matrix (6k × 50k) |
| ot_cve_database.pkl | ~3 MB | OT CVE dataframe |

## File Dependencies

```
model_trainer.py
├── requires: training_ready.csv
├── requires: ot_training_ready.csv
└── creates: 6 model .pkl files

cve_mapper.py
├── requires: 6 model .pkl files
├── reads: model_input.json
└── writes: model_input.json (with CVEs)

risk_scorer.py
├── reads: model_input.json (with CVEs)
└── writes: model_input.json (with risk scores)
```

## Total Disk Space Required

- Datasets: ~150 MB
- Models: ~620 MB
- Scripts: <1 MB
- Total: ~770 MB
