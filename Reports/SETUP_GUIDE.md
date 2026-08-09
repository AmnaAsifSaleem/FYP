# CAVE-OT Setup Guide

Complete setup instructions for the CAVE-OT ML pipeline on Windows.

## Prerequisites

- Python 3.8 or higher
- Windows 10/11
- 8GB RAM minimum (16GB recommended)
- Datasets in `D:\Downloads\CAVE-OT Datasets\`

## Step-by-Step Setup

### Step 1: Verify Datasets

Ensure these files exist:

```
D:\Downloads\CAVE-OT Datasets\
├── training_ready.csv          (206,553 rows)
└── ot_training_ready.csv       (5,991 rows)
```

### Step 2: Install Python Dependencies

Open Command Prompt or PowerShell in the project directory:

```bash
pip install -r requirements.txt
```

This installs:
- pandas (data manipulation)
- numpy (numerical operations)
- scikit-learn (TF-IDF and similarity)
- joblib (model serialization)
- tqdm (progress bars)

### Step 3: Train the Models (One-Time Setup)

```bash
python model_trainer.py
```

**Expected output:**
- Training takes 5-10 minutes
- Creates 6 model files in `D:\Downloads\CAVE-OT Datasets\model\`
- Shows validation tests with sample queries
- Final message: "✓ TRAINING COMPLETE"

**Model files created:**
```
D:\Downloads\CAVE-OT Datasets\model\
├── general_vectorizer.pkl      (TF-IDF vectorizer - 206k CVEs)
├── general_matrix.pkl          (TF-IDF matrix - 206k × 50k)
├── cve_database.pkl            (Full CVE dataframe)
├── ot_vectorizer.pkl           (OT fine-tuned vectorizer)
├── ot_matrix.pkl               (OT TF-IDF matrix - 6k × 50k)
└── ot_cve_database.pkl         (OT CVE dataframe)
```

### Step 4: Test the Pipeline

Run the test script to verify everything works:

```bash
python test_pipeline.py
```

This creates sample devices and runs the full pipeline. You should see CVEs mapped to Schneider, Siemens, and Rockwell devices.

## Runtime Usage

### Option 1: Using the Batch Script (Recommended)

```bash
run_pipeline.bat
```

This automatically runs both scripts in sequence.

### Option 2: Manual Execution

```bash
python cve_mapper.py      # Maps devices to CVEs
python risk_scorer.py     # Calculates risk scores
```

### Option 3: Custom Input File

```bash
python cve_mapper.py custom_input.json
python risk_scorer.py custom_input.json
```

## Input File Format

Create `model_input.json` with this structure:

```json
[
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
  }
]
```

**Required fields:**
- `ip`, `port`, `service`, `device_type`, `zone`
- `vendor`, `product`, `firmware`

**Optional fields:**
- `alert_count` (default: 0)
- `alert_severity` (default: 3, range: 1-3)

## Output Format

After running the pipeline, `model_input.json` is updated with CVE data:

```json
[
  {
    "ip": "192.168.1.10",
    "vendor": "Schneider Electric",
    "product": "Modicon M340",
    "cves": [
      {
        "cve_id": "CVE-2019-10915",
        "cvss": 8.8,
        "epss": 0.021,
        "kev": 0,
        "c_impact": 0.22,
        "i_impact": 0.22,
        "a_impact": 0.56,
        "similarity": 0.94,
        "risk_score": 8.7,
        "risk_tier": "CRITICAL",
        "risk_emoji": "🔴"
      }
    ]
  }
]
```

CVEs are sorted by `risk_score` (highest first).

## Troubleshooting

### Error: "Models not found"

**Solution:** Run `python model_trainer.py` first

### Error: "training_ready.csv not found"

**Solution:** Verify datasets are in `D:\Downloads\CAVE-OT Datasets\`

### Error: "No module named 'sklearn'"

**Solution:** Run `pip install -r requirements.txt`

### Warning: "No CVEs found for device"

**Possible causes:**
- Vendor/product name doesn't match dataset
- Similarity threshold too high
- Firmware version outside affected range

**Solution:** Check vendor/product spelling, try lowering threshold in `cve_mapper.py`

### Training takes too long

**Normal:** 5-10 minutes on modern hardware
**If >20 minutes:** Check CPU usage, close other applications

## Performance Notes

- **Training:** One-time, 5-10 minutes
- **CVE Mapping:** ~1-2 seconds per device
- **Risk Scoring:** <1 second per device
- **Memory:** ~2GB during training, ~500MB at runtime

## Integration with discover.py

The full CAVE-OT workflow:

```
1. discover.py          → Scans network, creates model_input.json
2. cve_mapper.py        → Adds CVE list to each device
3. risk_scorer.py       → Calculates risk scores
4. Dashboard            → Displays results
```

Your scripts (cve_mapper.py and risk_scorer.py) read and write the same `model_input.json` file.

## Next Steps

After successful setup:

1. Integrate with `discover.py` network scanner
2. Connect to Suricata for live alert data
3. Build dashboard to visualize results
4. Set up automated scanning schedule

## Support

For issues or questions about the ML pipeline:
- Check validation tests in `model_trainer.py` output
- Run `test_pipeline.py` to verify setup
- Review `README.md` for algorithm details
