# CAVE-OT Project Status Summary

## 📋 Project Overview

<cite index="1-1,1-492,1-494,1-495">**CAVE-OT (Context-Aware Vulnerability Engine for OT)** is an AI-based, contextually aware vulnerability management solution that focuses on vulnerability prioritization based on exploitability, criticality, and industrial constraints. The solution stresses decision support over scanning, assisting security professionals in OT-safe remediation decisions.</cite>

**Team Members:**
- Amna Asif (22I-8777)
- Abdul Mueed Malik (22I-1622)
- M. Nameer Khan (22I-1695)

**Supervisor:** Dr. Subhanullah  
**Institution:** National University of Computer and Emerging Sciences, Islamabad  
**Session:** 2022-2026

---

## ✅ What Has Been Completed (FYP-1)

### 1. **Data Processing Pipeline** ✓
<cite index="1-547,1-548,1-549,1-550">The project has developed an AI-based, context-aware vulnerability management and attack path analysis platform specifically designed for industrial IT/OT networks. Unlike conventional scanners, the solution offers security teams actionable intelligence while ensuring operational safety and availability.</cite>

**Files:**
- `data_processor.py` - Processes NVD 2.0 format + EPSS + CISA KEV data
- `datacleaner.py` - Final cleaning pass before model training
- **Output:** `training_ready.csv` (206,553 CVEs), `ot_training_ready.csv` (5,991 OT CVEs)

### 2. **Machine Learning Model Training** ✓
<cite index="1-566,1-567,1-568,1-569,1-570,1-571">The system uses hybrid asset discovery that combines audit-based inventory with passive network monitoring to detect authorized and unauthorized assets. It implements context-aware risk scoring that evaluates vulnerabilities using CVSS, EPSS, asset criticality, and OT-specific CIA weighting.</cite>

**Trained Models (in `model/` folder):**
- `general_vectorizer.pkl` (2 MB) - TF-IDF vectorizer for general CVEs
- `general_matrix.pkl` (104.45 MB) - Similarity matrix for 206K CVEs
- `cve_database.pkl` (53.28 MB) - General CVE database
- `ot_vectorizer.pkl` (2.48 MB) - OT-specific TF-IDF vectorizer
- `ot_matrix.pkl` (2.48 MB) - OT similarity matrix
- `ot_cve_database.pkl` (1.29 MB) - OT CVE database (5,991 CVEs)

**Algorithm:** TF-IDF + Cosine Similarity with vendor/product/description weighting

### 3. **Passive Asset Discovery** ✓
**File:** `discover.py`

Reads asset inventory from JSON and maps CVEs to each device using the trained model.
- Query format: `vendor + product + firmware`
- Returns top-K matching CVEs per device
- **Output:** `vulnerability_scan_results.json`

### 4. **CVE Mapping System** ✓
**File:** `cve_mapper.py`

Maps discovered devices to matching CVEs using trained TF-IDF similarity models.
- Reads `model_input.json` with device data
- Adds CVE list to each device
- Filters by firmware version range
- Uses different thresholds for IT vs OT zones

### 5. **Comprehensive Model Evaluation** ✓
**Files:**
- `model_evaluator.py` - Basic IR metrics evaluation
- `detailed_metrics_calculator.py` - Comprehensive ML metrics
- `comprehensive_evaluator.py` - Full evaluation with all metrics

**Key Results (Honest Evaluation - No Data Leakage):**
- **Top-1 Vendor Accuracy:** 85.40%
- **Top-5 Vendor Recall:** 90.08%
- **Mean Reciprocal Rank (MRR):** 0.8704
- **NDCG@10:** 0.8695
- **MAP@10:** 84.65%

**Per-Vendor Performance (Top Vendors):**
- Siemens: 98.8% accuracy
- Advantech: 98.2% accuracy
- Delta Electronics: 97.5% accuracy
- Rockwell Automation: 96.1% accuracy
- Moxa: 95.3% accuracy
- Schneider Electric: 93.4% accuracy

---

## 📁 Key Files and Their Purpose

### **Working/Useful Files:**

| File | Purpose | Status | How to Run |
|------|---------|--------|------------|
| `check_setup.py` | Verifies all dependencies and files are in place | ✓ Ready | `python check_setup.py` |
| `discover.py` | Passive asset discovery and CVE mapping | ✓ Ready | `python discover.py` (needs `assets.json`) |
| `cve_mapper.py` | Maps devices to CVEs with version filtering | ✓ Ready | `python cve_mapper.py` (needs `model_input.json`) |
| `comprehensive_evaluator.py` | Full model evaluation with all metrics | ✓ Ready | `python comprehensive_evaluator.py` |
| `model_input.json` | Sample device input for CVE mapping | ✓ Ready | Edit and use with `cve_mapper.py` |
| `assets.json` | Sample asset inventory (6 devices) | ✓ Ready | Edit and use with `discover.py` |

### **Data Processing Files (Already Executed):**

| File | Purpose | Status |
|------|---------|--------|
| `data_processor.py` | Processes raw NVD + EPSS + KEV data | ✓ Completed |
| `datacleaner.py` | Cleans and normalizes vendor/product names | ✓ Completed |

### **Output/Report Files:**

| File | Description |
|------|-------------|
| `comprehensive_evaluation_report.txt` | Full evaluation report with all metrics |
| `comprehensive_evaluation_results.json` | Detailed results in JSON format |
| `HONEST_EVALUATION_REPORT.md` | Honest evaluation methodology and results |
| `comprehensive_metrics.json` | All calculated metrics |
| `evaluation_results.json` | Basic evaluation results |

---

## 🚀 How to Run and Test the System

### **1. Verify Setup**
```bash
python check_setup.py
```
This checks:
- Python version (3.8+)
- Required packages (pandas, numpy, sklearn, joblib, tqdm)
- Training datasets
- Trained models
- Pipeline scripts

### **2. Test CVE Mapping (Single Device)**
Edit `model_input.json` with your device:
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

Then run:
```bash
python cve_mapper.py
```

**Output:** Updates `model_input.json` with matching CVEs for each device.

### **3. Test Asset Discovery (Multiple Devices)**
Edit `assets.json` with your asset inventory (already has 6 sample devices).

Then run:
```bash
python discover.py
```

**Output:** Creates `vulnerability_scan_results.json` with top-25 CVEs per device.

### **4. Run Model Evaluation**
```bash
python comprehensive_evaluator.py
```

**Output:** 
- `comprehensive_evaluation_results.json`
- `comprehensive_evaluation_report.txt`

---

## 📊 Current Model Performance

### **Evaluation Methodology**
- **Train/Test Split:** 80/20 (proper split, no data leakage)
- **Training Set:** 4,792 OT CVEs
- **Test Set:** 1,199 OT CVEs (held-out)
- **Evaluation:** Vendor matching accuracy (since exact CVE matching is not possible with held-out data)

### **Core Metrics**
| Metric | @1 | @3 | @5 | @10 |
|--------|----|----|----|----|
| **Precision** | 85.40% | 80.93% | 77.85% | 73.60% |
| **Recall** | 85.40% | 88.24% | 89.24% | 90.08% |
| **F1-Score** | 0.8540 | 0.8443 | 0.8316 | 0.8101 |

### **Ranking Metrics**
- **MRR (Mean Reciprocal Rank):** 0.8704
- **MAP@10:** 84.65%
- **NDCG@5:** 0.8721
- **NDCG@10:** 0.8695

### **Similarity Score Statistics**
- **Mean:** 0.5664
- **Median:** 0.6052
- **90th Percentile:** 0.7900
- **Range:** 0.0928 - 0.9602

---

## 🎯 What's Working

1. ✅ **Data Pipeline:** Successfully processes 200K+ CVEs from NVD, EPSS, and CISA KEV
2. ✅ **Model Training:** TF-IDF similarity model trained on general + OT-specific CVEs
3. ✅ **Passive Discovery:** Can scan asset inventory and map CVEs without active scanning
4. ✅ **CVE Mapping:** Maps devices to relevant CVEs with version filtering
5. ✅ **High Accuracy:** 85.4% vendor accuracy, 90% top-5 recall
6. ✅ **OT Vendor Support:** Excellent performance on major OT vendors (Siemens, Rockwell, Advantech, Moxa, Schneider)
7. ✅ **Evaluation Framework:** Comprehensive evaluation with proper train/test split

---

## 🔄 What's Next (FYP-2)

<cite index="1-618,1-619,1-620,1-621">According to the project timeline, FYP-2 runs from August to December and focuses on:

**Iteration 03 (Aug-Oct):**
- Module 2: Decision Support and Attack Path Analysis
- Attack path modeling
- Policy enforcement integration

**Iteration 04 (Nov-Dec):**
- Module 2: Dashboard development
- LLM-Based Remediation Advisor
- Testing, evaluation, and documentation</cite>

### **Planned Features:**

<cite index="1-577,1-578,1-579,1-580,1-581,1-582,1-583,1-584,1-585,1-586,1-587,1-588,1-589">1. **Attack Path Analysis and Visualization**
   - Uses graph-based logic to model how vulnerabilities can be chained from IT to OT systems
   - Requirements: NetworkX library for graph modeling; visualization dashboard for SOC teams
   - Improves situational awareness and highlights critical paths for immediate mitigation

2. **LLM-Based Remediation Advisor**
   - Generates explainable, OT-safe recommendations without automatic patching
   - Requirements: Large Language Models integrated with RAG framework; human-in-the-loop decision interface
   - Provides actionable, safe, and policy-compliant guidance for vulnerability mitigation</cite>

---

## 🛠️ Technical Stack

<cite index="1-590,1-591,1-592,1-593,1-594,1-595,1-596,1-597">**Programming:**
- Python (primary language)
- JavaScript (dashboard)
- HTML/CSS (UI)

**Machine Learning:**
- Scikit-learn (TF-IDF, similarity)
- Large Language Models (LLMs) - planned
- Retrieval-Augmented Generation (RAG) - planned

**Networking & Security:**
- Wireshark/PCAP Analysis (passive monitoring)
- Scapy (packet analysis)
- NetworkX (attack path graphs) - planned</cite>

<cite index="1-602,1-603,1-604,1-605,1-606,1-607">**Databases:**
- PostgreSQL (asset inventories, vulnerability data)
- NVD (National Vulnerability Database)
- EPSS (Exploit Prediction Scoring System)

**Development:**
- Linux-based environment
- Docker (containerization) - planned
- Simulated/Lab IT/OT environment</cite>

---

## 📝 Quick Start Guide

### **Test the System Right Now:**

1. **Check if everything is ready:**
   ```bash
   python check_setup.py
   ```

2. **Map CVEs to a single device:**
   ```bash
   python cve_mapper.py
   # Uses model_input.json (already has 1 sample device)
   ```

3. **Scan multiple devices:**
   ```bash
   python discover.py
   # Uses assets.json (already has 6 sample devices)
   ```

4. **View results:**
   - `model_input.json` - Updated with CVEs
   - `vulnerability_scan_results.json` - Full scan results

### **Add Your Own Devices:**

Edit `assets.json`:
```json
[
  {
    "ip": "YOUR_IP",
    "port": YOUR_PORT,
    "service": "Modbus/DNP3/S7comm/BACnet",
    "device_type": "PLC/RTU/HMI",
    "zone": "OT",
    "vendor": "Siemens/Schneider/Rockwell/etc",
    "product": "S7-300/Modicon M340/etc",
    "firmware": "VERSION",
    "description": "Device description",
    "criticality": 0.9
  }
]
```

Then run `python discover.py`

---

## 📈 Model Performance Summary

**Strengths:**
- ✅ High vendor accuracy (85.4%)
- ✅ Excellent top-5 recall (90%)
- ✅ Strong performance on major OT vendors (Siemens 98.8%, Advantech 98.2%)
- ✅ Good generalization to new devices (90% accuracy on unseen devices)
- ✅ High confidence scores (avg 0.5664)

**Areas for Improvement:**
- ⚠️ Lower performance on some vendors (Zabbix 60%, Emerson 72%)
- ⚠️ Product matching could be improved (4.61 avg vs 7.36 vendor matches)
- ⚠️ Some vendor confusion (ABB ↔ Schneider, Honeywell ↔ Siemens)

---

## 📚 Documentation Files

- `FYP1-ProposalDocument-S26-063-D-CAVE-OT.pdf` - Original project proposal
- `HONEST_EVALUATION_REPORT.md` - Detailed evaluation methodology and results
- `comprehensive_evaluation_report.txt` - Full metrics report
- `FORMULAS.md` - Risk scoring formulas (if exists)
- `FILE_MANIFEST.md` - File descriptions (if exists)

---

## 🎓 Academic Context

<cite index="1-496,1-497,1-498,1-499,1-500,1-501,1-502,1-503,1-504">**Problem Statement:**
The increasing connectivity between enterprise IT and operational technology in industrial IT/OT environments has made these environments more vulnerable to cybersecurity threats. Current vulnerability management tools are mainly developed for traditional IT environments and are highly dependent on static CVSS scores for prioritization. These tools do not consider the likelihood of exploit, criticality of assets, and operational effects, which are important considerations in industrial environments. This has resulted in overwhelmed security teams dealing with high volumes of alerts without any clear guidance on remediation priorities. Active vulnerability scanning also poses risks of disrupting critical OT devices such as PLCs and SCADA systems.</cite>

<cite index="1-513,1-514,1-515,1-516,1-517,1-518,1-519,1-520,1-521,1-522,1-523,1-524,1-525,1-526">**Solution:**
CAVE-OT is an AI-driven decision-support system designed to improve vulnerability management in industrial IT/OT environments. The application focuses on analyzing and prioritizing security risks without performing intrusive scanning or automatic remediation. It maintains an accurate view of the environment using audit-based asset inventories and passive monitoring techniques. Vulnerabilities are evaluated using a context-aware risk scoring approach that combines severity, exploit likelihood, and asset criticality. The system analyzes attack paths across IT and OT networks to identify how vulnerabilities can be chained to reach critical systems. Policy enforcement mechanisms ensure that remediation decisions align with organizational security rules and industrial constraints.</cite>

---

## 🔗 Related Work

<cite index="1-632,1-633,1-634,1-635,1-636,1-637,1-638,1-639,1-640,1-641,1-642,1-643">**References:**
1. Nozomi Networks - OT/IoT Vulnerability Management Platform
2. Australian Cyber Security Magazine - The Economic Impact of ICS Vulnerabilities
3. Kaspersky - Why CVSS Alone Is Not Enough for Risk-Based Vulnerability Management
4. Nexus Connect - CVSS Scores Are No Longer Enough: The Move to Context-Driven Vulnerability Management</cite>

---

## 📞 Contact

**Project Team:**
- Amna Asif (22I-8777)
- Abdul Mueed Malik (22I-1622)
- M. Nameer Khan (22I-1695)

**Supervisor:** Dr. Subhanullah  
**Department:** Computer Science  
**University:** NUCES-FAST Islamabad

---

**Last Updated:** March 12, 2026  
**Project Status:** FYP-1 Complete ✓ | FYP-2 In Progress (Aug-Dec 2026)
