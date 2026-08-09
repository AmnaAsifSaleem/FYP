# Policy Compliance Model — Evaluation Report

**Model:** Random Forest Classifier  
**Task:** Predict policy compliance status for OT/IT network assets  
**Report Generated:** May 2026  

---

## 1. Dataset Overview

| Property | Value |
|---|---|
| Total samples | 3,000 |
| Features | 16 (4 categorical + 12 numerical) |
| Training set | 2,400 samples (80%) |
| Test set | 600 samples (20%) |
| Split strategy | Stratified random split, seed=42 |

### Class Distribution

| Class | Count | % of Dataset |
|---|---|---|
| NON_COMPLIANT | 2,306 | 76.9% |
| COMPLIANT | 667 | 22.2% |
| NEEDS_REVIEW | 27 | 0.9% |

> Note: NEEDS_REVIEW samples are treated as NON_COMPLIANT (class 0) during training. The dataset is imbalanced — `class_weight='balanced'` is applied to compensate.

---

## 2. Model Configuration

**Algorithm:** Random Forest Classifier (scikit-learn)

| Hyperparameter | Value | Rationale |
|---|---|---|
| n_estimators | 200 | More trees = more stable predictions |
| max_depth | 15 | Allows complex decision boundaries |
| min_samples_split | 5 | Prevents overly specific splits |
| min_samples_leaf | 2 | Minimum leaf size for generalization |
| max_features | sqrt | Reduces correlation between trees |
| bootstrap | True | Standard bagging |
| class_weight | balanced | Handles class imbalance |
| random_state | 42 | Reproducibility |

---

## 3. Test Set Performance

Evaluated on 600 held-out samples never seen during training.

### Overall Metrics

| Metric | Score |
|---|---|
| Accuracy | **95.50%** |
| AUC-ROC | **98.63%** |
| Precision (COMPLIANT) | **94.17%** |
| Recall (COMPLIANT) | **84.96%** |
| F1-Score (COMPLIANT) | **89.33%** |

### Per-Class Classification Report

| Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| NON_COMPLIANT | 0.96 | 0.99 | 0.97 | 467 |
| COMPLIANT | 0.94 | 0.85 | 0.89 | 133 |
| **Macro avg** | **0.95** | **0.92** | **0.93** | 600 |
| **Weighted avg** | **0.95** | **0.95** | **0.95** | 600 |

### Confusion Matrix

```
                  Predicted
                  NON_COMPLIANT   COMPLIANT
Actual  NON_COMPLIANT     460           7
        COMPLIANT          20         113
```

| | Value |
|---|---|
| True Negatives (TN) | 460 — correctly identified NON_COMPLIANT |
| False Positives (FP) | 7 — NON_COMPLIANT wrongly marked COMPLIANT |
| False Negatives (FN) | 20 — COMPLIANT wrongly marked NON_COMPLIANT |
| True Positives (TP) | 113 — correctly identified COMPLIANT |

> The 7 false positives are the most security-critical errors — assets that are actually non-compliant but the model clears them. At 1.5% of the test set, this is within acceptable bounds for a security advisory tool.

---

## 4. Cross-Validation Results

5-fold stratified cross-validation on the training set (2,400 samples).

| Fold | Accuracy |
|---|---|
| Fold 1 | 93.96% |
| Fold 2 | 92.92% |
| Fold 3 | 93.75% |
| Fold 4 | 90.63% |
| Fold 5 | 91.88% |
| **Mean** | **92.62%** |
| **Std Dev** | **±1.24%** |

The 2.88% gap between CV mean (92.62%) and test accuracy (95.50%) is within normal variance. Low standard deviation (±1.24%) confirms the model is stable across different data splits.

---

## 5. Confidence Score Analysis

Confidence = probability of the predicted class (always ≥ 0.5).

| Metric | Value |
|---|---|
| Mean confidence | 0.859 |
| Minimum confidence | 0.503 |
| Maximum confidence | 1.000 |
| High confidence predictions (≥ 0.80) | 433 / 600 (72.2%) |
| Low confidence predictions (< 0.60) | 42 / 600 (7.0%) |

72% of predictions are made with ≥ 80% confidence. The 42 low-confidence predictions (< 0.60) are the candidates most suitable for NEEDS_REVIEW escalation — a gap in the current implementation.

---

## 6. Feature Importance

Ranked by mean decrease in impurity across all 200 trees.

| Rank | Feature | Importance | Interpretation |
|---|---|---|---|
| 1 | zone | 19.06% | OT/SCADA/DMZ/IT zone is the strongest compliance signal |
| 2 | encrypted | 14.29% | Whether communication is encrypted |
| 3 | firmware_eol | 11.02% | End-of-life firmware is a strong non-compliance indicator |
| 4 | service | 10.76% | Protocol type (Modbus, HTTP, SSH, etc.) |
| 5 | port | 8.22% | Port number (high-risk ports: 80, 21, 135, 445, 161) |
| 6 | days_since_patch | 4.80% | Patch age (NERC CIP-007-6 threshold: 35 days) |
| 7 | cvss | 4.66% | Base vulnerability severity |
| 8 | criticality | 4.38% | Asset criticality weight |
| 9 | epss | 3.58% | Exploit probability |
| 10 | i_impact | 3.29% | Integrity impact |
| 11 | device_type | 3.23% | PLC, RTU, HMI, SCADA, etc. |
| 12 | a_impact | 2.99% | Availability impact |
| 13 | c_impact | 2.89% | Confidentiality impact |
| 14 | kev | 2.55% | CISA Known Exploited Vulnerability flag |
| 15 | vendor | 2.31% | Device manufacturer |
| 16 | alert_count | 1.96% | Number of Suricata IDS alerts |

Top 3 features (zone, encrypted, firmware_eol) account for **44.4%** of total importance. This aligns with the underlying policy rules — zone segmentation and encryption are the primary compliance drivers in NIST SP 800-82r3 and CISA DiD.

---

## 7. Compliance Standards Alignment

The model was trained on labels generated by rule-based logic derived from:

| Standard | Coverage |
|---|---|
| NIST SP 800-82 Rev 3 | Zone segmentation, encryption, protocol restrictions |
| NERC CIP-007-6 | Patch management (35-day threshold), port/service control |
| CISA Defense-in-Depth | High-risk port flagging, active exploitation alerts |
| CISA KEV Catalog | Known exploited vulnerability detection |

---

## 8. Limitations

- **Dataset is synthetically generated** from deterministic rules — real-world assets may exhibit edge cases not represented in training data
- **NEEDS_REVIEW class** (27 samples, 0.9%) is collapsed into NON_COMPLIANT; a dedicated third-class model would improve nuance
- **Low-confidence predictions** (42 samples, 7%) are not automatically escalated to NEEDS_REVIEW in the current implementation
- **Vendor coverage**: 26 vendors in training data; unseen vendors fall back to closest match via string similarity
- **Static features**: `days_since_patch`, `firmware_eol`, and `alert_count` use default values when live data is unavailable, which may reduce prediction accuracy

---

## 9. Summary

The policy compliance model achieves **95.5% accuracy** and **98.6% AUC-ROC** on the held-out test set, with stable cross-validation performance (92.6% ± 1.2%). The model correctly identifies 99% of non-compliant assets and 85% of compliant ones. The primary compliance signals — network zone, encryption status, and firmware EOL — match the intent of the underlying NIST/NERC/CISA policy framework.

The model is suitable for automated compliance screening of OT/IT assets, with the recommendation that low-confidence predictions (< 0.60) be flagged for manual review before action is taken.
