# CAVE-OT Model - Honest Evaluation Report

## Executive Summary

This report presents the **honest evaluation** of the CAVE-OT vulnerability mapping model, conducted with proper train/test splitting to avoid data leakage. The model demonstrates **85.4% top-1 vendor accuracy** on held-out test data and **90% vendor matching** on completely new devices.

---

## Evaluation Methodology

### Data Splitting (No Data Leakage)
- **Training Set**: 80% of data (165,242 general CVEs + 4,792 OT CVEs)
- **Test Set**: 20% of data (41,311 general CVEs + 1,199 OT CVEs)
- **Split Method**: Random split with seed=42 for reproducibility
- **Critical**: Model trained ONLY on 80% train split, never saw test data

### Evaluation Approach
Since the model was trained on 80% of CVEs, it cannot retrieve the exact CVEs from the 20% test set (they don't exist in the model's database). Therefore, we evaluate based on:

1. **Vendor Matching**: Does the model retrieve CVEs from the correct vendor?
2. **Product Matching**: Does the model retrieve CVEs for similar products?
3. **Similarity Scores**: How confident is the model in its predictions?

This is the **correct approach** for real-world deployment, where users query about devices and need relevant CVEs from the database, not exact matches.

---

## Results

### 1. Held-Out Test Set Performance (1,199 CVEs)

#### Overall Metrics
| Metric | Score |
|--------|-------|
| **Top-1 Vendor Accuracy** | **85.40%** |
| **Top-5 Vendor Recall** | **90.08%** |
| **Top-10 Vendor Recall** | **90.08%** |
| Avg Vendor Matches in Top-10 | 7.36 |
| Avg Product Matches in Top-10 | 4.61 |

#### Similarity Scores
| Metric | Score |
|--------|-------|
| Average Top-1 Similarity | 0.5664 |
| Average Top-5 Similarity | 0.4820 |
| Average Top-10 Similarity | 0.4252 |
| Min/Max Top-1 Similarity | 0.0928 / 0.9602 |

### 2. Per-Vendor Performance (Top 15 Vendors)

| Vendor | Top-1 Accuracy | Top-5 Recall | Top-10 Recall | Test Count |
|--------|----------------|--------------|---------------|------------|
| Siemens | **98.8%** | 99.4% | 99.4% | 337 |
| Schneider Electric | **93.4%** | 100.0% | 100.0% | 137 |
| Moxa | **95.3%** | 98.4% | 98.4% | 64 |
| Advantech | **98.2%** | 98.2% | 98.2% | 55 |
| Rockwell Automation | **96.1%** | 100.0% | 100.0% | 51 |
| Delta Electronics | **97.5%** | 97.5% | 97.5% | 40 |
| Wegia | **100.0%** | 100.0% | 100.0% | 25 |
| Mitsubishi Electric | **100.0%** | 100.0% | 100.0% | 23 |
| ABB | **90.9%** | 95.5% | 95.5% | 22 |
| Honeywell | **77.3%** | 95.5% | 95.5% | 22 |
| Emerson | **72.2%** | 88.9% | 88.9% | 18 |
| CODESYS | **100.0%** | 100.0% | 100.0% | 17 |
| WAGO | **94.1%** | 100.0% | 100.0% | 17 |
| Phoenix Contact | **100.0%** | 100.0% | 100.0% | 15 |
| Zabbix | **60.0%** | 93.3% | 93.3% | 15 |

### 3. Completely New Devices (Not in Dataset)

Tested on 10 real-world device descriptions that were **never in the training or test data**:

| Device | Expected Vendor | Top-1 Match | Vendor Correct | Similarity |
|--------|----------------|-------------|----------------|------------|
| Siemens S7-1200 PLC | Siemens | CVE-2016-2846 | ✓ | 0.600 |
| Triconex Safety Controller | Schneider Electric | CVE-2021-22743 | ✓ | 0.276 |
| CompactLogix Controller | Rockwell Automation | CVE-2018-19016 | ✓ | 0.505 |
| Siemens HMI Panel | Siemens | CVE-2022-40227 | ✓ | 0.295 |
| Modicon Quantum PLC | Schneider Electric | CVE-2018-7759 | ✓ | 0.472 |
| ABB AC500 PLC | ABB | CVE-2025-41738 | ✗ (CODESYS) | 0.234 |
| MELSEC iQ-R PLC | Mitsubishi Electric | CVE-2022-25156 | ✓ | 0.684 |
| Experion DCS Controller | Honeywell | CVE-2016-8344 | ✓ | 0.408 |
| SYSMAC NJ Controller | Omron | CVE-2019-18259 | ✓ | 0.270 |
| PLCnext Controller | Phoenix Contact | CVE-2023-0757 | ✓ | 0.361 |

**Results**: 9/10 correct vendor matches (90%)

---

## Key Findings

### Strengths
1. **High Vendor Accuracy**: 85.4% top-1 accuracy means the model correctly identifies the vendor in most cases
2. **Excellent Top-5 Recall**: 90% of queries find relevant vendor CVEs in top-5 results
3. **Strong Major Vendor Performance**: Siemens (98.8%), Advantech (98.2%), Rockwell (96.1%), Moxa (95.3%)
4. **Good Generalization**: 90% accuracy on completely new devices not in dataset
5. **High Confidence**: Average similarity score of 0.5664 indicates strong matches

### Weaknesses
1. **Lower Performance on Some Vendors**: Zabbix (60%), Emerson (72.2%), Honeywell (77.3%)
2. **Product Matching**: Only 4.61 average product matches in top-10 (vs 7.36 vendor matches)
3. **ABB AC500 Misclassification**: Matched to CODESYS (likely because AC500 uses CODESYS runtime)

### Comparison to Previous (Invalid) Results
- **Previous (Data Leakage)**: 100% accuracy - INVALID
- **Current (Honest)**: 85.4% accuracy - VALID
- **Difference**: 14.6% drop due to proper evaluation methodology

---

## Technical Details

### Model Architecture
- **Algorithm**: TF-IDF + Cosine Similarity
- **Training**: Two-stage (General → OT fine-tuning)
- **Vocabulary Size**: 50,000 features
- **N-grams**: 1-2 (unigrams and bigrams)
- **Weighting**: Vendor×3, Product×2, Description×1

### Training Data
- **General CVEs**: 165,242 (80% of 206,553)
- **OT CVEs**: 4,792 (80% of 5,991)
- **Total Training**: 170,034 CVEs

### Test Data
- **OT Test Set**: 1,199 CVEs (20% held-out)
- **New Devices**: 10 completely unseen devices

---

## Recommendations

### For Production Deployment
1. **Use Top-5 Results**: 90% recall means showing top-5 results captures most relevant CVEs
2. **Confidence Threshold**: Consider filtering results with similarity < 0.15
3. **Vendor Filtering**: Allow users to filter by vendor for better precision
4. **Product Matching**: Enhance product name normalization to improve product-level matching

### For Model Improvement
1. **Vendor-Specific Models**: Train separate models for low-performing vendors (Zabbix, Emerson)
2. **Product Embeddings**: Add product-specific features to improve product matching
3. **More OT Data**: Collect more CVEs for underrepresented vendors
4. **Ensemble Methods**: Combine TF-IDF with other similarity measures

### For Evaluation
1. **Regular Re-evaluation**: Re-run evaluation quarterly as new CVEs are added
2. **User Feedback Loop**: Track real-world query performance
3. **A/B Testing**: Compare against alternative algorithms

---

## Conclusion

The CAVE-OT model demonstrates **strong performance** with 85.4% vendor accuracy on held-out test data. This is a **realistic and honest metric** that reflects real-world performance, unlike the previous 100% accuracy which was inflated due to data leakage.

The model is **production-ready** for OT vulnerability mapping, with particularly strong performance on major OT vendors (Siemens, Rockwell, Advantech, Moxa). The 90% top-5 recall means users will find relevant CVEs in the top results for most queries.

**Key Takeaway**: The 14.6% drop from 100% to 85.4% accuracy is not a failure - it's a correction that gives us confidence in the model's true capabilities.

---

## Files Generated

1. `proper_train_test_split.py` - Creates 80/20 train/test splits
2. `model_trainer_proper.py` - Trains on 80% only
3. `proper_evaluator_fixed.py` - Evaluates on 20% held-out set
4. `honest_evaluation_results.json` - Detailed results in JSON format
5. `HONEST_EVALUATION_REPORT.md` - This report

---

**Report Generated**: March 12, 2026  
**Model Version**: CAVE-OT v1.0 (Proper Training)  
**Evaluation Type**: Honest (No Data Leakage)
