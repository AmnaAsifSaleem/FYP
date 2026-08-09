"""
CAVE-OT Model Training and Evaluation
Single-pass TF-IDF training (NOT a neural network)
"""

import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.model_selection import train_test_split
import joblib
import json
import os
from collections import defaultdict
from datetime import datetime

DATASET_FOLDER = r"D:\Downloads\CAVE-OT Datasets"
MODEL_FOLDER = os.path.join(DATASET_FOLDER, "model")

os.makedirs(MODEL_FOLDER, exist_ok=True)

def build_corpus(df):
    """Build text corpus with weighted repetition"""
    texts = []
    for _, row in df.iterrows():
        vendor = str(row['vendor']) * 3
        product = str(row['product']) * 2
        desc = str(row['description'])
        texts.append(f'{vendor} {product} {desc}')
    return texts

print("="*80)
print("CAVE-OT MODEL TRAINING AND EVALUATION")
print("="*80)
print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

# ============================================================================
# STEP 1 — SPLIT ot_training_ready.csv ONLY
# ============================================================================
print("STEP 1: Split ot_training_ready.csv (80/20)")
print("-"*80)

df_ot = pd.read_csv(os.path.join(DATASET_FOLDER, 'ot_training_ready.csv'))
print(f"Loaded ot_training_ready.csv: {len(df_ot)} rows")

# Simple random split — NO stratify
ot_train, ot_test = train_test_split(
    df_ot,
    test_size=0.20,
    random_state=42
)

print(f"OT Train: {len(ot_train)} rows (80%)")
print(f"OT Test:  {len(ot_test)} rows (20%)")

ot_train.to_csv(os.path.join(DATASET_FOLDER, 'ot_train_split.csv'), index=False)
ot_test.to_csv(os.path.join(DATASET_FOLDER, 'ot_test_split.csv'), index=False)
print("✓ Saved: ot_train_split.csv")
print("✓ Saved: ot_test_split.csv")

# ============================================================================
# STEP 2 — STAGE 1: TRAIN ON training_ready.csv
# ============================================================================
print(f"\nSTEP 2: Stage 1 - Train on training_ready.csv")
print("-"*80)

df_full = pd.read_csv(os.path.join(DATASET_FOLDER, 'training_ready.csv'))
print(f"Loaded training_ready.csv: {len(df_full)} rows")

print("Building general corpus...")
general_corpus = build_corpus(df_full)

print("Training general TF-IDF vectorizer...")
general_vectorizer = TfidfVectorizer(
    analyzer='word',
    ngram_range=(1, 2),
    min_df=2,
    max_df=0.95,
    max_features=50000,
    sublinear_tf=True,
)

general_matrix = general_vectorizer.fit_transform(general_corpus)

joblib.dump(general_vectorizer, os.path.join(MODEL_FOLDER, 'general_vectorizer.pkl'))
joblib.dump(general_matrix, os.path.join(MODEL_FOLDER, 'general_matrix.pkl'))
joblib.dump(df_full, os.path.join(MODEL_FOLDER, 'cve_database.pkl'))

print(f"✓ Stage 1 done. Matrix: {general_matrix.shape}")
print(f"✓ Vocabulary size: {len(general_vectorizer.vocabulary_):,}")

# ============================================================================
# STEP 3 — STAGE 2: FINE-TUNE ON ot_train (80% only)
# ============================================================================
print(f"\nSTEP 3: Stage 2 - Fine-tune on ot_train (80% only)")
print("-"*80)

print("Building OT corpus...")
ot_corpus = build_corpus(ot_train)

print("Training OT TF-IDF vectorizer with general vocabulary...")
ot_vectorizer = TfidfVectorizer(
    analyzer='word',
    ngram_range=(1, 2),
    min_df=1,
    max_df=0.95,
    max_features=50000,
    sublinear_tf=True,
    vocabulary=general_vectorizer.vocabulary_
)

ot_matrix = ot_vectorizer.fit_transform(ot_corpus)

joblib.dump(ot_vectorizer, os.path.join(MODEL_FOLDER, 'ot_vectorizer.pkl'))
joblib.dump(ot_matrix, os.path.join(MODEL_FOLDER, 'ot_matrix.pkl'))
joblib.dump(ot_train, os.path.join(MODEL_FOLDER, 'ot_cve_database.pkl'))

print(f"✓ Stage 2 done. OT Matrix: {ot_matrix.shape}")

# ============================================================================
# STEP 4 — EVALUATE ON ot_test (20% only)
# ============================================================================
print(f"\nSTEP 4: Evaluate on ot_test (20% held-out)")
print("-"*80)
print(f"Test set size: {len(ot_test)} CVEs (NEVER seen during training)")

hits_at_1 = []
hits_at_5 = []
hits_at_10 = []
reciprocal_ranks = []
top1_similarities = []
vendor_results = defaultdict(lambda: {'hits_1': [], 'hits_5': [], 'hits_10': [], 'rr': []})

print("Evaluating...")
for idx, (_, row) in enumerate(ot_test.iterrows()):
    # Build query from this test CVE
    query = f"{row['vendor']} {row['product']} {row['description']}"
    query = query.lower().strip()
    true_vendor = str(row['vendor']).lower().strip()
    
    # Vectorize and find similar CVEs
    q_vec = ot_vectorizer.transform([query])
    scores = cosine_similarity(q_vec, ot_matrix).flatten()
    
    # Get top 10
    top10_idx = scores.argsort()[-10:][::-1]
    top10_rows = ot_train.iloc[top10_idx]
    top10_vendors = [str(v).lower().strip() for v in top10_rows['vendor']]
    top10_scores = scores[top10_idx]
    
    top1_similarities.append(float(top10_scores[0]))
    
    # Hit@1: is correct vendor the top result?
    hit_1 = 1 if true_vendor in top10_vendors[:1] else 0
    hit_5 = 1 if true_vendor in top10_vendors[:5] else 0
    hit_10 = 1 if true_vendor in top10_vendors[:10] else 0
    
    hits_at_1.append(hit_1)
    hits_at_5.append(hit_5)
    hits_at_10.append(hit_10)
    
    # MRR: find position of first correct vendor
    rr = 0
    for rank, v in enumerate(top10_vendors, start=1):
        if v == true_vendor:
            rr = 1.0 / rank
            break
    reciprocal_ranks.append(rr)
    
    # Store per-vendor
    vendor_results[true_vendor]['hits_1'].append(hit_1)
    vendor_results[true_vendor]['hits_5'].append(hit_5)
    vendor_results[true_vendor]['hits_10'].append(hit_10)
    vendor_results[true_vendor]['rr'].append(rr)
    
    if (idx + 1) % 100 == 0:
        print(f"  Progress: {idx + 1}/{len(ot_test)}")

# Results
n = len(ot_test)
hit1 = sum(hits_at_1) / n
hit5 = sum(hits_at_5) / n
hit10 = sum(hits_at_10) / n
mrr = sum(reciprocal_ranks) / n
avg_sim = np.mean(top1_similarities)
median_sim = np.median(top1_similarities)
min_sim = np.min(top1_similarities)
max_sim = np.max(top1_similarities)
std_sim = np.std(top1_similarities)

print(f"\n{'='*80}")
print("OVERALL METRICS")
print(f"{'='*80}")
print(f"Test set size:        {n}")
print(f"Hit@1  (Precision@1): {hit1:.4f}  ({hit1*100:.2f}%)")
print(f"Hit@5  (Recall@5):    {hit5:.4f}  ({hit5*100:.2f}%)")
print(f"Hit@10 (Recall@10):   {hit10:.4f} ({hit10*100:.2f}%)")
print(f"MRR:                  {mrr:.4f}")
print(f"\nSimilarity Scores:")
print(f"  Mean:   {avg_sim:.4f}")
print(f"  Median: {median_sim:.4f}")
print(f"  Std:    {std_sim:.4f}")
print(f"  Range:  {min_sim:.4f} - {max_sim:.4f}")

# ============================================================================
# STEP 5 — PER-VENDOR BREAKDOWN
# ============================================================================
print(f"\n{'='*80}")
print("PER-VENDOR BREAKDOWN (vendors with ≥5 test samples)")
print(f"{'='*80}")

vendor_stats = []
for vendor, results in vendor_results.items():
    count = len(results['hits_1'])
    if count >= 5:
        vendor_stats.append({
            'vendor': vendor,
            'count': count,
            'hit@1': sum(results['hits_1']) / count,
            'hit@5': sum(results['hits_5']) / count,
            'hit@10': sum(results['hits_10']) / count,
            'mrr': sum(results['rr']) / count
        })

vendor_stats.sort(key=lambda x: x['hit@1'], reverse=True)

print(f"{'Vendor':<30} {'Count':>6} {'Hit@1':>8} {'Hit@5':>8} {'Hit@10':>8} {'MRR':>8}")
print("-"*80)
for vs in vendor_stats:
    print(f"{vs['vendor']:<30} {vs['count']:>6} {vs['hit@1']:>7.1%} {vs['hit@5']:>7.1%} {vs['hit@10']:>7.1%} {vs['mrr']:>8.4f}")

# ============================================================================
# STEP 6 — NEW DEVICE SIMULATION (10 queries)
# ============================================================================
print(f"\n{'='*80}")
print("NEW DEVICE SIMULATION (10 queries NOT in dataset)")
print(f"{'='*80}")

queries = [
    "siemens simatic s7-1200 v4.1 profinet",
    "schneider electric modicon m580 2.80 modbus",
    "rockwell automation controllogix 1756 ethernet ip",
    "advantech webaccess scada 8.4 http",
    "moxa nport 5150 serial device server",
    "abb ac500 plc modbus tcp",
    "delta electronics dvp plc modbus",
    "mitsubishi electric melsec iq-r ethernet",
    "codesys runtime v3.5 industrial",
    "wago 750 plc modbus",
]

new_device_results = []

for i, query in enumerate(queries, 1):
    print(f"\n{i}. Query: {query}")
    
    q_vec = ot_vectorizer.transform([query.lower()])
    scores = cosine_similarity(q_vec, ot_matrix).flatten()
    
    top3_idx = scores.argsort()[-3:][::-1]
    
    query_results = []
    for rank, idx in enumerate(top3_idx, 1):
        cve_row = ot_train.iloc[idx]
        result = {
            'rank': rank,
            'cve_id': cve_row['cve_id'],
            'vendor': cve_row['vendor'],
            'product': cve_row['product'],
            'cvss': float(cve_row.get('cvss', 0)),
            'epss': float(cve_row.get('epss', 0)),
            'kev': int(cve_row.get('kev', 0)),
            'similarity': float(scores[idx])
        }
        query_results.append(result)
        # Production format: CVE-ID cvss=X epss=Y kev=Z
        print(f"   {rank}. {result['cve_id']} cvss={result['cvss']:.1f} epss={result['epss']:.3f} kev={result['kev']}")
    
    new_device_results.append({
        'query': query,
        'top_3': query_results
    })

# ============================================================================
# STEP 7 — SAVE RESULTS
# ============================================================================
print(f"\n{'='*80}")
print("SAVING RESULTS")
print(f"{'='*80}")

# Save JSON
output_json = {
    'metadata': {
        'generated': datetime.now().isoformat(),
        'test_set_size': len(ot_test),
        'train_set_size': len(ot_train),
        'evaluation_method': '80/20 random split, IR metrics'
    },
    'overall_metrics': {
        'hit@1': float(hit1),
        'hit@5': float(hit5),
        'hit@10': float(hit10),
        'mrr': float(mrr),
        'similarity_mean': float(avg_sim),
        'similarity_median': float(median_sim),
        'similarity_std': float(std_sim),
        'similarity_min': float(min_sim),
        'similarity_max': float(max_sim)
    },
    'per_vendor_metrics': vendor_stats,
    'new_device_tests': new_device_results
}

with open(os.path.join(DATASET_FOLDER, 'evaluation_results.json'), 'w') as f:
    json.dump(output_json, f, indent=2)
print("✓ Saved: evaluation_results.json")

# Save text report
report_lines = []
report_lines.append("="*80)
report_lines.append("CAVE-OT MODEL EVALUATION REPORT")
report_lines.append("="*80)
report_lines.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
report_lines.append(f"Test Set: {len(ot_test)} CVEs (20% held-out, NEVER seen during training)")
report_lines.append(f"Train Set: {len(ot_train)} CVEs (80%)")
report_lines.append("\n" + "="*80)
report_lines.append("OVERALL METRICS")
report_lines.append("="*80)
report_lines.append(f"Hit@1  (Precision@1): {hit1:.4f}  ({hit1*100:.2f}%)")
report_lines.append(f"Hit@5  (Recall@5):    {hit5:.4f}  ({hit5*100:.2f}%)")
report_lines.append(f"Hit@10 (Recall@10):   {hit10:.4f} ({hit10*100:.2f}%)")
report_lines.append(f"MRR:                  {mrr:.4f}")
report_lines.append(f"\nSimilarity Scores:")
report_lines.append(f"  Mean:   {avg_sim:.4f}")
report_lines.append(f"  Median: {median_sim:.4f}")
report_lines.append(f"  Std:    {std_sim:.4f}")
report_lines.append(f"  Range:  {min_sim:.4f} - {max_sim:.4f}")
report_lines.append("\n" + "="*80)
report_lines.append("PER-VENDOR BREAKDOWN (vendors with ≥5 test samples)")
report_lines.append("="*80)
report_lines.append(f"{'Vendor':<30} {'Count':>6} {'Hit@1':>8} {'Hit@5':>8} {'Hit@10':>8} {'MRR':>8}")
report_lines.append("-"*80)
for vs in vendor_stats:
    report_lines.append(f"{vs['vendor']:<30} {vs['count']:>6} {vs['hit@1']:>7.1%} {vs['hit@5']:>7.1%} {vs['hit@10']:>7.1%} {vs['mrr']:>8.4f}")
report_lines.append("\n" + "="*80)
report_lines.append("NEW DEVICE SIMULATION")
report_lines.append("="*80)
for i, result in enumerate(new_device_results, 1):
    report_lines.append(f"\n{i}. Query: {result['query']}")
    for r in result['top_3']:
        report_lines.append(f"   {r['rank']}. {r['cve_id']} cvss={r['cvss']:.1f} epss={r.get('epss', 0):.3f} kev={r.get('kev', 0)}")

with open(os.path.join(DATASET_FOLDER, 'EVALUATION_REPORT.txt'), 'w', encoding='utf-8') as f:
    f.write('\n'.join(report_lines))
print("✓ Saved: EVALUATION_REPORT.txt")

print(f"\n{'='*80}")
print("✓ TRAINING AND EVALUATION COMPLETE")
print(f"{'='*80}")
print(f"Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
