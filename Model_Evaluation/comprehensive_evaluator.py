"""
Comprehensive Evaluator for CAVE-OT Model
Calculates ALL evaluation metrics on the 20% test split
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.model_selection import train_test_split
from collections import defaultdict, Counter
import json
import os
from datetime import datetime

MODEL_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model")
DATASET_FOLDER = os.path.dirname(os.path.abspath(__file__))

def load_all_models():
    """Load all trained model files"""
    print("Loading all model files...")
    models = {
        'ot_vectorizer': joblib.load(f'{MODEL_FOLDER}/ot_vectorizer.pkl'),
        'ot_matrix': joblib.load(f'{MODEL_FOLDER}/ot_matrix.pkl'),
        'ot_df': joblib.load(f'{MODEL_FOLDER}/ot_cve_database.pkl'),
        'general_vectorizer': joblib.load(f'{MODEL_FOLDER}/general_vectorizer.pkl'),
        'general_matrix': joblib.load(f'{MODEL_FOLDER}/general_matrix.pkl'),
        'general_df': joblib.load(f'{MODEL_FOLDER}/cve_database.pkl')
    }
    print(f"  ✓ OT model: {len(models['ot_df'])} CVEs")
    print(f"  ✓ General model: {len(models['general_df'])} CVEs")
    return models

def load_or_create_test_split():
    """Load existing test split or recreate with same random_state"""
    test_file = f'{DATASET_FOLDER}/ot_training_ready_test.csv'
    
    if os.path.exists(test_file):
        print(f"\nLoading existing test split...")
        test_df = pd.read_csv(test_file)
        print(f"  ✓ Test set: {len(test_df)} CVEs")
        return test_df
    else:
        print(f"\nTest split not found. Recreating with random_state=42...")
        full_df = pd.read_csv(f'{DATASET_FOLDER}/ot_training_ready.csv')
        _, test_df = train_test_split(full_df, test_size=0.2, random_state=42)
        test_df.to_csv(test_file, index=False)
        print(f"  ✓ Created test set: {len(test_df)} CVEs")
        return test_df

def calculate_ndcg(relevance_scores, k):
    """Calculate Normalized Discounted Cumulative Gain"""
    relevance_scores = relevance_scores[:k]
    dcg = sum((2**rel - 1) / np.log2(i + 2) for i, rel in enumerate(relevance_scores))
    ideal_scores = sorted(relevance_scores, reverse=True)
    idcg = sum((2**rel - 1) / np.log2(i + 2) for i, rel in enumerate(ideal_scores))
    return dcg / idcg if idcg > 0 else 0

def evaluate_query(query_row, vectorizer, matrix, df, k=10):
    """Evaluate a single query and return detailed results"""
    query = f"{query_row['vendor']} {query_row['product']} {query_row['description'][:100]}"
    q_vec = vectorizer.transform([query])
    scores = cosine_similarity(q_vec, matrix).flatten()
    
    # Get top-k results
    top_idx = scores.argsort()[-k:][::-1]
    top_cves = df.iloc[top_idx]
    top_scores = scores[top_idx]
    
    # Calculate vendor matches
    vendor_matches = []
    for i in range(k):
        is_match = top_cves.iloc[i]['vendor'].lower() == query_row['vendor'].lower()
        vendor_matches.append(1 if is_match else 0)
    
    # Find first match position (for MRR)
    first_match_pos = next((i+1 for i, m in enumerate(vendor_matches) if m == 1), None)
    
    return {
        'query_vendor': query_row['vendor'],
        'query_product': query_row['product'],
        'query_cve': query_row['cve_id'],
        'top_vendors': [top_cves.iloc[i]['vendor'] for i in range(k)],
        'top_cves': [top_cves.iloc[i]['cve_id'] for i in range(k)],
        'top_scores': top_scores.tolist(),
        'vendor_matches': vendor_matches,
        'first_match_position': first_match_pos,
        'reciprocal_rank': 1.0 / first_match_pos if first_match_pos else 0
    }

def calculate_precision_at_k(results, k):
    """Calculate Precision@k"""
    precisions = []
    for r in results:
        matches_in_k = sum(r['vendor_matches'][:k])
        precisions.append(matches_in_k / k)
    return np.mean(precisions)

def calculate_recall_at_k(results, k):
    """Calculate Recall@k (assuming 1 relevant item per query)"""
    recalls = []
    for r in results:
        matches_in_k = sum(r['vendor_matches'][:k])
        recalls.append(min(matches_in_k, 1))  # Binary: found or not
    return np.mean(recalls)

def calculate_f1_at_k(precision, recall):
    """Calculate F1 score from precision and recall"""
    if precision + recall == 0:
        return 0
    return 2 * (precision * recall) / (precision + recall)

def calculate_map(results, k=10):
    """Calculate Mean Average Precision"""
    aps = []
    for r in results:
        relevant_positions = [i+1 for i, m in enumerate(r['vendor_matches'][:k]) if m == 1]
        if not relevant_positions:
            aps.append(0)
        else:
            precisions_at_relevant = [sum(r['vendor_matches'][:pos]) / pos for pos in relevant_positions]
            aps.append(np.mean(precisions_at_relevant))
    return np.mean(aps)

def run_comprehensive_evaluation(models, test_df):
    """Run complete evaluation on test set"""
    print("\nRunning comprehensive evaluation...")
    print(f"Test set size: {len(test_df)} CVEs")
    
    results = []
    
    for i, row in test_df.iterrows():
        if (i + 1) % 100 == 0:
            print(f"  Progress: {i+1}/{len(test_df)}")
        
        result = evaluate_query(row, models['ot_vectorizer'], models['ot_matrix'], models['ot_df'], k=10)
        results.append(result)
    
    print(f"  ✓ Evaluated {len(results)} queries")
    return results

def calculate_all_metrics(results):
    """Calculate all requested metrics"""
    print("\nCalculating all metrics...")
    
    metrics = {}
    
    # 1. Precision @ k
    for k in [1, 3, 5, 10]:
        metrics[f'precision@{k}'] = calculate_precision_at_k(results, k)
    
    # 2. Recall @ k
    for k in [1, 3, 5, 10]:
        metrics[f'recall@{k}'] = calculate_recall_at_k(results, k)
    
    # 3. F1 Score @ k
    for k in [1, 3, 5, 10]:
        p = metrics[f'precision@{k}']
        r = metrics[f'recall@{k}']
        metrics[f'f1@{k}'] = calculate_f1_at_k(p, r)
    
    # 4. MRR (Mean Reciprocal Rank)
    metrics['mrr'] = np.mean([r['reciprocal_rank'] for r in results])
    
    # 5. MAP (Mean Average Precision)
    metrics['map@10'] = calculate_map(results, k=10)
    
    # 6. NDCG @ 5 and @ 10
    ndcg_5 = [calculate_ndcg(r['vendor_matches'], 5) for r in results]
    ndcg_10 = [calculate_ndcg(r['vendor_matches'], 10) for r in results]
    metrics['ndcg@5'] = np.mean(ndcg_5)
    metrics['ndcg@10'] = np.mean(ndcg_10)
    
    print("  ✓ Core metrics calculated")
    return metrics

def calculate_per_vendor_metrics(results):
    """Calculate metrics per vendor"""
    print("\nCalculating per-vendor metrics...")
    
    vendor_results = defaultdict(list)
    for r in results:
        vendor_results[r['query_vendor']].append(r)
    
    vendor_metrics = {}
    target_vendors = [
        'siemens', 'schneider electric', 'rockwell automation',
        'advantech', 'moxa', 'delta electronics', 'abb',
        'mitsubishi electric', 'codesys', 'wago'
    ]
    
    for vendor in target_vendors:
        vendor_lower = vendor.lower()
        matching_results = []
        
        # Find all variations of vendor name
        for v, res_list in vendor_results.items():
            if vendor_lower in v.lower() or v.lower() in vendor_lower:
                matching_results.extend(res_list)
        
        if matching_results:
            p1 = calculate_precision_at_k(matching_results, 1)
            p5 = calculate_precision_at_k(matching_results, 5)
            r5 = calculate_recall_at_k(matching_results, 5)
            f1_5 = calculate_f1_at_k(p5, r5)
            
            vendor_metrics[vendor] = {
                'count': len(matching_results),
                'precision@1': p1,
                'precision@5': p5,
                'recall@5': r5,
                'f1@5': f1_5
            }
    
    print(f"  ✓ Calculated metrics for {len(vendor_metrics)} vendors")
    return vendor_metrics

def calculate_similarity_statistics(results):
    """Calculate similarity score statistics"""
    print("\nCalculating similarity statistics...")
    
    top1_scores = [r['top_scores'][0] for r in results]
    
    stats = {
        'mean': np.mean(top1_scores),
        'median': np.median(top1_scores),
        'std': np.std(top1_scores),
        'min': np.min(top1_scores),
        'max': np.max(top1_scores),
        'percentile_25': np.percentile(top1_scores, 25),
        'percentile_50': np.percentile(top1_scores, 50),
        'percentile_75': np.percentile(top1_scores, 75),
        'percentile_90': np.percentile(top1_scores, 90)
    }
    
    # Histogram
    bins = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]
    histogram = {}
    for i in range(len(bins)-1):
        count = sum(1 for s in top1_scores if bins[i] <= s < bins[i+1])
        histogram[f'{bins[i]:.1f}-{bins[i+1]:.1f}'] = count
    # Handle edge case for 1.0
    histogram['0.8-1.0'] = sum(1 for s in top1_scores if 0.8 <= s <= 1.0)
    
    stats['histogram'] = histogram
    
    print("  ✓ Similarity statistics calculated")
    return stats

def analyze_false_positives(results):
    """Analyze false positive patterns"""
    print("\nAnalyzing false positives...")
    
    # Count wrong vendors in top-5
    wrong_vendor_count = 0
    total_top5_results = 0
    vendor_confusion = Counter()
    
    for r in results:
        query_vendor = r['query_vendor'].lower()
        for i in range(min(5, len(r['top_vendors']))):
            total_top5_results += 1
            top_vendor = r['top_vendors'][i].lower()
            if top_vendor != query_vendor:
                wrong_vendor_count += 1
                # Track confusion pairs
                pair = tuple(sorted([query_vendor, top_vendor]))
                vendor_confusion[pair] += 1
    
    fp_rate = wrong_vendor_count / total_top5_results if total_top5_results > 0 else 0
    
    # Get most confused pairs
    most_confused = vendor_confusion.most_common(10)
    
    analysis = {
        'false_positive_rate_top5': fp_rate,
        'wrong_vendors_in_top5': wrong_vendor_count,
        'total_top5_slots': total_top5_results,
        'most_confused_pairs': [
            {'vendors': list(pair), 'count': count}
            for pair, count in most_confused
        ]
    }
    
    print(f"  ✓ False positive rate: {fp_rate:.2%}")
    return analysis

def analyze_thresholds(results):
    """Analyze precision/recall at different similarity thresholds"""
    print("\nAnalyzing similarity thresholds...")
    
    thresholds = [0.10, 0.15, 0.20, 0.25, 0.30]
    threshold_analysis = {}
    
    for thresh in thresholds:
        # Filter results by threshold
        above_threshold = []
        below_threshold = []
        
        for r in results:
            if r['top_scores'][0] >= thresh:
                above_threshold.append(r)
            else:
                below_threshold.append(r)
        
        if above_threshold:
            precision = calculate_precision_at_k(above_threshold, 1)
            recall = len(above_threshold) / len(results)  # Coverage
            f1 = calculate_f1_at_k(precision, recall)
        else:
            precision = 0
            recall = 0
            f1 = 0
        
        threshold_analysis[f'{thresh:.2f}'] = {
            'threshold': thresh,
            'precision': precision,
            'recall_coverage': recall,
            'f1': f1,
            'queries_above': len(above_threshold),
            'queries_below': len(below_threshold)
        }
    
    # Recommend optimal threshold (best F1)
    best_thresh = max(threshold_analysis.items(), key=lambda x: x[1]['f1'])
    
    print(f"  ✓ Optimal threshold: {best_thresh[0]} (F1: {best_thresh[1]['f1']:.4f})")
    return threshold_analysis, best_thresh[0]

def generate_report(metrics, vendor_metrics, similarity_stats, fp_analysis, threshold_analysis, optimal_threshold):
    """Generate comprehensive text report"""
    
    report = []
    report.append("=" * 80)
    report.append("CAVE-OT MODEL - COMPREHENSIVE EVALUATION REPORT")
    report.append("=" * 80)
    report.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Evaluation Method: 80/20 Train/Test Split (NO DATA LEAKAGE)")
    report.append("")
    
    # Core Metrics
    report.append("=" * 80)
    report.append("1. PRECISION METRICS")
    report.append("=" * 80)
    for k in [1, 3, 5, 10]:
        report.append(f"Precision@{k:2d}:  {metrics[f'precision@{k}']:.4f} ({metrics[f'precision@{k}']*100:.2f}%)")
    
    report.append("\n" + "=" * 80)
    report.append("2. RECALL METRICS")
    report.append("=" * 80)
    for k in [1, 3, 5, 10]:
        report.append(f"Recall@{k:2d}:     {metrics[f'recall@{k}']:.4f} ({metrics[f'recall@{k}']*100:.2f}%)")
    
    report.append("\n" + "=" * 80)
    report.append("3. F1 SCORE METRICS")
    report.append("=" * 80)
    for k in [1, 3, 5, 10]:
        report.append(f"F1@{k:2d}:         {metrics[f'f1@{k}']:.4f}")
    
    report.append("\n" + "=" * 80)
    report.append("4. RANKING METRICS")
    report.append("=" * 80)
    report.append(f"MRR (Mean Reciprocal Rank):  {metrics['mrr']:.4f}")
    report.append(f"  → First match at position: {1/metrics['mrr']:.2f} (average)")
    
    report.append("\n" + "=" * 80)
    report.append("5. MEAN AVERAGE PRECISION")
    report.append("=" * 80)
    report.append(f"MAP@10:  {metrics['map@10']:.4f} ({metrics['map@10']*100:.2f}%)")
    
    report.append("\n" + "=" * 80)
    report.append("6. NORMALIZED DISCOUNTED CUMULATIVE GAIN")
    report.append("=" * 80)
    report.append(f"NDCG@5:   {metrics['ndcg@5']:.4f}")
    report.append(f"NDCG@10:  {metrics['ndcg@10']:.4f}")
    
    # Per-Vendor Metrics
    report.append("\n" + "=" * 80)
    report.append("7. PER-VENDOR BREAKDOWN")
    report.append("=" * 80)
    report.append(f"{'Vendor':<25} {'Count':>6} {'P@1':>8} {'P@5':>8} {'R@5':>8} {'F1@5':>8}")
    report.append("-" * 80)
    for vendor, vm in sorted(vendor_metrics.items(), key=lambda x: x[1]['count'], reverse=True):
        report.append(f"{vendor:<25} {vm['count']:>6} {vm['precision@1']:>7.2%} {vm['precision@5']:>7.2%} {vm['recall@5']:>7.2%} {vm['f1@5']:>8.4f}")
    
    # Similarity Statistics
    report.append("\n" + "=" * 80)
    report.append("8. SIMILARITY SCORE STATISTICS")
    report.append("=" * 80)
    report.append(f"Mean:              {similarity_stats['mean']:.4f}")
    report.append(f"Median:            {similarity_stats['median']:.4f}")
    report.append(f"Std Dev:           {similarity_stats['std']:.4f}")
    report.append(f"Min:               {similarity_stats['min']:.4f}")
    report.append(f"Max:               {similarity_stats['max']:.4f}")
    report.append(f"25th Percentile:   {similarity_stats['percentile_25']:.4f}")
    report.append(f"75th Percentile:   {similarity_stats['percentile_75']:.4f}")
    report.append(f"90th Percentile:   {similarity_stats['percentile_90']:.4f}")
    report.append("\nHistogram:")
    for range_str, count in similarity_stats['histogram'].items():
        report.append(f"  {range_str}: {count:4d} queries")
    
    # False Positive Analysis
    report.append("\n" + "=" * 80)
    report.append("9. FALSE POSITIVE ANALYSIS")
    report.append("=" * 80)
    report.append(f"False Positive Rate (Top-5): {fp_analysis['false_positive_rate_top5']:.2%}")
    report.append(f"Wrong Vendors in Top-5:      {fp_analysis['wrong_vendors_in_top5']:,}")
    report.append(f"Total Top-5 Slots:           {fp_analysis['total_top5_slots']:,}")
    report.append("\nMost Confused Vendor Pairs:")
    for i, pair_info in enumerate(fp_analysis['most_confused_pairs'][:10], 1):
        v1, v2 = pair_info['vendors']
        report.append(f"  {i:2d}. {v1:<25} ↔ {v2:<25} ({pair_info['count']:3d} times)")
    
    # Threshold Analysis
    report.append("\n" + "=" * 80)
    report.append("10. THRESHOLD ANALYSIS")
    report.append("=" * 80)
    report.append(f"{'Threshold':>10} {'Precision':>12} {'Coverage':>12} {'F1':>10} {'Queries':>10}")
    report.append("-" * 80)
    for thresh_str, ta in sorted(threshold_analysis.items()):
        report.append(f"  ≥ {ta['threshold']:.2f}   {ta['precision']:>11.2%} {ta['recall_coverage']:>11.2%} {ta['f1']:>10.4f} {ta['queries_above']:>10}")
    report.append(f"\n✓ RECOMMENDED THRESHOLD: {optimal_threshold} (Best F1 Score)")
    
    report.append("\n" + "=" * 80)
    report.append("END OF REPORT")
    report.append("=" * 80)
    
    return "\n".join(report)

def print_summary_table(metrics, vendor_metrics):
    """Print clean summary table to terminal"""
    print("\n" + "=" * 80)
    print("COMPREHENSIVE EVALUATION SUMMARY")
    print("=" * 80)
    
    print("\n📊 CORE METRICS")
    print("-" * 80)
    print(f"{'Metric':<20} {'@1':>10} {'@3':>10} {'@5':>10} {'@10':>10}")
    print("-" * 80)
    print(f"{'Precision':<20} {metrics['precision@1']:>9.2%} {metrics['precision@3']:>9.2%} {metrics['precision@5']:>9.2%} {metrics['precision@10']:>9.2%}")
    print(f"{'Recall':<20} {metrics['recall@1']:>9.2%} {metrics['recall@3']:>9.2%} {metrics['recall@5']:>9.2%} {metrics['recall@10']:>9.2%}")
    print(f"{'F1-Score':<20} {metrics['f1@1']:>10.4f} {metrics['f1@3']:>10.4f} {metrics['f1@5']:>10.4f} {metrics['f1@10']:>10.4f}")
    
    print("\n📈 RANKING METRICS")
    print("-" * 80)
    print(f"MRR:      {metrics['mrr']:.4f}")
    print(f"MAP@10:   {metrics['map@10']:.4f}")
    print(f"NDCG@5:   {metrics['ndcg@5']:.4f}")
    print(f"NDCG@10:  {metrics['ndcg@10']:.4f}")
    
    print("\n🏭 TOP VENDORS")
    print("-" * 80)
    print(f"{'Vendor':<25} {'Count':>6} {'P@1':>8} {'F1@5':>8}")
    print("-" * 80)
    for vendor, vm in sorted(vendor_metrics.items(), key=lambda x: x[1]['count'], reverse=True)[:10]:
        print(f"{vendor:<25} {vm['count']:>6} {vm['precision@1']:>7.2%} {vm['f1@5']:>8.4f}")
    
    print("\n" + "=" * 80)

def main():
    print("=" * 80)
    print("CAVE-OT COMPREHENSIVE EVALUATOR")
    print("=" * 80)
    
    # Load models
    models = load_all_models()
    
    # Load test split
    test_df = load_or_create_test_split()
    
    # Run evaluation
    results = run_comprehensive_evaluation(models, test_df)
    
    # Calculate all metrics
    metrics = calculate_all_metrics(results)
    vendor_metrics = calculate_per_vendor_metrics(results)
    similarity_stats = calculate_similarity_statistics(results)
    fp_analysis = analyze_false_positives(results)
    threshold_analysis, optimal_threshold = analyze_thresholds(results)
    
    # Generate report
    report_text = generate_report(metrics, vendor_metrics, similarity_stats, fp_analysis, threshold_analysis, optimal_threshold)
    
    # Save results
    print("\nSaving results...")
    
    # Save JSON
    output_json = {
        'metadata': {
            'generated': datetime.now().isoformat(),
            'test_set_size': len(test_df),
            'evaluation_method': '80/20 train/test split'
        },
        'core_metrics': metrics,
        'vendor_metrics': vendor_metrics,
        'similarity_statistics': similarity_stats,
        'false_positive_analysis': fp_analysis,
        'threshold_analysis': threshold_analysis,
        'optimal_threshold': optimal_threshold,
        'sample_results': results[:50]
    }
    
    with open('comprehensive_evaluation_results.json', 'w') as f:
        json.dump(output_json, f, indent=2, default=str)
    print("  ✓ Saved: comprehensive_evaluation_results.json")
    
    # Save text report
    with open('comprehensive_evaluation_report.txt', 'w', encoding='utf-8') as f:
        f.write(report_text)
    print("  ✓ Saved: comprehensive_evaluation_report.txt")
    
    # Print summary
    print_summary_table(metrics, vendor_metrics)
    
    print("\n" + "=" * 80)
    print("✓ COMPREHENSIVE EVALUATION COMPLETE")
    print("=" * 80)
    print("\nAll results saved to:")
    print("  - comprehensive_evaluation_results.json")
    print("  - comprehensive_evaluation_report.txt")

if __name__ == "__main__":
    main()
