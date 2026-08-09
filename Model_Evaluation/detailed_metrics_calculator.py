"""
Calculate comprehensive ML metrics for CAVE-OT model
Includes: Accuracy, Precision, Recall, F1-Score, MAP, NDCG, etc.
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.metrics import precision_score, recall_score, f1_score, classification_report
from collections import defaultdict
import json

MODEL_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model")
DATASET_FOLDER = os.path.dirname(os.path.abspath(__file__))

def load_models():
    """Load trained models"""
    print("Loading models...")
    return {
        'ot_vectorizer': joblib.load(f'{MODEL_FOLDER}/ot_vectorizer.pkl'),
        'ot_matrix': joblib.load(f'{MODEL_FOLDER}/ot_matrix.pkl'),
        'ot_df': joblib.load(f'{MODEL_FOLDER}/ot_cve_database.pkl')
    }

def calculate_ndcg(relevance_scores, k=10):
    """Calculate Normalized Discounted Cumulative Gain"""
    dcg = sum((2**rel - 1) / np.log2(i + 2) for i, rel in enumerate(relevance_scores[:k]))
    ideal_scores = sorted(relevance_scores, reverse=True)
    idcg = sum((2**rel - 1) / np.log2(i + 2) for i, rel in enumerate(ideal_scores[:k]))
    return dcg / idcg if idcg > 0 else 0

def calculate_map(results, k=10):
    """Calculate Mean Average Precision"""
    aps = []
    for result in results:
        if result['vendor_matches_in_top_k'] > 0:
            # Calculate precision at each relevant position
            precisions = []
            relevant_count = 0
            for i in range(1, k + 1):
                if i <= result['vendor_matches_in_top_k']:
                    relevant_count += 1
                    precisions.append(relevant_count / i)
            ap = np.mean(precisions) if precisions else 0
            aps.append(ap)
        else:
            aps.append(0)
    return np.mean(aps)

def evaluate_comprehensive(models):
    """Comprehensive evaluation with all metrics"""
    print("\nRunning comprehensive evaluation...")
    
    # Load test set
    test_df = pd.read_csv(f'{DATASET_FOLDER}/ot_training_ready_test.csv')
    print(f"Test set size: {len(test_df)} CVEs")
    
    results = []
    y_true_top1 = []
    y_pred_top1 = []
    y_true_top5 = []
    y_pred_top5 = []
    y_true_top10 = []
    y_pred_top10 = []
    
    ndcg_scores = []
    reciprocal_ranks = []
    
    for i, row in test_df.iterrows():
        if (i + 1) % 100 == 0:
            print(f"  Progress: {i+1}/{len(test_df)}")
        
        # Build query
        query = f"{row['vendor']} {row['product']} {row['description'][:100]}"
        q_vec = models['ot_vectorizer'].transform([query])
        scores = cosine_similarity(q_vec, models['ot_matrix']).flatten()
        
        # Get top-k results
        top_idx = scores.argsort()[-10:][::-1]
        top_cves = models['ot_df'].iloc[top_idx]
        top_scores = scores[top_idx]
        
        # Check vendor matches at different k values
        vendor_matches = []
        for j in range(10):
            is_match = top_cves.iloc[j]['vendor'].lower() == row['vendor'].lower()
            vendor_matches.append(1 if is_match else 0)
        
        # Top-1 metrics
        y_true_top1.append(1)  # Always expect a match
        y_pred_top1.append(1 if vendor_matches[0] else 0)
        
        # Top-5 metrics
        y_true_top5.append(1)
        y_pred_top5.append(1 if sum(vendor_matches[:5]) > 0 else 0)
        
        # Top-10 metrics
        y_true_top10.append(1)
        y_pred_top10.append(1 if sum(vendor_matches[:10]) > 0 else 0)
        
        # NDCG calculation
        ndcg = calculate_ndcg(vendor_matches, k=10)
        ndcg_scores.append(ndcg)
        
        # MRR calculation
        first_match_pos = next((i+1 for i, m in enumerate(vendor_matches) if m == 1), None)
        if first_match_pos:
            reciprocal_ranks.append(1.0 / first_match_pos)
        else:
            reciprocal_ranks.append(0)
        
        # Store detailed result
        results.append({
            'query_vendor': row['vendor'],
            'query_product': row['product'],
            'top_1_vendor': top_cves.iloc[0]['vendor'],
            'top_1_match': vendor_matches[0],
            'top_5_matches': sum(vendor_matches[:5]),
            'top_10_matches': sum(vendor_matches[:10]),
            'vendor_matches_in_top_k': sum(vendor_matches),
            'top_1_score': top_scores[0],
            'top_5_avg_score': np.mean(top_scores[:5]),
            'top_10_avg_score': np.mean(top_scores),
            'ndcg': ndcg,
            'rr': reciprocal_ranks[-1]
        })
    
    return results, y_true_top1, y_pred_top1, y_true_top5, y_pred_top5, y_true_top10, y_pred_top10, ndcg_scores, reciprocal_ranks

def calculate_all_metrics(results, y_true_top1, y_pred_top1, y_true_top5, y_pred_top5, y_true_top10, y_pred_top10, ndcg_scores, reciprocal_ranks):
    """Calculate all evaluation metrics"""
    
    metrics = {}
    
    # Basic counts
    total = len(results)
    metrics['total_queries'] = total
    
    # Top-1 Metrics
    metrics['top_1_accuracy'] = sum(y_pred_top1) / total
    metrics['top_1_precision'] = precision_score(y_true_top1, y_pred_top1, zero_division=0)
    metrics['top_1_recall'] = recall_score(y_true_top1, y_pred_top1, zero_division=0)
    metrics['top_1_f1_score'] = f1_score(y_true_top1, y_pred_top1, zero_division=0)
    
    # Top-5 Metrics
    metrics['top_5_accuracy'] = sum(y_pred_top5) / total
    metrics['top_5_precision'] = precision_score(y_true_top5, y_pred_top5, zero_division=0)
    metrics['top_5_recall'] = recall_score(y_true_top5, y_pred_top5, zero_division=0)
    metrics['top_5_f1_score'] = f1_score(y_true_top5, y_pred_top5, zero_division=0)
    
    # Top-10 Metrics
    metrics['top_10_accuracy'] = sum(y_pred_top10) / total
    metrics['top_10_precision'] = precision_score(y_true_top10, y_pred_top10, zero_division=0)
    metrics['top_10_recall'] = recall_score(y_true_top10, y_pred_top10, zero_division=0)
    metrics['top_10_f1_score'] = f1_score(y_true_top10, y_pred_top10, zero_division=0)
    
    # Ranking Metrics
    metrics['mean_reciprocal_rank'] = np.mean(reciprocal_ranks)
    metrics['ndcg_at_10'] = np.mean(ndcg_scores)
    metrics['map_at_10'] = calculate_map(results, k=10)
    
    # Similarity Score Statistics
    metrics['avg_top_1_similarity'] = np.mean([r['top_1_score'] for r in results])
    metrics['std_top_1_similarity'] = np.std([r['top_1_score'] for r in results])
    metrics['min_top_1_similarity'] = np.min([r['top_1_score'] for r in results])
    metrics['max_top_1_similarity'] = np.max([r['top_1_score'] for r in results])
    metrics['median_top_1_similarity'] = np.median([r['top_1_score'] for r in results])
    
    # Match Statistics
    metrics['avg_matches_in_top_5'] = np.mean([r['top_5_matches'] for r in results])
    metrics['avg_matches_in_top_10'] = np.mean([r['top_10_matches'] for r in results])
    
    # Percentile Analysis
    top1_scores = [r['top_1_score'] for r in results]
    metrics['similarity_25th_percentile'] = np.percentile(top1_scores, 25)
    metrics['similarity_75th_percentile'] = np.percentile(top1_scores, 75)
    metrics['similarity_90th_percentile'] = np.percentile(top1_scores, 90)
    
    # Success Rate by Similarity Threshold
    thresholds = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
    for thresh in thresholds:
        count = sum(1 for r in results if r['top_1_score'] >= thresh and r['top_1_match'])
        total_above = sum(1 for r in results if r['top_1_score'] >= thresh)
        metrics[f'precision_at_similarity_{thresh}'] = count / total_above if total_above > 0 else 0
    
    return metrics

def main():
    print("=" * 80)
    print("CAVE-OT COMPREHENSIVE METRICS CALCULATION")
    print("=" * 80)
    
    models = load_models()
    
    # Run evaluation
    results, y_true_top1, y_pred_top1, y_true_top5, y_pred_top5, y_true_top10, y_pred_top10, ndcg_scores, reciprocal_ranks = evaluate_comprehensive(models)
    
    # Calculate all metrics
    metrics = calculate_all_metrics(results, y_true_top1, y_pred_top1, y_true_top5, y_pred_top5, y_true_top10, y_pred_top10, ndcg_scores, reciprocal_ranks)
    
    # Display results
    print("\n" + "=" * 80)
    print("COMPREHENSIVE EVALUATION METRICS")
    print("=" * 80)
    
    print("\n📊 CLASSIFICATION METRICS")
    print("-" * 80)
    print(f"Total Test Queries:              {metrics['total_queries']}")
    print()
    print("TOP-1 METRICS (Exact Match):")
    print(f"  Accuracy:                      {metrics['top_1_accuracy']:.4f} ({metrics['top_1_accuracy']*100:.2f}%)")
    print(f"  Precision:                     {metrics['top_1_precision']:.4f}")
    print(f"  Recall:                        {metrics['top_1_recall']:.4f}")
    print(f"  F1-Score:                      {metrics['top_1_f1_score']:.4f}")
    print()
    print("TOP-5 METRICS (At Least 1 Match in Top-5):")
    print(f"  Accuracy:                      {metrics['top_5_accuracy']:.4f} ({metrics['top_5_accuracy']*100:.2f}%)")
    print(f"  Precision:                     {metrics['top_5_precision']:.4f}")
    print(f"  Recall:                        {metrics['top_5_recall']:.4f}")
    print(f"  F1-Score:                      {metrics['top_5_f1_score']:.4f}")
    print()
    print("TOP-10 METRICS (At Least 1 Match in Top-10):")
    print(f"  Accuracy:                      {metrics['top_10_accuracy']:.4f} ({metrics['top_10_accuracy']*100:.2f}%)")
    print(f"  Precision:                     {metrics['top_10_precision']:.4f}")
    print(f"  Recall:                        {metrics['top_10_recall']:.4f}")
    print(f"  F1-Score:                      {metrics['top_10_f1_score']:.4f}")
    
    print("\n📈 RANKING METRICS")
    print("-" * 80)
    print(f"Mean Reciprocal Rank (MRR):      {metrics['mean_reciprocal_rank']:.4f}")
    print(f"NDCG@10:                         {metrics['ndcg_at_10']:.4f}")
    print(f"MAP@10:                          {metrics['map_at_10']:.4f}")
    print(f"Avg Matches in Top-5:            {metrics['avg_matches_in_top_5']:.2f}")
    print(f"Avg Matches in Top-10:           {metrics['avg_matches_in_top_10']:.2f}")
    
    print("\n📊 SIMILARITY SCORE STATISTICS")
    print("-" * 80)
    print(f"Mean:                            {metrics['avg_top_1_similarity']:.4f}")
    print(f"Std Dev:                         {metrics['std_top_1_similarity']:.4f}")
    print(f"Median:                          {metrics['median_top_1_similarity']:.4f}")
    print(f"Min:                             {metrics['min_top_1_similarity']:.4f}")
    print(f"Max:                             {metrics['max_top_1_similarity']:.4f}")
    print(f"25th Percentile:                 {metrics['similarity_25th_percentile']:.4f}")
    print(f"75th Percentile:                 {metrics['similarity_75th_percentile']:.4f}")
    print(f"90th Percentile:                 {metrics['similarity_90th_percentile']:.4f}")
    
    print("\n📊 PRECISION BY SIMILARITY THRESHOLD")
    print("-" * 80)
    print("Threshold | Precision")
    print("-" * 80)
    for thresh in [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]:
        prec = metrics[f'precision_at_similarity_{thresh}']
        print(f"  ≥ {thresh:.1f}   |  {prec:.4f} ({prec*100:.2f}%)")
    
    # Save detailed results
    output = {
        'metrics': metrics,
        'sample_results': results[:50]
    }
    
    with open('comprehensive_metrics.json', 'w') as f:
        json.dump(output, f, indent=2, default=str)
    
    print("\n" + "=" * 80)
    print("✓ COMPREHENSIVE METRICS CALCULATED")
    print("=" * 80)
    print("\nResults saved to: comprehensive_metrics.json")

if __name__ == "__main__":
    main()
