"""
CAVE-OT Model Evaluator
Evaluates TF-IDF similarity model performance using IR metrics
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.metrics.pairwise import cosine_similarity
from collections import defaultdict
import json

MODEL_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model")
DATASET_FOLDER = os.path.dirname(os.path.abspath(__file__))

def load_models():
    """Load trained models"""
    print("Loading models...")
    return {
        'general_vectorizer': joblib.load(f'{MODEL_FOLDER}/general_vectorizer.pkl'),
        'general_matrix': joblib.load(f'{MODEL_FOLDER}/general_matrix.pkl'),
        'general_df': joblib.load(f'{MODEL_FOLDER}/cve_database.pkl'),
        'ot_vectorizer': joblib.load(f'{MODEL_FOLDER}/ot_vectorizer.pkl'),
        'ot_matrix': joblib.load(f'{MODEL_FOLDER}/ot_matrix.pkl'),
        'ot_df': joblib.load(f'{MODEL_FOLDER}/ot_cve_database.pkl')
    }

def build_test_queries():
    """Build test queries from known vendor-product-CVE mappings"""
    df = pd.read_csv(f'{DATASET_FOLDER}/ot_training_ready.csv')
    
    # Sample diverse test cases
    test_cases = []
    
    # Group by vendor to get diverse samples
    vendors = ['siemens', 'schneider electric', 'rockwell automation', 
               'advantech', 'moxa', 'delta electronics']
    
    for vendor in vendors:
        vendor_cves = df[df['vendor'] == vendor].head(20)
        for _, row in vendor_cves.iterrows():
            query = f"{row['vendor']} {row['product']} {row['description'][:100]}"
            test_cases.append({
                'query': query,
                'expected_cve': row['cve_id'],
                'vendor': row['vendor'],
                'product': row['product']
            })
    
    return test_cases

def evaluate_query(query, expected_cve, vectorizer, matrix, df, k=10):
    """Evaluate a single query"""
    # Transform query
    q_vec = vectorizer.transform([query])
    scores = cosine_similarity(q_vec, matrix).flatten()
    
    # Get top K results
    top_idx = scores.argsort()[-k:][::-1]
    top_cves = df.iloc[top_idx]['cve_id'].values
    top_scores = scores[top_idx]
    
    # Check if expected CVE is in results
    if expected_cve in top_cves:
        position = np.where(top_cves == expected_cve)[0][0] + 1
        score = top_scores[np.where(top_cves == expected_cve)[0][0]]
        return {
            'found': True,
            'position': position,
            'score': score,
            'top_k_cves': top_cves.tolist(),
            'top_k_scores': top_scores.tolist()
        }
    else:
        return {
            'found': False,
            'position': None,
            'score': 0.0,
            'top_k_cves': top_cves.tolist(),
            'top_k_scores': top_scores.tolist()
        }

def calculate_metrics(results, k_values=[1, 5, 10]):
    """Calculate evaluation metrics"""
    metrics = {}
    
    total = len(results)
    found_count = sum(1 for r in results if r['found'])
    
    # Overall accuracy (found in top K)
    metrics['total_queries'] = total
    metrics['found_in_top_k'] = found_count
    metrics['hit_rate'] = found_count / total if total > 0 else 0
    
    # Hit rate@K and Recall@K
    for k in k_values:
        hit_rate_at_k = sum(1 for r in results if r['found'] and r['position'] <= k) / total if total else 0
        metrics[f'hit_rate@{k}'] = hit_rate_at_k
        metrics[f'recall@{k}'] = hit_rate_at_k  # Same for single relevant doc
    
    # Mean Reciprocal Rank (MRR)
    reciprocal_ranks = [1/r['position'] if r['found'] else 0 for r in results]
    metrics['mrr'] = np.mean(reciprocal_ranks) if reciprocal_ranks else 0
    
    # Average position of found results
    positions = [r['position'] for r in results if r['found']]
    metrics['avg_position'] = np.mean(positions) if positions else 0
    
    # Score statistics
    scores = [r['score'] for r in results if r['found']]
    if scores:
        metrics['avg_similarity_score'] = np.mean(scores)
        metrics['min_similarity_score'] = np.min(scores)
        metrics['max_similarity_score'] = np.max(scores)
    else:
        metrics['avg_similarity_score'] = 0
        metrics['min_similarity_score'] = 0
        metrics['max_similarity_score'] = 0
    
    return metrics

def main():
    print("=" * 60)
    print("CAVE-OT MODEL EVALUATION")
    print("=" * 60)
    
    # Load models
    models = load_models()
    
    # Build test queries
    print("\nBuilding test queries from OT dataset...")
    test_cases = build_test_queries()
    print(f"  ✓ Created {len(test_cases)} test queries")
    
    # Evaluate OT model
    print(f"\n[1/2] Evaluating OT fine-tuned model...")
    ot_results = []
    for i, test in enumerate(test_cases, 1):
        if i % 20 == 0:
            print(f"  Progress: {i}/{len(test_cases)}")
        result = evaluate_query(
            test['query'],
            test['expected_cve'],
            models['ot_vectorizer'],
            models['ot_matrix'],
            models['ot_df'],
            k=10
        )
        result['vendor'] = test['vendor']
        ot_results.append(result)
    
    # Evaluate general model (for comparison)
    print(f"\n[2/2] Evaluating general model (baseline)...")
    general_results = []
    for i, test in enumerate(test_cases, 1):
        if i % 20 == 0:
            print(f"  Progress: {i}/{len(test_cases)}")
        result = evaluate_query(
            test['query'],
            test['expected_cve'],
            models['general_vectorizer'],
            models['general_matrix'],
            models['general_df'],
            k=10
        )
        result['vendor'] = test['vendor']
        general_results.append(result)
    
    # Calculate metrics
    print("\nCalculating metrics...")
    ot_metrics = calculate_metrics(ot_results)
    general_metrics = calculate_metrics(general_results)
    
    # Display results
    print("\n" + "=" * 60)
    print("EVALUATION RESULTS")
    print("=" * 60)
    
    print("\n📊 OT FINE-TUNED MODEL")
    print("-" * 60)
    print(f"Total Test Queries:        {ot_metrics['total_queries']}")
    print(f"Found in Top 10:           {ot_metrics['found_in_top_k']}")
    print(f"Overall retrieval hit rate:          {ot_metrics['hit_rate']:.2%}")
    print(f"\nHit rate@1:               {ot_metrics['hit_rate@1']:.2%}")
    print(f"Hit rate@5:               {ot_metrics['hit_rate@5']:.2%}")
    print(f"Hit rate@10:              {ot_metrics['hit_rate@10']:.2%}")
    print(f"\nMean Reciprocal Rank:      {ot_metrics['mrr']:.4f}")
    print(f"Average Position:          {ot_metrics['avg_position']:.2f}")
    print(f"\nAvg Similarity Score:      {ot_metrics['avg_similarity_score']:.4f}")
    print(f"Min Similarity Score:      {ot_metrics['min_similarity_score']:.4f}")
    print(f"Max Similarity Score:      {ot_metrics['max_similarity_score']:.4f}")
    
    print("\n📊 GENERAL MODEL (Baseline)")
    print("-" * 60)
    print(f"Overall retrieval hit rate:          {general_metrics['hit_rate']:.2%}")
    print(f"Hit rate@1:               {general_metrics['hit_rate@1']:.2%}")
    print(f"Hit rate@5:               {general_metrics['hit_rate@5']:.2%}")
    print(f"Hit rate@10:              {general_metrics['hit_rate@10']:.2%}")
    print(f"Mean Reciprocal Rank:      {general_metrics['mrr']:.4f}")
    print(f"Avg Similarity Score:      {general_metrics['avg_similarity_score']:.4f}")
    
    # Improvement analysis
    print("\n📈 IMPROVEMENT (OT vs General)")
    print("-" * 60)
    acc_improvement = (ot_metrics['hit_rate'] - general_metrics['hit_rate']) * 100
    p1_improvement = (ot_metrics['hit_rate@1'] - general_metrics['hit_rate@1']) * 100
    p5_improvement = (ot_metrics['hit_rate@5'] - general_metrics['hit_rate@5']) * 100
    mrr_improvement = (ot_metrics['mrr'] - general_metrics['mrr']) * 100
    
    print(f"Accuracy Improvement:      {acc_improvement:+.2f}%")
    print(f"Hit rate@1 Improvement:   {p1_improvement:+.2f}%")
    print(f"Hit rate@5 Improvement:   {p5_improvement:+.2f}%")
    print(f"MRR Improvement:           {mrr_improvement:+.2f}%")
    
    # Per-vendor breakdown
    print("\n📋 PER-VENDOR PERFORMANCE (OT Model)")
    print("-" * 60)
    vendor_stats = defaultdict(lambda: {'total': 0, 'found': 0})
    for result in ot_results:
        vendor = result['vendor']
        vendor_stats[vendor]['total'] += 1
        if result['found']:
            vendor_stats[vendor]['found'] += 1
    
    for vendor, stats in sorted(vendor_stats.items()):
        accuracy = stats['found'] / stats['total'] if stats['total'] > 0 else 0
        print(f"{vendor:25} {accuracy:6.2%}  ({stats['found']}/{stats['total']})")
    
    # Save detailed results
    output = {
        'ot_model': ot_metrics,
        'general_model': general_metrics,
        'improvement': {
            'accuracy': acc_improvement,
            'hit_rate@1': p1_improvement,
            'hit_rate@5': p5_improvement,
            'mrr': mrr_improvement
        },
        'vendor_breakdown': dict(vendor_stats)
    }
    
    with open('evaluation_results.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    print("\n" + "=" * 60)
    print("✓ EVALUATION COMPLETE")
    print("=" * 60)
    print("\nDetailed results saved to: evaluation_results.json")

if __name__ == "__main__":
    main()
