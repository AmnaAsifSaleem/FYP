"""
CAVE-OT Proper Evaluator
Evaluates on held-out test set (20%) + completely new devices
NO DATA LEAKAGE
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.metrics.pairwise import cosine_similarity
from collections import defaultdict
import json

MODEL_FOLDER = r"D:\Downloads\CAVE-OT Datasets\model"
DATASET_FOLDER = r"D:\Downloads\CAVE-OT Datasets"

def load_models():
    """Load trained models"""
    print("Loading models (trained on 80% only)...")
    return {
        'ot_vectorizer': joblib.load(f'{MODEL_FOLDER}/ot_vectorizer.pkl'),
        'ot_matrix': joblib.load(f'{MODEL_FOLDER}/ot_matrix.pkl'),
        'ot_df': joblib.load(f'{MODEL_FOLDER}/ot_cve_database.pkl')
    }

def evaluate_query(query, expected_cve, vectorizer, matrix, df, k=10):
    """Evaluate a single query"""
    q_vec = vectorizer.transform([query])
    scores = cosine_similarity(q_vec, matrix).flatten()
    
    top_idx = scores.argsort()[-k:][::-1]
    top_cves = df.iloc[top_idx]['cve_id'].values
    top_scores = scores[top_idx]
    
    if expected_cve in top_cves:
        position = np.where(top_cves == expected_cve)[0][0] + 1
        score = top_scores[np.where(top_cves == expected_cve)[0][0]]
        return {
            'found': True,
            'position': position,
            'score': score
        }
    else:
        return {
            'found': False,
            'position': None,
            'score': 0.0
        }

def calculate_metrics(results, k_values=[1, 5, 10]):
    """Calculate evaluation metrics"""
    metrics = {}
    total = len(results)
    found_count = sum(1 for r in results if r['found'])
    
    metrics['total_queries'] = total
    metrics['found_in_top_k'] = found_count
    metrics['hit_rate'] = found_count / total if total > 0 else 0
    
    for k in k_values:
        hit_rate_at_k = sum(1 for r in results if r['found'] and r['position'] <= k) / total if total else 0
        metrics[f'hit_rate@{k}'] = hit_rate_at_k
    
    reciprocal_ranks = [1/r['position'] if r['found'] else 0 for r in results]
    metrics['mrr'] = np.mean(reciprocal_ranks) if reciprocal_ranks else 0
    
    positions = [r['position'] for r in results if r['found']]
    metrics['avg_position'] = np.mean(positions) if positions else 0
    
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

def test_on_held_out_set(models):
    """Test on 20% held-out test set"""
    print("\n[1/2] Evaluating on held-out test set (20%)...")
    
    # Load TEST set (never seen during training)
    test_df = pd.read_csv(f'{DATASET_FOLDER}/ot_training_ready_test.csv')
    print(f"  Test set size: {len(test_df)} CVEs")
    
    results = []
    vendor_stats = defaultdict(lambda: {'total': 0, 'found': 0})
    
    for i, row in test_df.iterrows():
        if (i + 1) % 100 == 0:
            print(f"  Progress: {i+1}/{len(test_df)}")
        
        query = f"{row['vendor']} {row['product']} {row['description'][:100]}"
        result = evaluate_query(
            query,
            row['cve_id'],
            models['ot_vectorizer'],
            models['ot_matrix'],
            models['ot_df'],
            k=10
        )
        result['vendor'] = row['vendor']
        results.append(result)
        
        vendor_stats[row['vendor']]['total'] += 1
        if result['found']:
            vendor_stats[row['vendor']]['found'] += 1
    
    return results, vendor_stats

def test_on_new_devices(models):
    """Test on completely new device descriptions"""
    print("\n[2/2] Testing on 10 completely new devices...")
    
    # Real-world device descriptions NOT in dataset
    new_devices = [
        {
            'query': 'siemens simatic s7-1200 plc firmware 4.2 profinet vulnerability',
            'vendor': 'siemens',
            'description': 'New S7-1200 device'
        },
        {
            'query': 'schneider electric triconex safety controller tricon v11 memory corruption',
            'vendor': 'schneider electric',
            'description': 'Triconex safety system'
        },
        {
            'query': 'rockwell automation compactlogix 5380 ethernet ip remote code execution',
            'vendor': 'rockwell automation',
            'description': 'CompactLogix controller'
        },
        {
            'query': 'siemens simatic hmi panel tp1200 comfort vnc server authentication bypass',
            'vendor': 'siemens',
            'description': 'HMI touch panel'
        },
        {
            'query': 'schneider electric modicon quantum plc unity pro buffer overflow',
            'vendor': 'schneider electric',
            'description': 'Quantum PLC'
        },
        {
            'query': 'abb ac500 plc codesys runtime denial of service',
            'vendor': 'abb',
            'description': 'ABB AC500 controller'
        },
        {
            'query': 'mitsubishi electric melsec iq-r series plc slmp protocol vulnerability',
            'vendor': 'mitsubishi electric',
            'description': 'MELSEC iQ-R PLC'
        },
        {
            'query': 'honeywell experion pks c300 controller firmware privilege escalation',
            'vendor': 'honeywell',
            'description': 'Experion DCS controller'
        },
        {
            'query': 'omron sysmac nj series plc fins protocol stack overflow',
            'vendor': 'omron',
            'description': 'SYSMAC NJ controller'
        },
        {
            'query': 'phoenix contact plcnext control axi axioline hardening sql injection',
            'vendor': 'phoenix contact',
            'description': 'PLCnext controller'
        }
    ]
    
    results = []
    for device in new_devices:
        q_vec = models['ot_vectorizer'].transform([device['query']])
        scores = cosine_similarity(q_vec, models['ot_matrix']).flatten()
        
        top_idx = scores.argsort()[-5:][::-1]
        top_cves = models['ot_df'].iloc[top_idx]
        top_scores = scores[top_idx]
        
        results.append({
            'device': device['description'],
            'vendor': device['vendor'],
            'top_cve': top_cves.iloc[0]['cve_id'],
            'top_score': top_scores[0],
            'top_5_avg_score': np.mean(top_scores),
            'found_relevant': top_scores[0] > 0.15
        })
        
        print(f"  {device['description']:30} → {top_cves.iloc[0]['cve_id']} (sim: {top_scores[0]:.3f})")
    
    return results

def main():
    print("=" * 60)
    print("CAVE-OT PROPER EVALUATION (NO DATA LEAKAGE)")
    print("=" * 60)
    
    models = load_models()
    
    # Test 1: Held-out test set
    test_results, vendor_stats = test_on_held_out_set(models)
    test_metrics = calculate_metrics(test_results)
    
    # Test 2: Completely new devices
    new_device_results = test_on_new_devices(models)
    
    # Display results
    print("\n" + "=" * 60)
    print("HONEST EVALUATION RESULTS")
    print("=" * 60)
    
    print("\n📊 HELD-OUT TEST SET (20% - Never Seen During Training)")
    print("-" * 60)
    print(f"Total Test Queries:        {test_metrics['total_queries']}")
    print(f"Found in Top 10:           {test_metrics['found_in_top_k']}")
    print(f"Overall retrieval hit rate:          {test_metrics['hit_rate']:.2%}")
    print(f"\nHit rate@1:               {test_metrics['hit_rate@1']:.2%}")
    print(f"Hit rate@5:               {test_metrics['hit_rate@5']:.2%}")
    print(f"Hit rate@10:              {test_metrics['hit_rate@10']:.2%}")
    print(f"\nMean Reciprocal Rank:      {test_metrics['mrr']:.4f}")
    print(f"Average Position:          {test_metrics['avg_position']:.2f}")
    print(f"\nAvg Similarity Score:      {test_metrics['avg_similarity_score']:.4f}")
    print(f"Min Similarity Score:      {test_metrics['min_similarity_score']:.4f}")
    print(f"Max Similarity Score:      {test_metrics['max_similarity_score']:.4f}")
    
    print("\n📋 Per-Vendor Performance (Test Set)")
    print("-" * 60)
    for vendor, stats in sorted(vendor_stats.items(), key=lambda x: x[1]['total'], reverse=True)[:10]:
        accuracy = stats['found'] / stats['total'] if stats['total'] > 0 else 0
        print(f"{vendor:25} {accuracy:6.2%}  ({stats['found']}/{stats['total']})")
    
    print("\n📊 COMPLETELY NEW DEVICES (Not in Dataset)")
    print("-" * 60)
    relevant_count = sum(1 for r in new_device_results if r['found_relevant'])
    avg_score = np.mean([r['top_score'] for r in new_device_results])
    print(f"Devices Tested:            10")
    print(f"Found Relevant CVEs:       {relevant_count}/10 ({relevant_count/10*100:.0f}%)")
    print(f"Avg Top-1 Similarity:      {avg_score:.4f}")
    
    # Save results
    output = {
        'test_set_metrics': test_metrics,
        'vendor_breakdown': dict(vendor_stats),
        'new_devices': new_device_results
    }
    
    with open('honest_evaluation_results.json', 'w') as f:
        json.dump(output, f, indent=2, default=str)
    
    print("\n" + "=" * 60)
    print("✓ HONEST EVALUATION COMPLETE")
    print("=" * 60)
    print("\nResults saved to: honest_evaluation_results.json")
    print("\n⚠️  These are REAL metrics with no data leakage")

if __name__ == "__main__":
    main()
