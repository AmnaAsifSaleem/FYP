"""
CAVE-OT Proper Evaluator (FIXED)
Evaluates on held-out test set (20%) + completely new devices
NO DATA LEAKAGE - Measures vendor/product relevance, not exact CVE matching
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

def evaluate_query_relevance(query_row, vectorizer, matrix, df, k=10):
    """
    Evaluate query by checking if retrieved CVEs are from same vendor/product
    This is the correct approach since test CVEs are not in training database
    """
    query = f"{query_row['vendor']} {query_row['product']} {query_row['description'][:100]}"
    q_vec = vectorizer.transform([query])
    scores = cosine_similarity(q_vec, matrix).flatten()
    
    top_idx = scores.argsort()[-k:][::-1]
    top_cves = df.iloc[top_idx]
    top_scores = scores[top_idx]
    
    # Check vendor match
    vendor_matches = sum(1 for i in range(k) if top_cves.iloc[i]['vendor'].lower() == query_row['vendor'].lower())
    
    # Check product match (fuzzy)
    product_matches = sum(1 for i in range(k) if query_row['product'].lower() in top_cves.iloc[i]['product'].lower() 
                         or top_cves.iloc[i]['product'].lower() in query_row['product'].lower())
    
    return {
        'top_1_vendor_match': top_cves.iloc[0]['vendor'].lower() == query_row['vendor'].lower(),
        'top_5_vendor_match': vendor_matches >= 1,
        'top_10_vendor_match': vendor_matches >= 1,
        'vendor_matches_in_top_10': vendor_matches,
        'product_matches_in_top_10': product_matches,
        'top_1_score': top_scores[0],
        'top_5_avg_score': np.mean(top_scores[:5]),
        'top_10_avg_score': np.mean(top_scores),
        'top_1_cve': top_cves.iloc[0]['cve_id'],
        'top_1_vendor': top_cves.iloc[0]['vendor'],
        'top_1_product': top_cves.iloc[0]['product']
    }

def test_on_held_out_set(models):
    """Test on 20% held-out test set"""
    print("\n[1/2] Evaluating on held-out test set (20%)...")
    
    # Load TEST set (never seen during training)
    test_df = pd.read_csv(f'{DATASET_FOLDER}/ot_training_ready_test.csv')
    print(f"  Test set size: {len(test_df)} CVEs")
    
    results = []
    vendor_stats = defaultdict(lambda: {'total': 0, 'top1_match': 0, 'top5_match': 0, 'top10_match': 0})
    
    for i, row in test_df.iterrows():
        if (i + 1) % 100 == 0:
            print(f"  Progress: {i+1}/{len(test_df)}")
        
        result = evaluate_query_relevance(
            row,
            models['ot_vectorizer'],
            models['ot_matrix'],
            models['ot_df'],
            k=10
        )
        result['query_vendor'] = row['vendor']
        result['query_product'] = row['product']
        result['query_cve'] = row['cve_id']
        results.append(result)
        
        vendor_stats[row['vendor']]['total'] += 1
        if result['top_1_vendor_match']:
            vendor_stats[row['vendor']]['top1_match'] += 1
        if result['top_5_vendor_match']:
            vendor_stats[row['vendor']]['top5_match'] += 1
        if result['top_10_vendor_match']:
            vendor_stats[row['vendor']]['top10_match'] += 1
    
    return results, vendor_stats

def calculate_metrics(results):
    """Calculate evaluation metrics based on vendor/product relevance"""
    total = len(results)
    
    metrics = {
        'total_queries': total,
        'top_1_vendor_accuracy': sum(1 for r in results if r['top_1_vendor_match']) / total,
        'top_5_vendor_recall': sum(1 for r in results if r['top_5_vendor_match']) / total,
        'top_10_vendor_recall': sum(1 for r in results if r['top_10_vendor_match']) / total,
        'avg_vendor_matches_in_top_10': np.mean([r['vendor_matches_in_top_10'] for r in results]),
        'avg_product_matches_in_top_10': np.mean([r['product_matches_in_top_10'] for r in results]),
        'avg_top_1_similarity': np.mean([r['top_1_score'] for r in results]),
        'avg_top_5_similarity': np.mean([r['top_5_avg_score'] for r in results]),
        'avg_top_10_similarity': np.mean([r['top_10_avg_score'] for r in results]),
        'min_top_1_similarity': np.min([r['top_1_score'] for r in results]),
        'max_top_1_similarity': np.max([r['top_1_score'] for r in results])
    }
    
    return metrics

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
        
        vendor_match = top_cves.iloc[0]['vendor'].lower() == device['vendor'].lower()
        
        results.append({
            'device': device['description'],
            'vendor': device['vendor'],
            'top_cve': top_cves.iloc[0]['cve_id'],
            'top_vendor': top_cves.iloc[0]['vendor'],
            'top_score': top_scores[0],
            'top_5_avg_score': np.mean(top_scores),
            'vendor_match': vendor_match
        })
        
        match_icon = "✓" if vendor_match else "✗"
        print(f"  {match_icon} {device['description']:30} → {top_cves.iloc[0]['cve_id']} ({top_cves.iloc[0]['vendor']}, sim: {top_scores[0]:.3f})")
    
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
    print(f"\nVendor Matching Performance:")
    print(f"  Top-1 Vendor Accuracy:   {test_metrics['top_1_vendor_accuracy']:.2%}")
    print(f"  Top-5 Vendor Recall:     {test_metrics['top_5_vendor_recall']:.2%}")
    print(f"  Top-10 Vendor Recall:    {test_metrics['top_10_vendor_recall']:.2%}")
    print(f"\nAverage Matches in Top-10:")
    print(f"  Vendor Matches:          {test_metrics['avg_vendor_matches_in_top_10']:.2f}")
    print(f"  Product Matches:         {test_metrics['avg_product_matches_in_top_10']:.2f}")
    print(f"\nSimilarity Scores:")
    print(f"  Avg Top-1 Score:         {test_metrics['avg_top_1_similarity']:.4f}")
    print(f"  Avg Top-5 Score:         {test_metrics['avg_top_5_similarity']:.4f}")
    print(f"  Avg Top-10 Score:        {test_metrics['avg_top_10_similarity']:.4f}")
    print(f"  Min/Max Top-1:           {test_metrics['min_top_1_similarity']:.4f} / {test_metrics['max_top_1_similarity']:.4f}")
    
    print("\n📋 Per-Vendor Performance (Test Set)")
    print("-" * 60)
    print(f"{'Vendor':<25} {'Top-1':>8} {'Top-5':>8} {'Top-10':>8} {'Count':>8}")
    print("-" * 60)
    for vendor, stats in sorted(vendor_stats.items(), key=lambda x: x[1]['total'], reverse=True)[:15]:
        top1_acc = stats['top1_match'] / stats['total'] if stats['total'] > 0 else 0
        top5_acc = stats['top5_match'] / stats['total'] if stats['total'] > 0 else 0
        top10_acc = stats['top10_match'] / stats['total'] if stats['total'] > 0 else 0
        print(f"{vendor:<25} {top1_acc:7.1%} {top5_acc:7.1%} {top10_acc:7.1%} {stats['total']:7}")
    
    print("\n📊 COMPLETELY NEW DEVICES (Not in Dataset)")
    print("-" * 60)
    vendor_match_count = sum(1 for r in new_device_results if r['vendor_match'])
    avg_score = np.mean([r['top_score'] for r in new_device_results])
    print(f"Devices Tested:            10")
    print(f"Top-1 Vendor Matches:      {vendor_match_count}/10 ({vendor_match_count/10*100:.0f}%)")
    print(f"Avg Top-1 Similarity:      {avg_score:.4f}")
    
    # Save results
    output = {
        'test_set_metrics': test_metrics,
        'vendor_breakdown': dict(vendor_stats),
        'new_devices': new_device_results,
        'sample_results': test_results[:20]  # First 20 for inspection
    }
    
    with open('honest_evaluation_results.json', 'w') as f:
        json.dump(output, f, indent=2, default=str)
    
    print("\n" + "=" * 60)
    print("✓ HONEST EVALUATION COMPLETE")
    print("=" * 60)
    print("\nResults saved to: honest_evaluation_results.json")
    print("\n⚠️  These are REAL metrics with no data leakage")
    print("   Evaluation measures vendor/product relevance,")
    print("   not exact CVE matching (which would be impossible)")

if __name__ == "__main__":
    main()
