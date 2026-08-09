"""
CAVE-OT Model Trainer
Trains TF-IDF similarity models in two stages:
1. General training on all CVEs (206k rows)
2. OT fine-tuning on ICS-specific CVEs (6k rows)
"""

import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import joblib
import os
import sys
from tqdm import tqdm

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pipeline_paths import DATASET_FOLDER, MODEL_FOLDER as OUTPUT_FOLDER

def build_corpus(df):
    """Build text corpus from CVE data with weighted vendor/product"""
    print(f"Building corpus from {len(df)} CVEs...")
    corpus = []
    for _, row in tqdm(df.iterrows(), total=len(df), desc="Processing"):
        vendor = str(row['vendor']) * 3  # Higher weight
        product = str(row['product']) * 2  # Medium weight
        desc = str(row['description'])
        corpus.append(f'{vendor} {product} {desc}')
    return corpus

def test_query(query, vectorizer, matrix, df, top_n=5, threshold=0.10):
    """Test query against trained model"""
    q_vec = vectorizer.transform([query])
    scores = cosine_similarity(q_vec, matrix).flatten()
    top_idx = scores.argsort()[-top_n:][::-1]
    results = df.iloc[top_idx].copy()
    results['similarity'] = scores[top_idx]
    return results[results['similarity'] >= threshold][
        ['cve_id', 'vendor', 'product', 'cvss', 'epss', 'kev', 'similarity']
    ]

def main():
    print("=" * 60)
    print("CAVE-OT MODEL TRAINER")
    print("=" * 60)
    
    # Create output directory
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)
    print(f"\n[+] Output directory: {OUTPUT_FOLDER}")
    
    # Load datasets
    print(f"\n[1/5] Loading datasets...")
    df_full = pd.read_csv(f'{DATASET_FOLDER}/training_ready.csv')
    df_ot = pd.read_csv(f'{DATASET_FOLDER}/ot_training_ready.csv')
    print(f"  ✓ General CVEs: {len(df_full):,} rows")
    print(f"  ✓ OT CVEs: {len(df_ot):,} rows")
    
    # Build corpora
    print(f"\n[2/5] Building text corpora...")
    general_corpus = build_corpus(df_full)
    ot_corpus = build_corpus(df_ot)
    
    # Stage 1: General training
    print(f"\n[3/5] Stage 1: Training general model...")
    general_vectorizer = TfidfVectorizer(
        analyzer='word',
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.95,
        max_features=50000,
        sublinear_tf=True
    )
    
    general_matrix = general_vectorizer.fit_transform(general_corpus)
    print(f"  ✓ Matrix shape: {general_matrix.shape}")
    print(f"  ✓ Vocabulary size: {len(general_vectorizer.vocabulary_):,}")
    
    joblib.dump(general_vectorizer, f'{OUTPUT_FOLDER}/general_vectorizer.pkl')
    joblib.dump(general_matrix, f'{OUTPUT_FOLDER}/general_matrix.pkl')
    joblib.dump(df_full, f'{OUTPUT_FOLDER}/cve_database.pkl')
    print(f"  ✓ Saved general model files")
    
    # Stage 2: OT fine-tuning
    print(f"\n[4/5] Stage 2: OT fine-tuning...")
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
    print(f"  ✓ Matrix shape: {ot_matrix.shape}")
    
    joblib.dump(ot_vectorizer, f'{OUTPUT_FOLDER}/ot_vectorizer.pkl')
    joblib.dump(ot_matrix, f'{OUTPUT_FOLDER}/ot_matrix.pkl')
    joblib.dump(df_ot, f'{OUTPUT_FOLDER}/ot_cve_database.pkl')
    print(f"  ✓ Saved OT model files")
    
    # Validation tests
    print(f"\n[5/5] Running validation tests...")
    
    print("\n" + "=" * 60)
    print("TEST 1: Schneider Modicon M340")
    print("=" * 60)
    results = test_query(
        'schneider electric modicon m340 2.39 modbus',
        ot_vectorizer, ot_matrix, df_ot
    )
    if len(results) > 0:
        print(results.to_string(index=False))
    else:
        print("No matches found")
    
    print("\n" + "=" * 60)
    print("TEST 2: Siemens S7-300")
    print("=" * 60)
    results = test_query(
        'siemens simatic s7-300 v3.2 s7comm',
        ot_vectorizer, ot_matrix, df_ot
    )
    if len(results) > 0:
        print(results.to_string(index=False))
    else:
        print("No matches found")
    
    print("\n" + "=" * 60)
    print("TEST 3: Rockwell ControlLogix")
    print("=" * 60)
    results = test_query(
        'rockwell automation controllogix 1756 ethernet ip',
        ot_vectorizer, ot_matrix, df_ot
    )
    if len(results) > 0:
        print(results.to_string(index=False))
    else:
        print("No matches found")
    
    print("\n" + "=" * 60)
    print("✓ TRAINING COMPLETE")
    print("=" * 60)
    print(f"\nModel files saved to: {OUTPUT_FOLDER}")
    print("\nNext steps:")
    print("  1. Run: python cve_mapper.py")
    print("  2. Run: python risk_scorer.py")

if __name__ == "__main__":
    main()
