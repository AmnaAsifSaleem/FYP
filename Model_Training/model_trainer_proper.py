"""
CAVE-OT Model Trainer (Proper Version)
Trains ONLY on train split (80%) to avoid data leakage
"""

import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import joblib
import os
from tqdm import tqdm

DATASET_FOLDER = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model")

def build_corpus(df):
    """Build text corpus from CVE data with weighted vendor/product"""
    print(f"Building corpus from {len(df)} CVEs...")
    corpus = []
    for _, row in tqdm(df.iterrows(), total=len(df), desc="Processing"):
        vendor = str(row['vendor']) * 3
        product = str(row['product']) * 2
        desc = str(row['description'])
        corpus.append(f'{vendor} {product} {desc}')
    return corpus

def main():
    print("=" * 60)
    print("CAVE-OT MODEL TRAINER (PROPER - NO DATA LEAKAGE)")
    print("=" * 60)
    
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)
    print(f"\n[+] Output directory: {OUTPUT_FOLDER}")
    
    # Load TRAIN sets only
    print(f"\n[1/4] Loading TRAIN datasets only...")
    df_full_train = pd.read_csv(f'{DATASET_FOLDER}/training_ready_train.csv')
    df_ot_train = pd.read_csv(f'{DATASET_FOLDER}/ot_training_ready_train.csv')
    print(f"  ✓ General CVEs (train): {len(df_full_train):,} rows")
    print(f"  ✓ OT CVEs (train): {len(df_ot_train):,} rows")
    
    # Build corpora
    print(f"\n[2/4] Building text corpora...")
    general_corpus = build_corpus(df_full_train)
    ot_corpus = build_corpus(df_ot_train)
    
    # Stage 1: General training
    print(f"\n[3/4] Stage 1: Training general model...")
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
    joblib.dump(df_full_train, f'{OUTPUT_FOLDER}/cve_database.pkl')
    print(f"  ✓ Saved general model files")
    
    # Stage 2: OT fine-tuning
    print(f"\n[4/4] Stage 2: OT fine-tuning...")
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
    joblib.dump(df_ot_train, f'{OUTPUT_FOLDER}/ot_cve_database.pkl')
    print(f"  ✓ Saved OT model files")
    
    print("\n" + "=" * 60)
    print("✓ TRAINING COMPLETE (ON TRAIN SET ONLY)")
    print("=" * 60)
    print(f"\nModel files saved to: {OUTPUT_FOLDER}")
    print("\n⚠️  Models trained on 80% train split only")
    print("   Ready for honest evaluation on 20% test set")
    print("\nNext step: python proper_evaluator.py")

if __name__ == "__main__":
    main()
