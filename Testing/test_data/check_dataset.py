#!/usr/bin/env python3
"""
Check the policy dataset
"""

import pandas as pd
import os
import sys

# Add project root to path
project_root = os.path.join(os.path.dirname(__file__), '..', '..')
sys.path.insert(0, project_root)

dataset_path = os.path.join(project_root, "Datasets", "policy_dataset.csv")

print("Loading policy dataset...")
df = pd.read_csv(dataset_path)

print(f"Dataset shape: {df.shape}")
print(f"Columns ({len(df.columns)}):")
for i, col in enumerate(df.columns):
    print(f"  {i+1}. {col}")

print(f"\nFirst 3 rows:")
print(df.head(3))

print(f"\nCompliance status distribution:")
print(df['compliance_status'].value_counts())

# Check what features are used for training (excluding metadata columns)
metadata_cols = ['compliance_status', 'violated_policy', 'remediation', 'policy_source', 'severity']
feature_cols = [col for col in df.columns if col not in metadata_cols]

print(f"\nFeatures used for training ({len(feature_cols)}):")
for i, col in enumerate(feature_cols):
    print(f"  {i+1}. {col}")