#!/usr/bin/env python3
"""
Test to see what features the model expects
"""

import pickle
import os
import sys

# Add project root to path
project_root = os.path.join(os.path.dirname(__file__), '..', '..')
sys.path.insert(0, project_root)

# Load the model
model_path = os.path.join(project_root, "Policy_Compliance", "models", "policy_compliance_model.pkl")
scaler_path = os.path.join(project_root, "Policy_Compliance", "models", "scaler.pkl")
encoders_path = os.path.join(project_root, "Policy_Compliance", "models", "label_encoders.pkl")

print("Loading model and preprocessor...")
try:
    # Try using joblib first (which is what was used to save the files)
    import joblib
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    label_encoders = joblib.load(encoders_path)
    print("Loaded with joblib")
except ImportError:
    print("joblib not available, using pickle")
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    with open(scaler_path, 'rb') as f:
        scaler = pickle.load(f)
    with open(encoders_path, 'rb') as f:
        label_encoders = pickle.load(f)

print("\nModel type:", type(model))
print("Model feature names:", model.feature_names_in_ if hasattr(model, 'feature_names_in_') else "No feature_names_in_ attribute")

print("\nScaler type:", type(scaler))
print("Label encoders type:", type(label_encoders))

# Check if label_encoders is a dictionary
if isinstance(label_encoders, dict):
    print("Label encoders keys:", list(label_encoders.keys()))
    for key, encoder in label_encoders.items():
        print(f"  {key}: {len(encoder.classes_)} classes")
else:
    print("Label encoders is not a dictionary, it's a:", type(label_encoders))
    print("Content:", label_encoders)

# Check what features were used during training
if hasattr(model, 'feature_names_in_'):
    print(f"\nModel expects {len(model.feature_names_in_)} features:")
    for i, feature in enumerate(model.feature_names_in_):
        print(f"  {i+1}. {feature}")
else:
    print("\nModel doesn't have feature_names_in_ attribute")
    print("Trying to get feature names from training data...")
    
    # Try to load the training data to see features
    import pandas as pd
    try:
        dataset_path = os.path.join(project_root, "Datasets", "policy_dataset.csv")
        df = pd.read_csv(dataset_path)
        print(f"\nDataset has {len(df.columns)} columns:")
        for i, col in enumerate(df.columns):
            print(f"  {i+1}. {col}")
    except Exception as e:
        print(f"Could not load dataset: {e}")