"""
Policy Compliance Data Preprocessor
Loads and preprocesses the policy_dataset.csv for Random Forest training
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import os

def load_and_preprocess_data():
    """
    Load policy dataset, preprocess features, and split into train/test sets
    Returns: X_train, X_test, y_train, y_test, feature_names
    """
    print("Loading policy dataset...")
    
    # Load dataset - using the original dataset
    dataset_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                               'Datasets', 'policy_dataset.csv')
    df = pd.read_csv(dataset_path)
    
    print(f"Dataset loaded: {df.shape[0]} samples, {df.shape[1]} features")
    print(f"Compliance status distribution:\n{df['compliance_status'].value_counts()}")
    
    # Handle target variable (compliance_status)
    # Convert to binary: COMPLIANT=1, NON_COMPLIANT/NEEDS_REVIEW=0
    df['target'] = df['compliance_status'].apply(lambda x: 1 if x == 'COMPLIANT' else 0)
    
    # Separate features and target
    # Drop columns that won't be used as features
    features = df.drop(['compliance_status', 'target', 'violated_policy', 
                       'remediation', 'policy_source', 'severity'], axis=1)
    target = df['target']
    
    # Identify categorical and numerical columns
    categorical_cols = ['device_type', 'vendor', 'zone', 'service']
    numerical_cols = ['port', 'encrypted', 'cvss', 'epss', 'kev', 'c_impact', 
                     'i_impact', 'a_impact', 'criticality', 'days_since_patch', 
                     'firmware_eol', 'alert_count']
    
    print(f"\nCategorical features: {categorical_cols}")
    print(f"Numerical features: {numerical_cols}")
    
    # Encode categorical variables
    print("\nEncoding categorical variables...")
    label_encoders = {}
    for col in categorical_cols:
        le = LabelEncoder()
        features[col] = le.fit_transform(features[col])
        label_encoders[col] = le
        print(f"  {col}: {len(le.classes_)} unique values")
    
    # Scale numerical features
    print("Scaling numerical features...")
    scaler = StandardScaler()
    features[numerical_cols] = scaler.fit_transform(features[numerical_cols])
    
    # Split data (80% train, 20% test)
    print("\nSplitting data into train/test sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        features, target, test_size=0.2, random_state=42, stratify=target
    )
    
    print(f"Training set: {X_train.shape}")
    print(f"Test set: {X_test.shape}")
    
    # Save encoders and scaler for later use
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    os.makedirs(models_dir, exist_ok=True)
    
    joblib.dump(label_encoders, os.path.join(models_dir, 'label_encoders.pkl'))
    joblib.dump(scaler, os.path.join(models_dir, 'scaler.pkl'))
    
    print(f"\nPreprocessing objects saved to: {models_dir}/")
    
    return X_train, X_test, y_train, y_test, features.columns.tolist()

def prepare_single_asset(asset_data, label_encoders, scaler):
    """
    Prepare a single asset for prediction
    asset_data: dict with asset features
    Returns: prepared DataFrame
    """
    # Convert to DataFrame
    df = pd.DataFrame([asset_data])
    
    # Encode categorical variables
    for col, encoder in label_encoders.items():
        if col in df.columns:
            # Handle unseen categories by using a default value
            if df[col].iloc[0] not in encoder.classes_:
                print(f"Warning: Unknown category '{df[col].iloc[0]}' for feature '{col}'")
                # Use the most common class as default
                df[col] = encoder.transform([encoder.classes_[0]])[0]
            else:
                df[col] = encoder.transform([df[col].iloc[0]])[0]
    
    # Scale numerical features
    numerical_cols = ['port', 'encrypted', 'cvss', 'epss', 'kev', 'c_impact', 
                     'i_impact', 'a_impact', 'criticality', 'days_since_patch', 
                     'firmware_eol', 'alert_count']
    
    # Only scale columns that exist
    existing_num_cols = [col for col in numerical_cols if col in df.columns]
    if existing_num_cols:
        df[existing_num_cols] = scaler.transform(df[existing_num_cols])
    
    return df

if __name__ == "__main__":
    # Test the preprocessing
    X_train, X_test, y_train, y_test, feature_names = load_and_preprocess_data()
    
    print(f"\nFeature names: {feature_names}")
    print(f"\nSample of training data (first 3 rows):")
    print(X_train.head(3))
    
    # Test single asset preparation
    print("\nTesting single asset preparation...")
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    label_encoders = joblib.load(os.path.join(models_dir, 'label_encoders.pkl'))
    scaler = joblib.load(os.path.join(models_dir, 'scaler.pkl'))
    
    sample_asset = {
        'device_type': 'PLC',
        'vendor': 'Siemens',
        'zone': 'OT',
        'service': 'S7comm',
        'port': 102,
        'encrypted': 0,
        'cvss': 7.5,
        'epss': 0.05,
        'kev': 0,
        'c_impact': 0.5,
        'i_impact': 0.5,
        'a_impact': 0.5,
        'criticality': 0.8,
        'days_since_patch': 30,
        'firmware_eol': 0,
        'alert_count': 2
    }
    
    prepared_asset = prepare_single_asset(sample_asset, label_encoders, scaler)
    print(f"Prepared asset shape: {prepared_asset.shape}")
    print(f"Prepared asset columns: {prepared_asset.columns.tolist()}")