"""
Policy Compliance Model Trainer
Trains a Random Forest classifier to predict policy compliance
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_auc_score
import joblib
import os
import matplotlib.pyplot as plt
import seaborn as sns
from policy_preprocessor import load_and_preprocess_data

def train_random_forest():
    """
    Train Random Forest model and evaluate performance
    """
    print("=" * 60)
    print("POLICY COMPLIANCE MODEL TRAINING")
    print("=" * 60)
    
    # Load preprocessed data
    X_train, X_test, y_train, y_test, feature_names = load_and_preprocess_data()
    
    print("\nTraining Random Forest model...")
    
    # Train Random Forest with optimized hyperparameters
    rf_model = RandomForestClassifier(
        n_estimators=200,           # Number of trees
        max_depth=15,               # Maximum depth of trees
        min_samples_split=5,        # Minimum samples to split a node
        min_samples_leaf=2,         # Minimum samples at a leaf node
        max_features='sqrt',        # Number of features to consider for best split
        bootstrap=True,             # Use bootstrap samples
        random_state=42,            # For reproducibility
        n_jobs=-1,                  # Use all available cores
        class_weight='balanced'     # Handle class imbalance
    )
    
    rf_model.fit(X_train, y_train)
    
    print("Model training complete!")
    
    # Evaluate on test set
    print("\n" + "=" * 60)
    print("MODEL EVALUATION")
    print("=" * 60)
    
    y_pred = rf_model.predict(X_test)
    y_pred_proba = rf_model.predict_proba(X_test)[:, 1]
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    auc_score = roc_auc_score(y_test, y_pred_proba)
    
    print(f"\nAccuracy: {accuracy:.4f}")
    print(f"AUC-ROC Score: {auc_score:.4f}")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['NON_COMPLIANT', 'COMPLIANT']))
    
    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    print("\nConfusion Matrix:")
    print(cm)
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': feature_names,
        'importance': rf_model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\n" + "=" * 60)
    print("FEATURE IMPORTANCE ANALYSIS")
    print("=" * 60)
    
    print("\nTop 15 Most Important Features:")
    print(feature_importance.head(15))
    
    # Save model and feature importance
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    os.makedirs(models_dir, exist_ok=True)
    
    model_path = os.path.join(models_dir, 'policy_compliance_model.pkl')
    importance_path = os.path.join(models_dir, 'feature_importance.csv')
    
    joblib.dump(rf_model, model_path)
    feature_importance.to_csv(importance_path, index=False)
    
    print(f"\nModel saved to: {model_path}")
    print(f"Feature importance saved to: {importance_path}")
    
    # Create visualizations
    print("\nCreating visualizations...")
    create_visualizations(feature_importance, cm, y_test, y_pred_proba)
    
    return rf_model, feature_importance

def create_visualizations(feature_importance, cm, y_test, y_pred_proba):
    """
    Create visualization plots
    """
    try:
        import matplotlib.pyplot as plt
        import seaborn as sns
        
        # Set style
        plt.style.use('seaborn-v0_8-darkgrid')
        
        # 1. Feature Importance Plot
        plt.figure(figsize=(12, 8))
        top_features = feature_importance.head(15)
        plt.barh(range(len(top_features)), top_features['importance'])
        plt.yticks(range(len(top_features)), top_features['feature'])
        plt.xlabel('Feature Importance')
        plt.title('Top 15 Feature Importances for Policy Compliance Prediction')
        plt.gca().invert_yaxis()
        
        plots_dir = os.path.join(os.path.dirname(__file__), 'plots')
        os.makedirs(plots_dir, exist_ok=True)
        
        plt.savefig(os.path.join(plots_dir, 'feature_importance.png'), 
                   bbox_inches='tight', dpi=150)
        plt.close()
        
        # 2. Confusion Matrix Heatmap
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=['NON_COMPLIANT', 'COMPLIANT'],
                   yticklabels=['NON_COMPLIANT', 'COMPLIANT'])
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.title('Confusion Matrix')
        
        plt.savefig(os.path.join(plots_dir, 'confusion_matrix.png'), 
                   bbox_inches='tight', dpi=150)
        plt.close()
        
        print(f"Visualizations saved to: {plots_dir}/")
        
    except Exception as e:
        print(f"Warning: Could not create visualizations: {e}")

def test_model_with_samples(rf_model):
    """
    Test the trained model with sample assets
    """
    print("\n" + "=" * 60)
    print("SAMPLE PREDICTIONS")
    print("=" * 60)
    
    # Load preprocessing objects
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    label_encoders = joblib.load(os.path.join(models_dir, 'label_encoders.pkl'))
    scaler = joblib.load(os.path.join(models_dir, 'scaler.pkl'))
    
    # Sample assets for testing
    sample_assets = [
        {
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
        },
        {
            'device_type': 'Firewall',
            'vendor': 'Cisco',
            'zone': 'IT',
            'service': 'HTTPS',
            'port': 443,
            'encrypted': 1,
            'cvss': 3.5,
            'epss': 0.01,
            'kev': 0,
            'c_impact': 0.2,
            'i_impact': 0.2,
            'a_impact': 0.2,
            'criticality': 0.9,
            'days_since_patch': 10,
            'firmware_eol': 0,
            'alert_count': 0
        },
        {
            'device_type': 'RTU',
            'vendor': 'ABB',
            'zone': 'SCADA_Zone',
            'service': 'Modbus',
            'port': 502,
            'encrypted': 0,
            'cvss': 9.8,
            'epss': 0.8,
            'kev': 1,
            'c_impact': 0.8,
            'i_impact': 0.8,
            'a_impact': 0.8,
            'criticality': 0.95,
            'days_since_patch': 365,
            'firmware_eol': 1,
            'alert_count': 10
        }
    ]
    
    from policy_preprocessor import prepare_single_asset
    
    for i, asset in enumerate(sample_assets, 1):
        print(f"\nSample Asset {i}:")
        print(f"  Device: {asset['device_type']} ({asset['vendor']})")
        print(f"  Zone: {asset['zone']}, Service: {asset['service']}:{asset['port']}")
        print(f"  Encrypted: {bool(asset['encrypted'])}, CVSS: {asset['cvss']}, EPSS: {asset['epss']}")
        
        # Prepare asset
        prepared_asset = prepare_single_asset(asset, label_encoders, scaler)
        
        # Predict
        prediction = rf_model.predict(prepared_asset)[0]
        probability = rf_model.predict_proba(prepared_asset)[0][1]
        
        status = "COMPLIANT" if prediction == 1 else "NON_COMPLIANT"
        confidence = probability if prediction == 1 else 1 - probability
        
        print(f"  Prediction: {status}")
        print(f"  Confidence: {confidence:.3f}")
        print(f"  Compliance Score: {probability:.3f}")

if __name__ == "__main__":
    # Train and evaluate model
    rf_model, feature_importance = train_random_forest()
    
    # Test with sample assets
    test_model_with_samples(rf_model)
    
    print("\n" + "=" * 60)
    print("TRAINING COMPLETE!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Use policy_predictor.py to check your assets")
    print("2. Integrate with the main dashboard")
    print("3. Update database schema to store compliance results")