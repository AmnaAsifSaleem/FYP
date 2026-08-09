"""
Improved Policy Compliance Model Trainer
Addresses overfitting from deterministic dataset rules
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_auc_score
from sklearn.model_selection import cross_val_score, StratifiedKFold
import joblib
import os
import matplotlib.pyplot as plt
import seaborn as sns
from policy_preprocessor import load_and_preprocess_data

def train_robust_random_forest():
    """
    Train Random Forest model with techniques to prevent overfitting
    """
    print("=" * 60)
    print("IMPROVED POLICY COMPLIANCE MODEL TRAINING")
    print("=" * 60)
    print("Addressing overfitting from deterministic dataset rules")
    print("=" * 60)
    
    # Load preprocessed data
    X_train, X_test, y_train, y_test, feature_names = load_and_preprocess_data()
    
    print(f"\nTraining set: {X_train.shape}")
    print(f"Test set: {X_test.shape}")
    
    # 1. CROSS-VALIDATION (instead of single split)
    print("\n" + "=" * 60)
    print("CROSS-VALIDATION ANALYSIS")
    print("=" * 60)
    
    # Simple model for cross-validation
    cv_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=10,
        min_samples_leaf=4,
        max_features='sqrt',
        bootstrap=True,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )
    
    # 5-fold cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(cv_model, X_train, y_train, 
                                cv=cv, scoring='accuracy', n_jobs=-1)
    
    print(f"Cross-validation accuracy scores: {cv_scores}")
    print(f"Mean CV accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    # 2. TRAIN FINAL MODEL WITH REGULARIZATION
    print("\n" + "=" * 60)
    print("TRAINING FINAL MODEL WITH REGULARIZATION")
    print("=" * 60)
    
    # More conservative hyperparameters to prevent overfitting
    rf_model = RandomForestClassifier(
        n_estimators=150,           # Reduced from 200
        max_depth=12,               # Reduced from 15 (shallower trees)
        min_samples_split=10,       # Increased from 5 (more samples to split)
        min_samples_leaf=5,         # Increased from 2 (larger leaf nodes)
        max_features='sqrt',        # Consider fewer features per split
        bootstrap=True,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced',
        max_samples=0.8,            # Use only 80% of samples per tree
        ccp_alpha=0.01              # Cost complexity pruning
    )
    
    rf_model.fit(X_train, y_train)
    print("Model training complete with regularization!")
    
    # 3. EVALUATE ON TEST SET
    print("\n" + "=" * 60)
    print("MODEL EVALUATION ON TEST SET")
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
    
    # Calculate error analysis
    print("\n" + "=" * 60)
    print("ERROR ANALYSIS")
    print("=" * 60)
    
    # Find misclassified samples
    misclassified_mask = y_pred != y_test
    if misclassified_mask.any():
        misclassified_count = misclassified_mask.sum()
        print(f"Misclassified samples: {misclassified_count}/{len(y_test)} ({misclassified_count/len(y_test)*100:.1f}%)")
        
        # Analyze misclassifications
        X_test_misclassified = X_test[misclassified_mask]
        y_test_misclassified = y_test[misclassified_mask]
        y_pred_misclassified = y_pred[misclassified_mask]
        
        # Check if misclassifications are in deterministic rule areas
        print("\nAnalyzing misclassifications...")
        
        # Convert back to original feature space if possible
        # For now, just show counts
        false_positives = ((y_test_misclassified == 0) & (y_pred_misclassified == 1)).sum()
        false_negatives = ((y_test_misclassified == 1) & (y_pred_misclassified == 0)).sum()
        
        print(f"False Positives (NON_COMPLIANT → COMPLIANT): {false_positives}")
        print(f"False Negatives (COMPLIANT → NON_COMPLIANT): {false_negatives}")
    else:
        print("WARNING: No misclassifications found!")
        print("This suggests the test set follows the same deterministic rules as training.")
        print("The model may still overfit on real-world data.")
    
    # 4. FEATURE IMPORTANCE
    print("\n" + "=" * 60)
    print("FEATURE IMPORTANCE ANALYSIS")
    print("=" * 60)
    
    feature_importance = pd.DataFrame({
        'feature': feature_names,
        'importance': rf_model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\nTop 15 Most Important Features:")
    print(feature_importance.head(15))
    
    # Check if importance is too concentrated
    top_3_importance = feature_importance.head(3)['importance'].sum()
    print(f"\nTop 3 features account for {top_3_importance*100:.1f}% of importance")
    
    if top_3_importance > 0.8:
        print("WARNING: Feature importance is too concentrated!")
        print("This may indicate the model is relying on a few deterministic rules.")
    
    # 5. SAVE MODEL
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    os.makedirs(models_dir, exist_ok=True)
    
    model_path = os.path.join(models_dir, 'policy_compliance_model_improved.pkl')
    importance_path = os.path.join(models_dir, 'feature_importance_improved.csv')
    
    joblib.dump(rf_model, model_path)
    feature_importance.to_csv(importance_path, index=False)
    
    print(f"\nImproved model saved to: {model_path}")
    print(f"Feature importance saved to: {importance_path}")
    
    # 6. CREATE VISUALIZATIONS
    print("\nCreating visualizations...")
    create_improved_visualizations(feature_importance, cm, cv_scores)
    
    return rf_model, feature_importance

def create_improved_visualizations(feature_importance, cm, cv_scores):
    """
    Create visualization plots for the improved model
    """
    try:
        import matplotlib.pyplot as plt
        import seaborn as sns
        
        # Set style
        plt.style.use('seaborn-v0_8-darkgrid')
        
        plots_dir = os.path.join(os.path.dirname(__file__), 'plots')
        os.makedirs(plots_dir, exist_ok=True)
        
        # 1. Cross-Validation Scores
        plt.figure(figsize=(10, 6))
        plt.bar(range(1, len(cv_scores) + 1), cv_scores)
        plt.axhline(y=cv_scores.mean(), color='r', linestyle='--', label=f'Mean: {cv_scores.mean():.4f}')
        plt.xlabel('Fold')
        plt.ylabel('Accuracy')
        plt.title('5-Fold Cross-Validation Accuracy Scores')
        plt.ylim([0.9, 1.01])
        plt.legend()
        plt.grid(True, alpha=0.3)
        
        plt.savefig(os.path.join(plots_dir, 'cross_validation_scores.png'), 
                   bbox_inches='tight', dpi=150)
        plt.close()
        
        # 2. Feature Importance Plot
        plt.figure(figsize=(12, 8))
        top_features = feature_importance.head(15)
        colors = plt.cm.viridis(np.linspace(0.3, 0.9, len(top_features)))
        plt.barh(range(len(top_features)), top_features['importance'], color=colors)
        plt.yticks(range(len(top_features)), top_features['feature'])
        plt.xlabel('Feature Importance')
        plt.title('Top 15 Feature Importances (Improved Model)')
        plt.gca().invert_yaxis()
        
        plt.savefig(os.path.join(plots_dir, 'feature_importance_improved.png'), 
                   bbox_inches='tight', dpi=150)
        plt.close()
        
        # 3. Confusion Matrix Heatmap
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=['NON_COMPLIANT', 'COMPLIANT'],
                   yticklabels=['NON_COMPLIANT', 'COMPLIANT'])
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        plt.title('Confusion Matrix (Improved Model)')
        
        plt.savefig(os.path.join(plots_dir, 'confusion_matrix_improved.png'), 
                   bbox_inches='tight', dpi=150)
        plt.close()
        
        print(f"Visualizations saved to: {plots_dir}/")
        
    except Exception as e:
        print(f"Warning: Could not create visualizations: {e}")

def test_model_robustness(rf_model):
    """
    Test the model with edge cases and noisy data
    """
    print("\n" + "=" * 60)
    print("MODEL ROBUSTNESS TESTING")
    print("=" * 60)
    
    # Load preprocessing objects
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    label_encoders = joblib.load(os.path.join(models_dir, 'label_encoders.pkl'))
    scaler = joblib.load(os.path.join(models_dir, 'scaler.pkl'))
    
    from policy_preprocessor import prepare_single_asset
    
    # Test cases designed to challenge deterministic rules
    test_cases = [
        {
            'name': 'Edge Case 1: High CVSS but Secure',
            'asset': {
                'device_type': 'Firewall',
                'vendor': 'Fortinet',
                'zone': 'IT',
                'service': 'HTTPS',
                'port': 443,
                'encrypted': 1,
                'cvss': 8.5,  # High CVSS but encrypted HTTPS
                'epss': 0.02,
                'kev': 0,
                'c_impact': 0.8,
                'i_impact': 0.8,
                'a_impact': 0.8,
                'criticality': 0.9,
                'days_since_patch': 5,
                'firmware_eol': 0,
                'alert_count': 0
            },
            'expected': 'COMPLIANT'  # Should be compliant despite high CVSS
        },
        {
            'name': 'Edge Case 2: Low CVSS but Insecure',
            'asset': {
                'device_type': 'PLC',
                'vendor': 'Siemens',
                'zone': 'OT',
                'service': 'HTTP',  # Insecure protocol
                'port': 80,
                'encrypted': 0,
                'cvss': 3.5,  # Low CVSS
                'epss': 0.01,
                'kev': 0,
                'c_impact': 0.2,
                'i_impact': 0.2,
                'a_impact': 0.2,
                'criticality': 0.7,
                'days_since_patch': 100,
                'firmware_eol': 0,
                'alert_count': 2
            },
            'expected': 'NON_COMPLIANT'  # Should be non-compliant despite low CVSS
        },
        {
            'name': 'Edge Case 3: Mixed Signals',
            'asset': {
                'device_type': 'RTU',
                'vendor': 'ABB',
                'zone': 'OT',
                'service': 'Modbus',
                'port': 502,
                'encrypted': 0,
                'cvss': 6.5,  # Medium CVSS
                'epss': 0.08,  # Medium EPSS
                'kev': 0,
                'c_impact': 0.5,
                'i_impact': 0.5,
                'a_impact': 0.5,
                'criticality': 0.8,
                'days_since_patch': 45,
                'firmware_eol': 0,
                'alert_count': 1
            },
            'expected': 'NEEDS_REVIEW'  # Ambiguous case
        }
    ]
    
    for test_case in test_cases:
        print(f"\n{test_case['name']}:")
        print(f"  Device: {test_case['asset']['device_type']} ({test_case['asset']['vendor']})")
        print(f"  Service: {test_case['asset']['service']}:{test_case['asset']['port']} in {test_case['asset']['zone']}")
        print(f"  Encrypted: {bool(test_case['asset']['encrypted'])}, CVSS: {test_case['asset']['cvss']}, EPSS: {test_case['asset']['epss']}")
        
        # Prepare asset
        prepared_asset = prepare_single_asset(test_case['asset'], label_encoders, scaler)
        
        # Predict
        prediction = rf_model.predict(prepared_asset)[0]
        probability = rf_model.predict_proba(prepared_asset)[0][1]
        
        status = "COMPLIANT" if prediction == 1 else "NON_COMPLIANT"
        confidence = probability if prediction == 1 else 1 - probability
        
        print(f"  Prediction: {status}")
        print(f"  Confidence: {confidence:.3f}")
        print(f"  Compliance Score: {probability:.3f}")
        
        # Check if prediction matches expected
        if test_case['expected'] in ['COMPLIANT', 'NON_COMPLIANT']:
            expected_numeric = 1 if test_case['expected'] == 'COMPLIANT' else 0
            if prediction == expected_numeric:
                print(f"  ✓ Matches expected: {test_case['expected']}")
            else:
                print(f"  ✗ Does not match expected: {test_case['expected']}")

def main():
    """
    Main function to train improved model
    """
    print("=" * 60)
    print("IMPROVED POLICY COMPLIANCE MODEL TRAINING")
    print("=" * 60)
    print("\nThis version addresses overfitting by:")
    print("1. Using cross-validation instead of single split")
    print("2. Adding regularization (shallower trees, more samples per split)")
    print("3. Analyzing misclassifications and feature concentration")
    print("4. Testing with edge cases")
    print("=" * 60)
    
    # Train improved model
    rf_model, feature_importance = train_robust_random_forest()
    
    # Test model robustness
    test_model_robustness(rf_model)
    
    print("\n" + "=" * 60)
    print("IMPROVED TRAINING COMPLETE!")
    print("=" * 60)
    
    print("\nRecommendations for real-world deployment:")
    print("1. The dataset has deterministic rules - consider adding noise/ambiguity")
    print("2. Monitor model performance on real assets over time")
    print("3. Consider ensemble methods for better generalization")
    print("4. Regularly retrain with new, real-world data")
    
    print("\nTo use the improved model, update policy_predictor.py to load:")
    print("  'policy_compliance_model_improved.pkl' instead of 'policy_compliance_model.pkl'")

if __name__ == "__main__":
    main()