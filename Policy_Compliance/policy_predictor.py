"""
Updated Policy Compliance Predictor with better explanations
"""

import pandas as pd
import numpy as np
import joblib
import os
import sys

class PolicyCompliancePredictor:
    """
    Predict policy compliance for OT/IT assets with clear explanations
    """
    
    def __init__(self, model_dir=None):
        """
        Initialize predictor with trained model
        """
        if model_dir is None:
            model_dir = os.path.join(os.path.dirname(__file__), 'models')
        
        self.model_dir = model_dir
        
        # Load model and preprocessing objects
        try:
            self.model = joblib.load(os.path.join(model_dir, 'policy_compliance_model.pkl'))
            self.label_encoders = joblib.load(os.path.join(model_dir, 'label_encoders.pkl'))
            self.scaler = joblib.load(os.path.join(model_dir, 'scaler.pkl'))
            self._model_loaded = True
            print(f"✓ Policy compliance model loaded from {model_dir}")
        except Exception as e:
            self._model_loaded = False
            self._load_error = str(e)
            print(f"✗ Error loading policy model: {e}")
            print("  Policy compliance predictions will be unavailable until the model is trained.")
    
    def prepare_asset(self, asset_data):
        """
        Prepare a single asset for prediction
        asset_data: dict with asset features
        Returns: prepared DataFrame
        """
        # Convert to DataFrame
        df = pd.DataFrame([asset_data])
        
        # Intelligent mapping for unknown categories
        category_mapping = {
            'device_type': {
                # Water treatment plant specific → generic training types
                'Dosing_Pump_PLC':        'PLC',
                'Filtration_PLC':         'PLC',
                'Turbidity_Sensor_PLC':   'PLC',
                'UV_Disinfection_PLC':    'PLC',
                'Reservoir_Level_PLC':    'PLC',
                'Booster_Pump_PLC':       'PLC',
                'Water_Level_RTU':        'RTU',
                'Flow_Meter_RTU':         'RTU',
                'WaterQuality_Sensor':    'Sensor',
                'Ventilation_Controller': 'PLC',
                'HMI_Interface':          'HMI',
                'Backup_HMI_Interface':   'HMI',
                'SCADA_Server':           'SCADA',
                'Historian':              'Historian',
                'Engineering_WS':        'Engineering_WS',
                'DMZ_Gateway':            'Gateway',
            },
            'vendor': {
                'General Electric': 'GE',
                'Schneider Electric': 'Schneider Electric',
            },
            'service': {
                'BACnet': 'EtherNet/IP',  # BACnet is similar to Ethernet/IP
                'IPMI':   'SSH',          # IPMI is a management protocol like SSH
            }
        }
        
        # Encode categorical variables
        for col, encoder in self.label_encoders.items():
            if col in df.columns:
                original_value = df[col].iloc[0]
                if original_value is None or (isinstance(original_value, float) and pd.isna(original_value)):
                    original_value = 'Unknown'
                mapped_value = original_value
                
                # Apply intelligent mapping if available
                if col in category_mapping and original_value in category_mapping[col]:
                    mapped_value = category_mapping[col][original_value]
                    print(f"Info: Mapped '{original_value}' → '{mapped_value}' for feature '{col}'")
                
                # Handle unseen categories
                if mapped_value not in encoder.classes_:
                    print(f"Warning: Unknown category '{original_value}' for feature '{col}'")
                    # Find the most similar category based on string similarity
                    from difflib import get_close_matches
                    matches = get_close_matches(mapped_value, encoder.classes_, n=1, cutoff=0.3)
                    if matches:
                        best_match = matches[0]
                        print(f"  Using closest match: '{best_match}'")
                        df[col] = encoder.transform([best_match])[0]
                    else:
                        # Use the most frequent category in training data
                        most_frequent = encoder.classes_[0]  # First class is usually most frequent
                        print(f"  Using most frequent category: '{most_frequent}'")
                        df[col] = encoder.transform([most_frequent])[0]
                else:
                    df[col] = encoder.transform([mapped_value])[0]
        
        # Scale numerical features
        numerical_cols = ['port', 'encrypted', 'cvss', 'epss', 'kev', 'c_impact', 
                         'i_impact', 'a_impact', 'criticality', 'days_since_patch', 
                         'firmware_eol', 'alert_count']
        
        # Only scale columns that exist
        existing_num_cols = [col for col in numerical_cols if col in df.columns]
        if existing_num_cols:
            df[existing_num_cols] = self.scaler.transform(df[existing_num_cols])
        
        return df
    
    def predict(self, asset_data):
        """
        Predict compliance for a single asset or multiple assets
        asset_data: DataFrame or dict with asset features
        Returns: list of prediction results
        """
        if not getattr(self, '_model_loaded', False):
            raise RuntimeError(
                f"Policy compliance model not loaded: {getattr(self, '_load_error', 'unknown error')}. "
                "Run Policy_Compliance/policy_model_trainer.py to train the model."
            )
        # Convert to DataFrame if dict
        if isinstance(asset_data, dict):
            asset_data = pd.DataFrame([asset_data])
        
        # Prepare assets and keep original features for explanation
        prepared_assets = []
        original_features_list = []
        
        for idx, row in asset_data.iterrows():
            # Keep original features before encoding/scaling
            original_features = row.to_dict()
            original_features_list.append(original_features)
            
            # Prepare asset for prediction
            prepared_asset = self.prepare_asset(original_features)
            prepared_assets.append(prepared_asset)
        
        # Combine all prepared assets
        if len(prepared_assets) > 1:
            X = pd.concat(prepared_assets, ignore_index=True)
        else:
            X = prepared_assets[0]
        
        # Predict
        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)[:, 1]
        
        # Get feature importance for explanation
        feature_importance = self.get_feature_importance()
        
        # Format results
        results = []
        for i, (pred, prob) in enumerate(zip(predictions, probabilities)):
            status = "COMPLIANT" if pred == 1 else "NON_COMPLIANT"
            confidence = prob if pred == 1 else 1 - prob
            
            # Get clear explanation for prediction
            original_asset_features = pd.Series(original_features_list[i])
            explanation = self.explain_prediction_clearly(original_asset_features, feature_importance)
            
            results.append({
                'compliance_status': status,
                'confidence': round(confidence, 3),
                'compliance_score': round(prob, 3),
                'explanation': explanation,
                'asset_index': i
            })
        
        return results
    
    def get_feature_importance(self):
        """
        Load feature importance from saved file
        """
        importance_path = os.path.join(self.model_dir, 'feature_importance.csv')
        if os.path.exists(importance_path):
            return pd.read_csv(importance_path)
        return None
    
    def explain_prediction_clearly(self, asset_features, feature_importance):
        """
        Generate CLEAR, actionable explanation for prediction
        Each explanation is one line with specific remediation advice
        """
        if feature_importance is None:
            return "Model prediction based on security policy patterns."
        
        # Create a dictionary of feature values
        feature_values = {}
        for feature in asset_features.index:
            feature_values[feature] = asset_features[feature]
        
        problematic_factors = []
        positive_factors = []
        
        # 1. CHECK ENCRYPTION STATUS
        if 'encrypted' in feature_values:
            encrypted = feature_values['encrypted']
            if encrypted == 0:
                problematic_factors.append("Communication not encrypted - enable TLS/encryption")
            else:
                positive_factors.append("Encrypted communication (good practice)")
        
        # 2. CHECK CVSS SCORE
        if 'cvss' in feature_values:
            try:
                cvss = float(feature_values['cvss'])
                if cvss >= 7.0:
                    problematic_factors.append(f"High severity vulnerability (CVSS {cvss:.1f})")
                elif cvss >= 4.0:
                    problematic_factors.append(f"Medium severity vulnerability (CVSS {cvss:.1f})")
                else:
                    positive_factors.append(f"Low CVSS score ({cvss:.1f}) - good security posture")
            except:
                pass
        
        # 3. CHECK EPSS SCORE
        if 'epss' in feature_values:
            try:
                epss = float(feature_values['epss'])
                if epss >= 0.1:
                    problematic_factors.append(f"High exploit probability (EPSS {epss:.3f}) - prioritize remediation")
                elif epss >= 0.01:
                    problematic_factors.append(f"Medium exploit probability (EPSS {epss:.3f}) - monitor closely")
                else:
                    positive_factors.append(f"Low exploit probability (EPSS {epss:.3f})")
            except:
                pass
        
        # 4. CHECK KEV STATUS
        if 'kev' in feature_values:
            kev = feature_values['kev']
            if kev == 1:
                problematic_factors.append("Known Exploited Vulnerability detected")
            else:
                positive_factors.append("No Known Exploited Vulnerabilities")
        
        # 5. CHECK FIRMWARE EOL
        if 'firmware_eol' in feature_values:
            eol = feature_values['firmware_eol']
            if eol == 1:
                problematic_factors.append("Firmware end-of-life - plan hardware replacement")
            else:
                positive_factors.append("Firmware supported by vendor")
        
        # 7. CHECK SERVICE/PROTOCOL SECURITY
        if 'service' in feature_values:
            service = str(feature_values['service'])
            service_explanations = {
                'Telnet': 'Telnet transmits passwords in plaintext - use SSH instead',
                'FTP': 'FTP has no encryption - use SFTP/SCP for file transfer',
                'HTTP': 'HTTP lacks encryption - enable HTTPS with valid certificate',
                'SNMP_v1': 'SNMPv1 uses plaintext community strings - upgrade to SNMPv3',
                'SNMP_v2': 'SNMPv2c has weak authentication - use SNMPv3 with encryption',
                'DCOM': 'DCOM/OPC Classic vulnerable to attacks - migrate to OPC UA',
                'Modbus': 'Modbus has no authentication/encryption - implement network segmentation',
                'S7comm': 'S7comm lacks security features - use VPN or network isolation',
                'RDP': 'RDP exposed without encryption - enable Network Level Authentication',
                'SMB': 'SMB exploited in ransomware attacks - disable or restrict access'
            }
            
            secure_services = {
                'HTTPS': 'HTTPS with valid certificate',
                'SSH': 'SSH with key-based authentication',
                'SNMP_v3': 'SNMPv3 with authPriv security level',
                'OPC_UA': 'OPC UA with authentication enabled',
                'RDP_Encrypted': 'RDP with encryption enabled'
            }
            
            if service in service_explanations:
                problematic_factors.append(service_explanations[service])
            elif service in secure_services:
                positive_factors.append(secure_services[service])
        
        # 8. CHECK ZONE COMPLIANCE
        if 'zone' in feature_values:
            zone = str(feature_values['zone'])
            if zone in ['OT', 'SCADA_Zone']:
                problematic_factors.append(f"OT zone device ({zone}) - requires enhanced security controls")
        
        # 9. CHECK DEVICE CRITICALITY
        if 'criticality' in feature_values:
            try:
                criticality = float(feature_values['criticality'])
                if criticality >= 0.8:
                    problematic_factors.append(f"High criticality device ({criticality:.2f}) - requires enhanced monitoring")
            except:
                pass
        
        # 10. CHECK ALERT COUNT
        if 'alert_count' in feature_values:
            try:
                alerts = float(feature_values['alert_count'])
                if alerts > 5:
                    problematic_factors.append(f"Multiple security alerts ({alerts:.0f}) - investigate immediately")
                elif alerts > 0:
                    problematic_factors.append(f"Security alerts detected ({alerts:.0f}) - review logs")
            except:
                pass
        
        # FORMAT FINAL EXPLANATION
        if problematic_factors:
            # Take top 3 most important problematic factors
            top_problems = problematic_factors[:3]
            return " | ".join(top_problems)
        elif positive_factors:
            # If no problems, show positive factors
            top_positives = positive_factors[:2]
            return "Good security practices: " + ", ".join(top_positives)
        else:
            # Fallback explanation
            return "Asset assessed against security policies"
    
    # Keep the old method for compatibility
    def explain_prediction(self, asset_features, feature_importance):
        """Legacy method - uses new clear explanation"""
        return self.explain_prediction_clearly(asset_features, feature_importance)
    
    def batch_predict_from_csv(self, csv_path):
        """
        Predict compliance for assets from a CSV file
        """
        if not os.path.exists(csv_path):
            print(f"✗ CSV file not found: {csv_path}")
            return None
        
        try:
            assets_df = pd.read_csv(csv_path)
            print(f"✓ Loaded {len(assets_df)} assets from {csv_path}")
            
            # Check required columns
            required_cols = ['device_type', 'vendor', 'zone', 'service', 'port']
            missing_cols = [col for col in required_cols if col not in assets_df.columns]
            
            if missing_cols:
                print(f"✗ Missing required columns: {missing_cols}")
                return None
            
            # Predict
            results = self.predict(assets_df)
            
            # Add results to dataframe
            for i, result in enumerate(results):
                for key, value in result.items():
                    if key != 'asset_index':
                        assets_df.loc[i, key] = value
            
            return assets_df
            
        except Exception as e:
            print(f"✗ Error processing CSV: {e}")
            return None

def test_with_assets_json():
    """
    Test predictor with assets from assets.json
    """
    import json
    
    # Load assets from assets.json
    assets_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                              'Assets', 'assets.json')
    
    if not os.path.exists(assets_path):
        print(f"✗ assets.json not found: {assets_path}")
        return None
    
    with open(assets_path, 'r') as f:
        assets = json.load(f)
    
    print(f"✓ Loaded {len(assets)} assets from assets.json")
    
    # Initialize predictor
    predictor = PolicyCompliancePredictor()
    
    # Prepare assets for prediction
    assets_for_prediction = []
    
    for asset in assets:
        # Map asset data to model features
        asset_features = {
            'device_type': asset.get('device_type', 'Unknown'),
            'vendor': asset.get('vendor', 'Unknown'),
            'zone': asset.get('zone', 'OT'),
            'service': asset.get('service', 'Unknown'),
            'port': asset.get('port', 0),
            'encrypted': 0,  # Default: not encrypted
            'cvss': 0.0,     # Default CVSS score
            'epss': 0.0,     # Default EPSS score
            'kev': 0,        # Default: not in KEV
            'c_impact': 0.0, # Default CIA impact
            'i_impact': 0.0,
            'a_impact': 0.0,
            'criticality': asset.get('criticality', 0.5),
            'days_since_patch': 30,  # Default: 30 days since patch
            'firmware_eol': 0,       # Default: firmware not EOL
            'alert_count': 0         # Default: no alerts
        }
        
        assets_for_prediction.append(asset_features)
    
    # Predict
    results = predictor.predict(pd.DataFrame(assets_for_prediction))
    
    # Display results
    print("\n" + "=" * 80)
    print("POLICY COMPLIANCE PREDICTIONS WITH CLEAR EXPLANATIONS")
    print("=" * 80)
    
    for i, (asset, result) in enumerate(zip(assets, results)):
        print(f"\nAsset {i+1}: {asset['vendor']} {asset['product']}")
        print(f"  IP: {asset['ip']}:{asset['port']}, Service: {asset['service']}")
        print(f"  Zone: {asset['zone']}, Device Type: {asset['device_type']}")
        print(f"  Prediction: {result['compliance_status']} (Confidence: {result['confidence']:.3f})")
        print(f"  Compliance Score: {result['compliance_score']:.3f}")
        print(f"  Explanation: {result['explanation']}")
    
    return results

if __name__ == "__main__":
    print("=" * 60)
    print("POLICY COMPLIANCE PREDICTOR (UPDATED EXPLANATIONS)")
    print("=" * 60)
    
    # Test with sample assets
    predictor = PolicyCompliancePredictor()
    
    # Test 1: Single asset
    print("\nTest 1: Single Asset Prediction")
    print("-" * 40)
    
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
    
    result = predictor.predict(sample_asset)
    print(f"Asset: {sample_asset['device_type']} ({sample_asset['vendor']})")
    print(f"Service: {sample_asset['service']}:{sample_asset['port']} in {sample_asset['zone']}")
    print(f"Prediction: {result[0]['compliance_status']}")
    print(f"Confidence: {result[0]['confidence']:.3f}")
    print(f"Compliance Score: {result[0]['compliance_score']:.3f}")
    print(f"Explanation: {result[0]['explanation']}")
    
    # Test 2: Predict for assets in assets.json
    print("\n\nTest 2: Predicting for assets in assets.json")
    print("-" * 40)
    
    test_with_assets_json()
    
    print("\n" + "=" * 60)
    print("PREDICTOR READY WITH CLEAR EXPLANATIONS")
    print("=" * 60)
    print("\nEach explanation now includes:")
    print("1. Specific security issue identified")
    print("2. Clear remediation advice")
    print("3. Actionable next steps")
    print("\nExample: 'Communication not encrypted - enable TLS/encryption'")
    print("Example: 'High severity vulnerability (CVSS 7.5) - patch immediately'")
    print("Example: 'Telnet transmits passwords in plaintext - use SSH instead'")