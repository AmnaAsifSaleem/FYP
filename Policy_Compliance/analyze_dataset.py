"""
Analyze the policy dataset to understand why we get 100% accuracy
"""

import pandas as pd
import os
import numpy as np

# Load the dataset
dataset_path = os.path.join('..', 'Datasets', 'policy_dataset_v2.csv')
df = pd.read_csv(dataset_path)

print('=' * 60)
print('DATASET ANALYSIS FOR PERFECT ACCURACY')
print('=' * 60)

print(f'\nDataset shape: {df.shape}')
print(f'COMPLIANT samples: {(df["compliance_status"] == "COMPLIANT").sum()}')
print(f'NON_COMPLIANT samples: {(df["compliance_status"] == "NON_COMPLIANT").sum()}')
print(f'NEEDS_REVIEW samples: {(df["compliance_status"] == "NEEDS_REVIEW").sum()}')

# Check for perfect rules
print('\n' + '=' * 60)
print('PERFECT RULES ANALYSIS')
print('=' * 60)

# Rule 1: Check if certain services always have same compliance status
print('\n1. SERVICE-BASED RULES:')
services = df['service'].unique()
for service in services:
    subset = df[df['service'] == service]
    unique_statuses = subset['compliance_status'].unique()
    if len(unique_statuses) == 1:
        count = len(subset)
        print(f'   {service}: Always {unique_statuses[0]} ({count} samples)')

# Rule 2: Check encrypted status
print('\n2. ENCRYPTION RULES:')
for encrypted in [0, 1]:
    subset = df[df['encrypted'] == encrypted]
    if len(subset) > 0:
        compliant_pct = (subset['compliance_status'] == 'COMPLIANT').mean() * 100
        print(f'   encrypted={encrypted}: {compliant_pct:.1f}% compliant')

# Rule 3: Check CVSS thresholds
print('\n3. CVSS THRESHOLD ANALYSIS:')
cvss_threshold = 7.0
below_threshold = df[df['cvss'] < cvss_threshold]
above_threshold = df[df['cvss'] >= cvss_threshold]

print(f'   CVSS < {cvss_threshold}: {len(below_threshold)} samples')
if len(below_threshold) > 0:
    compliant_below = (below_threshold['compliance_status'] == 'COMPLIANT').mean() * 100
    print(f'      {compliant_below:.1f}% compliant')

print(f'   CVSS >= {cvss_threshold}: {len(above_threshold)} samples')
if len(above_threshold) > 0:
    compliant_above = (above_threshold['compliance_status'] == 'COMPLIANT').mean() * 100
    print(f'      {compliant_above:.1f}% compliant')

# Rule 4: Check EPSS thresholds
print('\n4. EPSS THRESHOLD ANALYSIS:')
epss_threshold = 0.1
below_epss = df[df['epss'] < epss_threshold]
above_epss = df[df['epss'] >= epss_threshold]

print(f'   EPSS < {epss_threshold}: {len(below_epss)} samples')
if len(below_epss) > 0:
    compliant_below_epss = (below_epss['compliance_status'] == 'COMPLIANT').mean() * 100
    print(f'      {compliant_below_epss:.1f}% compliant')

print(f'   EPSS >= {epss_threshold}: {len(above_epss)} samples')
if len(above_epss) > 0:
    compliant_above_epss = (above_epss['compliance_status'] == 'COMPLIANT').mean() * 100
    print(f'      {compliant_above_epss:.1f}% compliant')

# Check for simple if-then rules
print('\n' + '=' * 60)
print('SIMPLE DECISION RULES')
print('=' * 60)

# Try to find simple rules
simple_rules = []

# Rule: If service is in insecure list, then NON_COMPLIANT
insecure_services = ['DCOM', 'HTTP', 'FTP', 'SMB', 'Telnet', 'SNMP_v1', 'SNMP_v2', 'RDP']
insecure_mask = df['service'].isin(insecure_services)
insecure_non_compliant = (df[insecure_mask]['compliance_status'] == 'NON_COMPLIANT').mean() * 100
print(f'\nRule 1: If service in {insecure_services}')
print(f'   Coverage: {insecure_mask.sum()}/{len(df)} samples ({insecure_mask.mean()*100:.1f}%)')
print(f'   Accuracy: {insecure_non_compliant:.1f}% NON_COMPLIANT')

# Rule: If CVSS >= 7.0, then NON_COMPLIANT
high_cvss_mask = df['cvss'] >= 7.0
high_cvss_non_compliant = (df[high_cvss_mask]['compliance_status'] == 'NON_COMPLIANT').mean() * 100
print(f'\nRule 2: If CVSS >= 7.0')
print(f'   Coverage: {high_cvss_mask.sum()}/{len(df)} samples ({high_cvss_mask.mean()*100:.1f}%)')
print(f'   Accuracy: {high_cvss_non_compliant:.1f}% NON_COMPLIANT')

# Rule: If encrypted=0 AND zone='OT', then NON_COMPLIANT
unencrypted_ot_mask = (df['encrypted'] == 0) & (df['zone'] == 'OT')
if unencrypted_ot_mask.any():
    unencrypted_ot_non_compliant = (df[unencrypted_ot_mask]['compliance_status'] == 'NON_COMPLIANT').mean() * 100
    print(f'\nRule 3: If encrypted=0 AND zone="OT"')
    print(f'   Coverage: {unencrypted_ot_mask.sum()}/{len(df)} samples ({unencrypted_ot_mask.mean()*100:.1f}%)')
    print(f'   Accuracy: {unencrypted_ot_non_compliant:.1f}% NON_COMPLIANT')

print('\n' + '=' * 60)
print('CONCLUSION')
print('=' * 60)
print('The dataset appears to have been created with deterministic rules.')
print('This explains the 100% accuracy - the model learned these rules.')
print('\nFor real-world deployment, we should:')
print('1. Add regularization to prevent overfitting')
print('2. Use cross-validation instead of single split')
print('3. Consider collecting more realistic, noisy data')
print('4. Add dropout or other techniques for robustness')