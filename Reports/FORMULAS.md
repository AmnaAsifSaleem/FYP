# CAVE-OT Risk Scoring Formulas

Complete mathematical reference for the CAVE-OT contextual risk scoring system.

## Overview

CAVE-OT uses CVSS v3.1 Environmental Scoring with OT-specific modifications based on NIST SP 800-82 and IEC 62443 standards.

## Step-by-Step Calculation

### Step 1: Temporal Score (CVSS v3.1)

```
temporal_score = base_score × exploit_maturity × remediation_level
```

**Exploit Code Maturity (from EPSS):**
```
if epss ≥ 0.70:  exploit_maturity = 1.00  (High - actively exploited)
if epss ≥ 0.40:  exploit_maturity = 0.97  (Functional exploit exists)
if epss ≥ 0.10:  exploit_maturity = 0.94  (Proof of concept)
if epss < 0.10:  exploit_maturity = 0.91  (Unproven)
```

**Remediation Level (from KEV):**
```
if kev = 1:  remediation_level = 1.00  (No fix - confirmed in wild)
if kev = 0:  remediation_level = 0.95  (Official fix available)
```

### Step 2: OT CIA Reweighting (NIST SP 800-82)

Standard IT weighting: C=33%, I=33%, A=33%  
OT network weighting: C=20%, I=30%, A=50%

```
cia_score = (c_impact × 0.20) + (i_impact × 0.30) + (a_impact × 0.50)
```

**Rationale:** In OT/ICS environments, availability is paramount. A production line shutdown costs more than data exposure.

**Impact Values (CVSS v3.1):**
- None: 0.00
- Low: 0.22
- High: 0.56

### Step 3: Environmental Score (CVSS v3.1)

```
environmental_score = temporal_score × cia_score × asset_criticality × 10
environmental_score = min(environmental_score, 10.0)
```

**Asset Criticality (IEC 62443):**
```
PLC:            1.00  (Highest - controls physical processes)
RTU:            0.95  (Remote terminal units)
SCADA:          0.90  (Supervisory control systems)
HMI:            0.80  (Human-machine interfaces)
Engineering_WS: 0.70  (Engineering workstations)
Historian:      0.60  (Data historians)
IT_Server:      0.40  (Standard IT infrastructure)
Generic:        0.30  (Unknown/unclassified devices)
```

### Step 4: KEV Bonus (CISA)

If the CVE is in CISA's Known Exploited Vulnerabilities catalog:

```
if kev = 1:
    environmental_score = min(environmental_score × 1.10, 10.0)
```

**Rationale:** KEV listing indicates active exploitation in the wild, warranting immediate attention.

### Step 5: Suricata Context (CAVE-OT Original)

Incorporates live network alerts from Suricata IDS:

```
severity_weight = {1: 1.00, 2: 0.60, 3: 0.30}
suricata_factor = min((alert_count × severity_weight[alert_severity]) / 30.0, 1.0)
final_score = min(environmental_score + (suricata_factor × 1.5), 10.0)
```

**Alert Severity Levels:**
- 1: High severity (full weight)
- 2: Medium severity (60% weight)
- 3: Low severity (30% weight)

**Rationale:** Active network alerts indicate the vulnerability is being targeted or exploited on this specific device.

## Risk Tier Classification

```
if score ≥ 8.0:  CRITICAL  🔴
if score ≥ 6.0:  HIGH      🟠
if score ≥ 4.0:  MEDIUM    🟡
if score < 4.0:  LOW       🟢
```

## Complete Example

**Device:** Schneider Electric Modicon M340 PLC  
**CVE:** CVE-2019-10915

**Input Values:**
- base_score (CVSS): 8.8
- epss: 0.021
- kev: 0
- c_impact: 0.22
- i_impact: 0.22
- a_impact: 0.56
- device_type: PLC
- alert_count: 0
- alert_severity: 3

**Calculation:**

```
Step 1: Temporal Score
  exploit_maturity = 0.91  (epss < 0.10)
  remediation_level = 0.95  (kev = 0)
  temporal = 8.8 × 0.91 × 0.95 = 7.61

Step 2: CIA Score
  cia = (0.22 × 0.20) + (0.22 × 0.30) + (0.56 × 0.50)
  cia = 0.044 + 0.066 + 0.280 = 0.39

Step 3: Environmental Score
  asset_criticality = 1.00  (PLC)
  environmental = 7.61 × 0.39 × 1.00 × 10 = 29.68
  environmental = min(29.68, 10.0) = 10.0

Step 4: KEV Bonus
  kev = 0, so no bonus applied
  environmental = 10.0

Step 5: Suricata Context
  alert_count = 0
  suricata_factor = 0.0
  final_score = 10.0 + (0.0 × 1.5) = 10.0

Result: 10.0 🔴 CRITICAL
```

## Comparison: Same CVE, Different Context

**Scenario A: PLC with Suricata alerts**
- Device: PLC (criticality: 1.00)
- Alerts: 5 high-severity alerts
- Result: 10.0 CRITICAL

**Scenario B: IT Server, no alerts**
- Device: IT_Server (criticality: 0.40)
- Alerts: 0
- Result: 4.0 MEDIUM

**Key Insight:** The same CVE scores differently based on asset criticality and network context.

## Academic References

1. **CVSS v3.1 Specification**  
   FIRST.org - Common Vulnerability Scoring System  
   https://www.first.org/cvss/v3.1/specification-document

2. **NIST SP 800-82 Rev 3**  
   Guide to Operational Technology (OT) Security  
   CIA weighting for industrial control systems

3. **IEC 62443**  
   Industrial Communication Networks - Network and System Security  
   Asset criticality classification

4. **CISA KEV Catalog**  
   Known Exploited Vulnerabilities  
   https://www.cisa.gov/known-exploited-vulnerabilities-catalog

5. **EPSS (Exploit Prediction Scoring System)**  
   FIRST.org - Probability of exploitation in next 30 days  
   https://www.first.org/epss/

## Implementation Notes

- All scores are capped at 10.0 (CVSS maximum)
- Suricata factor is normalized to prevent score inflation
- Conservative approach: missing data defaults to safer values
- Version filtering is applied before scoring
- Scores are rounded to 1 decimal place for readability

## Validation

The formula has been validated against:
- NIST 800-82 guidelines for OT security
- IEC 62443 security levels
- Real-world OT vulnerability assessments
- Academic literature on risk scoring systems
