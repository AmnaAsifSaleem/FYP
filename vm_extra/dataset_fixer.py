"""
CAVE-OT Policy Gatekeeper Dataset Generator v2
================================================
Fixes from v1:
  1. Balanced classes: ~47% COMPLIANT, ~47% NON_COMPLIANT, ~6% NEEDS_REVIEW
  2. OT-native protocols (Modbus, S7comm, DNP3) on correct device/zone = COMPLIANT
  3. Zone-protocol rules tightened (SSH/HTTPS allowed in IT/DMZ, not flagged in OT)
  4. EOL firmware reduced from 15% to 8%
  5. Explicit COMPLIANT scenario generation (not just random chance)

Sources:
  - NIST SP 800-82 Rev 3
  - NERC CIP-007-6
  - CISA Defense-in-Depth Guide
"""

import pandas as pd
import numpy as np
import random

random.seed(42)
np.random.seed(42)

# ─────────────────────────────────────────────
# POLICY RULES (same as v1, corrected)
# ─────────────────────────────────────────────

# Absolutely forbidden services regardless of context
# Source: NIST SP 800-82r3 §5.2.5.4; NERC CIP-007-6 R1.1
FORBIDDEN_SERVICES = {
    "Telnet": (
        "Telnet transmits credentials in plaintext — forbidden on all OT devices",
        "NIST SP 800-82r3 §5.2.5.4; CISA DiD §2.6",
        "Replace Telnet with SSH for encrypted remote access"
    ),
    "FTP": (
        "FTP lacks encryption and authentication — prohibited on OT networks",
        "NIST SP 800-82r3 §5.2.5.4; CISA DiD §3.2.2",
        "Replace FTP with SFTP or SCP for secure file transfer"
    ),
    "SNMP_v1": (
        "SNMPv1 has no authentication or encryption — community strings are plaintext",
        "NIST SP 800-82r3 §6.2.1; NERC CIP-007-6 R1.1",
        "Upgrade to SNMPv3 with authentication and encryption enabled"
    ),
    "SNMP_v2": (
        "SNMPv2c uses plaintext community strings — susceptible to eavesdropping",
        "NIST SP 800-82r3 §6.2.1; NERC CIP-007-6 R1.1",
        "Upgrade to SNMPv3 with authPriv security level"
    ),
    "HTTP": (
        "Unencrypted HTTP on OT device exposes management interface to interception",
        "NIST SP 800-82r3 §5.2.5.4; CISA DiD §2.5.1",
        "Disable HTTP, enable HTTPS with valid certificate; restrict to management VLAN"
    ),
    "DCOM": (
        "DCOM/OPC Classic exposed — known attack vector in Dragonfly/Havex ICS campaigns",
        "CISA DiD §3.3.4; NIST SP 800-82r3 §5.2.3",
        "Migrate to OPC UA with authentication; firewall DCOM ports 135/445"
    ),
    "SMB": (
        "SMB exposed on OT network — exploited in WannaCry/NotPetya ICS attacks",
        "CISA DiD §3.3; NIST SP 800-82r3 §5.2.3",
        "Disable SMB on all OT devices; block ports 445/135 at firewall"
    ),
}

# Expected protocols per device type
# Source: NIST SP 800-82r3 §6.2.4.1 (Least Functionality)
DEVICE_ALLOWED_SERVICES = {
    "PLC":            ["Modbus", "S7comm", "EtherNet/IP", "DNP3", "PROFINET", "IEC104"],
    "RTU":            ["DNP3", "Modbus", "IEC104", "ICCP"],
    "HMI":            ["OPC_UA", "Modbus", "S7comm", "EtherNet/IP", "VNC_Encrypted", "HTTPS"],
    "SCADA":          ["OPC_UA", "ICCP", "DNP3", "HTTPS", "SSH", "IEC104"],
    "Historian":      ["OPC_UA", "HTTPS", "SQL_Encrypted"],
    "Firewall":       ["HTTPS", "SSH", "SNMP_v3"],
    "Switch":         ["HTTPS", "SSH", "SNMP_v3"],
    "Engineering_WS": ["SSH", "HTTPS", "OPC_UA", "S7comm", "EtherNet/IP", "Modbus"],
    "Gateway":        ["OPC_UA", "HTTPS", "SSH", "Modbus", "DNP3", "EtherNet/IP"],
    "Sensor":         ["Modbus", "DNP3", "HART", "WirelessHART", "IEC104"],
}

# Allowed protocols per zone
# Source: CISA DiD §2.4.1; NIST SP 800-82r3 §5.2.3.1
ZONE_ALLOWED_SERVICES = {
    "OT":         ["Modbus", "S7comm", "EtherNet/IP", "DNP3", "PROFINET",
                   "IEC104", "OPC_UA", "HART", "WirelessHART", "ICCP",
                   "SSH", "HTTPS"],          # SSH/HTTPS allowed for management
    "DMZ":        ["OPC_UA", "HTTPS", "SSH", "SQL_Encrypted", "ICCP"],
    "IT":         ["HTTPS", "SSH", "SNMP_v3", "SQL_Encrypted", "RDP_Encrypted", "OPC_UA"],
    "SCADA_Zone": ["DNP3", "ICCP", "OPC_UA", "HTTPS", "SSH", "IEC104",
                   "Modbus", "EtherNet/IP"],
}

# Encryption required in these zones
# Source: NIST SP 800-82r3 §6.2.3; §6.2.10
ENCRYPTED_REQUIRED_ZONES = ["DMZ", "IT"]

HIGH_RISK_PORTS = {
    23:  ("Telnet", "NIST SP 800-82r3 §5.2.5.4 — Telnet port must be disabled"),
    21:  ("FTP",    "NIST SP 800-82r3 §5.2.5.4 — FTP port must be disabled"),
    69:  ("TFTP",   "CISA DiD §3.2.2 — TFTP has no authentication"),
    161: ("SNMP",   "NERC CIP-007-6 R1.1 — SNMP must use v3 or be disabled"),
    80:  ("HTTP",   "NIST SP 800-82r3 §5.2.5.4 — HTTP must be replaced with HTTPS"),
    3389:("RDP",    "NIST SP 800-82r3 §6.2.10 — RDP requires encryption and MFA"),
    135: ("DCOM",   "CISA DiD §3.3.4 — DCOM/OPC Classic vulnerable to enumeration attacks"),
    445: ("SMB",    "CISA DiD §3.3 — SMB exploited in many ICS attacks"),
}

PATCH_POLICY_DAYS = 35  # NERC CIP-007-6 R2.2

SERVICE_PORTS = {
    "Modbus": 502, "S7comm": 102, "EtherNet/IP": 44818, "DNP3": 20000,
    "PROFINET": 34962, "IEC104": 2404, "OPC_UA": 4840, "ICCP": 102,
    "HTTPS": 443, "HTTP": 80, "SSH": 22, "Telnet": 23, "FTP": 21,
    "RDP": 3389, "RDP_Encrypted": 3389, "SNMP_v1": 161, "SNMP_v2": 161,
    "SNMP_v3": 161, "SQL_Encrypted": 1433, "VNC_Encrypted": 5900,
    "HART": 5094, "WirelessHART": 5094, "DCOM": 135, "SMB": 445
}

SERVICE_ENCRYPTED = {
    "Modbus": False, "S7comm": False, "EtherNet/IP": False, "DNP3": False,
    "PROFINET": False, "IEC104": False, "OPC_UA": True, "ICCP": False,
    "HTTPS": True, "HTTP": False, "SSH": True, "Telnet": False, "FTP": False,
    "RDP": False, "RDP_Encrypted": True, "SNMP_v1": False, "SNMP_v2": False,
    "SNMP_v3": True, "SQL_Encrypted": True, "VNC_Encrypted": True,
    "HART": False, "WirelessHART": True, "DCOM": False, "SMB": False
}

DEVICE_TYPES = list(DEVICE_ALLOWED_SERVICES.keys())
ZONES = list(ZONE_ALLOWED_SERVICES.keys())

VENDORS = {
    "PLC":            ["Siemens", "Rockwell Automation", "Schneider Electric", "Mitsubishi", "ABB"],
    "RTU":            ["GE", "Schneider Electric", "ABB", "Emerson", "SEL"],
    "HMI":            ["Siemens", "Wonderware", "Rockwell Automation", "Inductive Automation", "GE"],
    "SCADA":          ["Siemens", "Wonderware", "GE", "Emerson", "ABB"],
    "Historian":      ["OSIsoft", "Honeywell", "Siemens", "ABB", "GE"],
    "Firewall":       ["Cisco", "Fortinet", "Palo Alto", "CheckPoint", "Hirschmann"],
    "Switch":         ["Cisco", "Hirschmann", "Moxa", "Belden", "Phoenix Contact"],
    "Engineering_WS": ["Siemens", "Rockwell Automation", "Schneider Electric", "ABB", "GE"],
    "Gateway":        ["Moxa", "Red Lion", "ProSoft", "HMS Networks", "Kepware"],
    "Sensor":         ["Honeywell", "Emerson", "Endress+Hauser", "Yokogawa", "ABB"],
}

CRITICALITY_MAP = {
    "PLC": (0.85, 1.00), "RTU": (0.80, 0.95), "SCADA": (0.75, 0.92),
    "HMI": (0.65, 0.85), "Historian": (0.50, 0.75), "Firewall": (0.70, 0.90),
    "Switch": (0.55, 0.80), "Engineering_WS": (0.50, 0.75),
    "Gateway": (0.60, 0.85), "Sensor": (0.40, 0.70),
}

# ─────────────────────────────────────────────
# CLASSIFICATION FUNCTION
# ─────────────────────────────────────────────

def classify_record(device_type, service, port, zone, encrypted,
                    cvss, kev, alert_count, days_since_patch, firmware_eol):
    violations = []

    # RULE 1: Absolutely forbidden services
    if service in FORBIDDEN_SERVICES:
        reason, source, remedy = FORBIDDEN_SERVICES[service]
        violations.append(("CRITICAL", reason, remedy, source))

    # RULE 2: High-risk ports (only flag if service is actually insecure)
    if port in HIGH_RISK_PORTS:
        svc_name, rule_text = HIGH_RISK_PORTS[port]
        if service not in ["SNMP_v3", "RDP_Encrypted", "HTTPS", "SSH", "OPC_UA"]:
            violations.append((
                "HIGH",
                f"Port {port} ({svc_name}) is high-risk — {rule_text}",
                f"Disable port {port} or replace with secure alternative",
                "NERC CIP-007-6 R1.1; NIST SP 800-82r3 §5.2.3"
            ))

    # RULE 3: Unexpected service for device type (least functionality)
    allowed_for_device = DEVICE_ALLOWED_SERVICES.get(device_type, [])
    if allowed_for_device and service not in allowed_for_device:
        violations.append((
            "HIGH",
            f"{service} is not an expected protocol for {device_type} — violates least functionality",
            f"Disable {service} on {device_type}; only enable required protocols",
            "NIST SP 800-82r3 §6.2.4.1; NERC CIP-007-6 R1.1"
        ))

    # RULE 4: Zone-protocol mismatch
    zone_allowed = ZONE_ALLOWED_SERVICES.get(zone, [])
    if zone_allowed and service not in zone_allowed:
        violations.append((
            "HIGH",
            f"{service} is not permitted in the {zone} zone — violates zone segmentation",
            f"Move device to correct zone or replace {service} with approved protocol",
            "NIST SP 800-82r3 §5.2.3.1; CISA DiD §2.4.1"
        ))

    # RULE 5: Encryption required in DMZ/IT zones
    if zone in ENCRYPTED_REQUIRED_ZONES and not encrypted:
        violations.append((
            "HIGH",
            f"Unencrypted {service} in {zone} zone — encryption mandatory across zone boundaries",
            f"Enable TLS on {service} or replace with encrypted equivalent",
            "NIST SP 800-82r3 §6.2.3; §6.2.10; CISA DiD §2.5.1"
        ))

    # RULE 6: High CVSS on unencrypted OT field device
    if not encrypted and cvss >= 7.5 and device_type in ["PLC", "RTU", "Sensor"]:
        violations.append((
            "MEDIUM",
            f"High-severity CVE (CVSS {cvss}) on unencrypted {service} — OT field device at risk",
            f"Apply vendor patch; implement network isolation and deep packet inspection",
            "NIST SP 800-82r3 Table 19; CISA DiD §2.6.1"
        ))

    # RULE 7: KEV + overdue patch (NERC CIP-007-6 R2)
    if kev == 1 and days_since_patch > PATCH_POLICY_DAYS:
        violations.append((
            "CRITICAL",
            f"CISA KEV on device — patch overdue by {days_since_patch - 35} days",
            f"Apply patch immediately or document mitigation plan per NERC CIP-007-6 R2.3",
            "NERC CIP-007-6 R2.2; R2.3; CISA KEV"
        ))

    # RULE 8: EOL firmware
    if firmware_eol:
        violations.append((
            "HIGH",
            f"Device firmware is end-of-life — no vendor patches available",
            f"Plan hardware replacement or implement compensating controls (network isolation)",
            "NIST SP 800-82r3 §5.2.5.2; NERC CIP-007-6 R2.1"
        ))

    # RULE 9: High alert count + overdue patches
    if alert_count >= 5 and days_since_patch > 60:
        violations.append((
            "HIGH",
            f"{alert_count} alerts on device with overdue patches — active exploitation risk",
            f"Isolate device, apply patches, review IDS alerts for indicators of compromise",
            "CISA DiD §2.7; NIST SP 800-82r3 §6.3.2"
        ))

    # ── DETERMINE LABEL ──────────────────────
    if not violations:
        return (
            "COMPLIANT",
            "No policy violations detected",
            "Continue monitoring; ensure patches applied within 35-day window",
            "NIST SP 800-82r3; NERC CIP-007-6; CISA DiD",
            "INFO"
        )

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    violations.sort(key=lambda x: sev_order.get(x[0], 9))
    top_sev, _, top_remedy, top_source = violations[0]

    label = "NEEDS_REVIEW" if top_sev == "MEDIUM" else "NON_COMPLIANT"
    all_reasons = " | ".join(set(v[1] for v in violations))
    all_sources = " | ".join(set(v[3] for v in violations))

    return (label, all_reasons, top_remedy, all_sources, top_sev)


# ─────────────────────────────────────────────
# SCENARIO BUILDERS
# ─────────────────────────────────────────────

def make_compliant_record():
    """
    Explicitly build a COMPLIANT record.
    Uses valid device+service+zone combinations from NIST SP 800-82r3.
    """
    # Valid compliant combinations
    scenarios = [
        # OT field devices with their native protocols — valid per NIST SP 800-82r3
        ("PLC",            "Modbus",       "OT"),
        ("PLC",            "S7comm",       "OT"),
        ("PLC",            "EtherNet/IP",  "OT"),
        ("PLC",            "PROFINET",     "OT"),
        ("PLC",            "IEC104",       "OT"),
        ("RTU",            "DNP3",         "OT"),
        ("RTU",            "Modbus",       "OT"),
        ("RTU",            "IEC104",       "OT"),
        ("RTU",            "DNP3",         "SCADA_Zone"),
        ("Sensor",         "Modbus",       "OT"),
        ("Sensor",         "HART",         "OT"),
        ("Sensor",         "WirelessHART", "OT"),
        ("Sensor",         "DNP3",         "OT"),
        # HMI/SCADA with secure protocols
        ("HMI",            "OPC_UA",       "OT"),
        ("HMI",            "HTTPS",        "OT"),
        ("SCADA",          "OPC_UA",       "SCADA_Zone"),
        ("SCADA",          "HTTPS",        "SCADA_Zone"),
        ("SCADA",          "SSH",          "SCADA_Zone"),
        ("SCADA",          "DNP3",         "SCADA_Zone"),
        # IT infrastructure with secure protocols
        ("Historian",      "OPC_UA",       "DMZ"),
        ("Historian",      "HTTPS",        "DMZ"),
        ("Historian",      "SQL_Encrypted","DMZ"),
        ("Firewall",       "HTTPS",        "IT"),
        ("Firewall",       "SSH",          "IT"),
        ("Firewall",       "SNMP_v3",      "IT"),
        ("Switch",         "SSH",          "IT"),
        ("Switch",         "HTTPS",        "IT"),
        ("Switch",         "SNMP_v3",      "IT"),
        ("Engineering_WS", "SSH",          "IT"),
        ("Engineering_WS", "HTTPS",        "IT"),
        ("Engineering_WS", "OPC_UA",       "DMZ"),
        ("Gateway",        "OPC_UA",       "DMZ"),
        ("Gateway",        "HTTPS",        "DMZ"),
        ("Gateway",        "Modbus",       "OT"),
        ("Gateway",        "DNP3",         "OT"),
    ]

    device_type, service, zone = random.choice(scenarios)
    vendor   = random.choice(VENDORS.get(device_type, ["Unknown"]))
    port     = SERVICE_PORTS.get(service, 502)
    encrypted = SERVICE_ENCRYPTED.get(service, False)

    # Low-risk CVE metrics for compliant devices
    cvss            = round(random.uniform(2.0, 6.9), 1)
    epss            = round(random.uniform(0.001, 0.05), 4)
    kev             = 0
    days_since_patch = random.randint(0, 30)   # within NERC CIP 35-day window
    firmware_eol    = False
    alert_count     = random.randint(0, 2)
    criticality     = round(random.uniform(*CRITICALITY_MAP.get(device_type, (0.5, 0.8))), 2)
    c_impact = round(random.uniform(0.0, 0.22), 2)
    i_impact = round(random.uniform(0.0, 0.22), 2)
    a_impact = round(random.uniform(0.0, 0.22), 2)

    label, violation_reason, remediation, policy_source, severity = classify_record(
        device_type, service, port, zone, encrypted,
        cvss, kev, alert_count, days_since_patch, firmware_eol
    )

    # If it didn't come out COMPLIANT due to some edge case, force-correct
    if label != "COMPLIANT":
        violation_reason = "No policy violations detected"
        remediation = "Continue monitoring; ensure patches applied within 35-day window"
        policy_source = "NIST SP 800-82r3; NERC CIP-007-6; CISA DiD"
        severity = "INFO"
        label = "COMPLIANT"

    return {
        "device_type": device_type, "vendor": vendor, "zone": zone,
        "service": service, "port": port, "encrypted": int(encrypted),
        "cvss": cvss, "epss": epss, "kev": kev,
        "c_impact": c_impact, "i_impact": i_impact, "a_impact": a_impact,
        "criticality": criticality, "days_since_patch": days_since_patch,
        "firmware_eol": int(firmware_eol), "alert_count": alert_count,
        "compliance_status": label, "severity": severity,
        "violated_policy": violation_reason, "remediation": remediation,
        "policy_source": policy_source,
    }


def make_non_compliant_record():
    """
    Explicitly build a NON_COMPLIANT record.
    Uses known-bad service/zone/device combinations from policy rules.
    """
    scenarios = [
        # Forbidden services
        ("PLC",    "Telnet",   "OT",         23),
        ("PLC",    "FTP",      "OT",         21),
        ("HMI",    "HTTP",     "IT",         80),
        ("HMI",    "HTTP",     "OT",         80),
        ("SCADA",  "SNMP_v1",  "OT",         161),
        ("SCADA",  "SNMP_v2",  "SCADA_Zone", 161),
        ("Switch", "HTTP",     "IT",         80),
        ("Switch", "Telnet",   "IT",         23),
        # Wrong protocol for device type
        ("PLC",    "HTTPS",    "OT",         443),
        ("Sensor", "SSH",      "OT",         22),
        ("Sensor", "HTTP",     "OT",         80),
        # Zone mismatches
        ("RTU",    "SSH",      "IT",         22),
        ("PLC",    "SQL_Encrypted","IT",     1433),
        ("Sensor", "OPC_UA",   "IT",         4840),
        # Unencrypted in DMZ/IT
        ("Gateway","Modbus",   "DMZ",        502),
        ("Gateway","DNP3",     "IT",         20000),
        ("HMI",    "Modbus",   "IT",         502),
        # High-risk ports
        ("Engineering_WS","RDP","IT",        3389),
        ("SCADA",  "DCOM",     "OT",         135),
        ("Historian","SMB",    "DMZ",        445),
    ]

    device_type, service, zone, port = random.choice(scenarios)
    vendor    = random.choice(VENDORS.get(device_type, ["Unknown"]))
    encrypted = SERVICE_ENCRYPTED.get(service, False)

    # Higher-risk CVE metrics
    cvss             = round(random.uniform(5.0, 10.0), 1)
    epss             = round(random.uniform(0.001, 0.40), 4)
    kev              = 1 if random.random() < 0.15 else 0
    days_since_patch = random.randint(10, 180)
    firmware_eol     = random.random() < 0.08
    alert_count      = random.randint(0, 8)
    criticality      = round(random.uniform(*CRITICALITY_MAP.get(device_type, (0.5, 0.8))), 2)
    c_impact = round(random.uniform(0.0, 0.56), 2)
    i_impact = round(random.uniform(0.0, 0.56), 2)
    a_impact = round(random.uniform(0.0, 0.56), 2)

    label, violation_reason, remediation, policy_source, severity = classify_record(
        device_type, service, port, zone, encrypted,
        cvss, kev, alert_count, days_since_patch, firmware_eol
    )

    return {
        "device_type": device_type, "vendor": vendor, "zone": zone,
        "service": service, "port": port, "encrypted": int(encrypted),
        "cvss": cvss, "epss": epss, "kev": kev,
        "c_impact": c_impact, "i_impact": i_impact, "a_impact": a_impact,
        "criticality": criticality, "days_since_patch": days_since_patch,
        "firmware_eol": int(firmware_eol), "alert_count": alert_count,
        "compliance_status": label, "severity": severity,
        "violated_policy": violation_reason, "remediation": remediation,
        "policy_source": policy_source,
    }


def make_needs_review_record():
    """
    NEEDS_REVIEW: medium-severity only — high CVSS on unencrypted OT field device
    but no forbidden service or zone mismatch.
    Source: NIST SP 800-82r3 Table 19
    """
    scenarios = [
        ("PLC",    "Modbus",  "OT", 502),
        ("PLC",    "S7comm",  "OT", 102),
        ("RTU",    "DNP3",    "OT", 20000),
        ("RTU",    "Modbus",  "OT", 502),
        ("Sensor", "HART",    "OT", 5094),
        ("Sensor", "Modbus",  "OT", 502),
        ("Sensor", "DNP3",    "OT", 20000),
        ("PLC",    "IEC104",  "OT", 2404),
        ("RTU",    "IEC104",  "OT", 2404),
    ]

    device_type, service, zone, port = random.choice(scenarios)
    vendor    = random.choice(VENDORS.get(device_type, ["Unknown"]))
    encrypted = False  # OT native protocols are unencrypted

    # High CVSS but no KEV, no EOL, no alert flood — triggers MEDIUM rule only
    cvss             = round(random.uniform(7.5, 10.0), 1)
    epss             = round(random.uniform(0.001, 0.10), 4)
    kev              = 0
    days_since_patch = random.randint(0, 34)   # within patch window
    firmware_eol     = False
    alert_count      = random.randint(0, 3)
    criticality      = round(random.uniform(*CRITICALITY_MAP.get(device_type, (0.5, 0.8))), 2)
    c_impact = round(random.uniform(0.0, 0.56), 2)
    i_impact = round(random.uniform(0.0, 0.56), 2)
    a_impact = round(random.uniform(0.22, 0.56), 2)

    label, violation_reason, remediation, policy_source, severity = classify_record(
        device_type, service, port, zone, encrypted,
        cvss, kev, alert_count, days_since_patch, firmware_eol
    )

    # Force NEEDS_REVIEW if edge case
    if label == "COMPLIANT":
        violation_reason = (
            f"High-severity CVE (CVSS {cvss}) on unencrypted {service} channel "
            f"— OT field device at elevated risk"
        )
        remediation = "Apply vendor patch; implement network segmentation and monitoring"
        policy_source = "NIST SP 800-82r3 Table 19; CISA DiD §2.6.1"
        severity = "MEDIUM"
        label = "NEEDS_REVIEW"

    return {
        "device_type": device_type, "vendor": vendor, "zone": zone,
        "service": service, "port": port, "encrypted": int(encrypted),
        "cvss": cvss, "epss": epss, "kev": kev,
        "c_impact": c_impact, "i_impact": i_impact, "a_impact": a_impact,
        "criticality": criticality, "days_since_patch": days_since_patch,
        "firmware_eol": int(firmware_eol), "alert_count": alert_count,
        "compliance_status": label, "severity": severity,
        "violated_policy": violation_reason, "remediation": remediation,
        "policy_source": policy_source,
    }


# ─────────────────────────────────────────────
# MAIN GENERATOR
# ─────────────────────────────────────────────

def generate_balanced_dataset(total=3000):
    """
    Target distribution:
      COMPLIANT     : 47%  → 1410 rows
      NON_COMPLIANT : 47%  → 1410 rows
      NEEDS_REVIEW  :  6%  →  180 rows
    """
    n_compliant     = int(total * 0.47)
    n_non_compliant = int(total * 0.47)
    n_needs_review  = total - n_compliant - n_non_compliant

    print(f"Generating {n_compliant} COMPLIANT records...")
    compliant_records = [make_compliant_record() for _ in range(n_compliant)]

    print(f"Generating {n_non_compliant} NON_COMPLIANT records...")
    non_compliant_records = [make_non_compliant_record() for _ in range(n_non_compliant)]

    print(f"Generating {n_needs_review} NEEDS_REVIEW records...")
    needs_review_records = [make_needs_review_record() for _ in range(n_needs_review)]

    all_records = compliant_records + non_compliant_records + needs_review_records
    df = pd.DataFrame(all_records)

    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df


if __name__ == "__main__":
    print("=" * 60)
    print("CAVE-OT Policy Dataset Generator v2 (Balanced)")
    print("Sources: NIST SP 800-82r3, NERC CIP-007-6, CISA DiD")
    print("=" * 60)

    df = generate_balanced_dataset(total=3000)

    print("\n=== COMPLIANCE DISTRIBUTION ===")
    dist = df["compliance_status"].value_counts()
    total = len(df)
    for label, count in dist.items():
        pct = count / total * 100
        print(f"  {label:<15}: {count:>4} rows  ({pct:.1f}%)")

    print("\n=== COMPLIANT: top device+service combos ===")
    c = df[df.compliance_status == "COMPLIANT"]
    print(c.groupby(["device_type","service"]).size().sort_values(ascending=False).head(10).to_string())

    print("\n=== NON_COMPLIANT: top violations ===")
    nc = df[df.compliance_status == "NON_COMPLIANT"]
    reasons = nc["violated_policy"].str.split("|").str[0].str.strip().value_counts().head(8)
    print(reasons.to_string())

    print("\n=== NEEDS_REVIEW: top cases ===")
    nr = df[df.compliance_status == "NEEDS_REVIEW"]
    print(nr.groupby(["device_type","service"]).size().sort_values(ascending=False).head(8).to_string())

    out_path = "A:/VM/CAVE-OT/policy_dataset_v2.csv" 
    df.to_csv(out_path, index=False)
    print(f"\nDataset saved: {out_path}")
    print(f"Shape: {df.shape}")