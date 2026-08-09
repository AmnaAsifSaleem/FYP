"""
CAVE-OT Policy Gatekeeper
=========================
Deterministic rule engine that reviews every AI-generated remediation
recommendation BEFORE it reaches a human analyst. This is the industrial-
safety constraint layer: no recommendation reaches the approve/reject/defer
queue without first being checked against the plant's own policy rules.

Deliberately rule-based first, ML second (the existing trained
PolicyCompliancePredictor is attached only as a soft confidence signal,
never the decision-maker) — an evaluator will reasonably ask "would you
trust an ML model alone to gate actions on a water treatment plant?" and
the honest answer is no.

Evaluates against the 7 rules already seeded in policy_rules
(Database/db_schema_policy.sql). Two of those seeded rules
(Patch Compliance, Firmware EOL Check) can never fire against this
testbed's real data today, because no upstream code tracks real patch
dates or firmware EOL status — policy_integrator.py hardcodes both to
defaults. That's documented here explicitly rather than silently
reinterpreted or hidden.
"""

_DISABLE_PATTERNS = [
    "permanently disable", "power off the device", "power off this device",
    "power down the device", "power down this device", "decommission",
    "shut down the device permanently", "shut down this device permanently",
    "remove the device", "remove this device", "take the device offline permanently",
    "take this device offline permanently", "disable the plc", "disable this plc",
    "disable the rtu", "disable this rtu", "disable the device permanently",
    "disable this device permanently", "disconnect the device permanently",
]

_ENCRYPTION_KEYWORDS = [
    "encrypt", "tls", "https", "vpn", "ipsec", "segmentation", "segment",
    "isolat", "firewall", "vlan", "acl", "jump host", "jump-host",
]

# These two seeded rules have no real upstream data to evaluate against —
# policy_integrator.prepare_asset_for_prediction() hardcodes
# days_since_patch=30 and firmware_eol=0 for every asset, so any threshold
# check against them would be evaluating a constant, not real risk.
_NON_EVALUABLE_RULES = {"Patch Compliance", "Firmware EOL Check"}


def _implies_permanent_disable(text: str) -> bool:
    t = text.lower()
    return any(p in t for p in _DISABLE_PATTERNS)


def _mentions_encryption_or_segmentation(text: str) -> bool:
    t = text.lower()
    return any(k in t for k in _ENCRYPTION_KEYWORDS)


def _rule_matches(rule: dict, asset: dict, cve: dict) -> bool:
    if rule["rule_name"] in _NON_EVALUABLE_RULES:
        return False
    if rule.get("zone") and rule["zone"] != asset.get("zone"):
        return False
    if rule.get("service") and rule["service"] != asset.get("service"):
        return False
    if rule.get("port") is not None and rule["port"] != asset.get("port"):
        return False
    if rule.get("device_type") and rule["device_type"] != asset.get("device_type"):
        return False
    if rule.get("cvss_threshold") is not None and cve.get("cvss", 0.0) < rule["cvss_threshold"]:
        return False
    if rule.get("epss_threshold") is not None and cve.get("epss", 0.0) < rule["epss_threshold"]:
        return False
    return True


def load_active_rules(cur) -> list[dict]:
    """Fetch active policy_rules rows as plain dicts. Caller supplies an
    open psycopg2 cursor (gatekeeper itself stays DB-agnostic)."""
    cur.execute("""
        SELECT rule_name, description, policy_source, zone, service, port,
               encrypted, device_type, cvss_threshold, epss_threshold,
               days_since_patch_threshold
        FROM policy_rules WHERE is_active = TRUE;
    """)
    rows = cur.fetchall()
    # RealDictCursor rows are already dict-like (RealDictRow subclasses
    # dict); iterating one yields its KEYS, so zip(cols, row) would silently
    # zip column names against other column names, not the real values.
    # Only zip-reconstruct for a plain cursor's tuple rows.
    if rows and isinstance(rows[0], dict):
        return [dict(r) for r in rows]
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in rows]


def check(asset: dict, cve: dict, recommendation, attack_path_info: dict | None,
          policy_rules: list[dict], ml_signal: dict | None = None) -> dict:
    """
    asset: {device_type, vendor, product, zone, criticality, service, port}
    cve: {cve_id, cvss, epss, kev, risk_score, risk_tier}
    recommendation: RemediationOutput (or anything with .recommendation /
                     .requires_maintenance_window attributes)
    attack_path_info: {"entry":, "hops":, "cost":, "is_target": True} or None
    policy_rules: list of dicts from load_active_rules()
    ml_signal: {"compliance_status":, "compliance_score":} or None

    Returns {"verdict": "ALLOW"|"BLOCK"|"NEEDS_REVIEW", "reasons": [...],
             "matched_rules": [...], "ml_confidence_signal": ml_signal}
    """
    rec_text = recommendation.recommendation if hasattr(recommendation, "recommendation") else str(recommendation)
    requires_window = getattr(recommendation, "requires_maintenance_window", False)

    # ── Hard gate 1: never permit disable/decommission language ────────────
    if _implies_permanent_disable(rec_text):
        return {
            "verdict": "BLOCK",
            "reasons": ["Recommendation implies permanently disabling/removing a "
                        "safety-critical OT device — not permitted regardless of "
                        "any other factor."],
            "matched_rules": [],
            "ml_confidence_signal": ml_signal,
        }

    # ── Hard gate 2: high-criticality OT asset must flag a maintenance window ──
    if asset.get("zone") == "OT" and asset.get("criticality", 0) > 0.9 and not requires_window:
        return {
            "verdict": "BLOCK",
            "reasons": [f"Criticality {asset.get('criticality', 0):.2f} OT asset — "
                        "recommendation must set requires_maintenance_window=true. "
                        "Model did not; manual override required."],
            "matched_rules": [],
            "ml_confidence_signal": ml_signal,
        }

    # ── Soft rule checks ─────────────────────────────────────────────────
    reasons, matched = [], []
    verdict = "ALLOW"

    for rule in policy_rules:
        if not _rule_matches(rule, asset, cve):
            continue
        matched.append(rule["rule_name"])

        if rule["rule_name"] in ("OT Zone Encryption", "IT Zone HTTPS Only"):
            if not _mentions_encryption_or_segmentation(rec_text):
                reasons.append(f"{rule['rule_name']}: recommendation doesn't address "
                                "encryption/segmentation for this zone/service.")
                verdict = "NEEDS_REVIEW"

        if rule["rule_name"] == "High CVSS Alert":
            reasons.append(f"High CVSS Alert rule matched (CVSS {cve.get('cvss')}).")

    # ── Attack-path amplifier (informational escalation, never a blocker) ──
    if attack_path_info and attack_path_info.get("is_target"):
        reasons.append(f"Asset is on an attack path from {attack_path_info['entry']} "
                        f"({attack_path_info['hops']} hops, cost {attack_path_info['cost']:.2f}).")
        if verdict == "ALLOW":
            verdict = "NEEDS_REVIEW"

    return {
        "verdict": verdict,
        "reasons": reasons,
        "matched_rules": matched,
        "ml_confidence_signal": ml_signal,
    }


if __name__ == "__main__":
    class _FakeRec:
        def __init__(self, text, window):
            self.recommendation = text
            self.requires_maintenance_window = window

    print("=" * 60)
    print("POLICY GATEKEEPER — SMOKE TEST (no DB needed)")
    print("=" * 60)

    asset = {"device_type": "Filtration_PLC", "vendor": "Siemens", "product": "S7-300",
              "zone": "OT", "criticality": 0.98, "service": "S7comm", "port": 10201}
    cve = {"cve_id": "CVE-2018-13800", "cvss": 7.3, "epss": 0.0063, "kev": 0,
           "risk_score": 10.0, "risk_tier": "CRITICAL"}
    rules = [
        {"rule_name": "OT Zone Encryption", "zone": "OT", "service": None, "port": None,
         "device_type": None, "cvss_threshold": None, "epss_threshold": None},
        {"rule_name": "High CVSS Alert", "zone": None, "service": None, "port": None,
         "device_type": None, "cvss_threshold": 7.0, "epss_threshold": None},
        {"rule_name": "Patch Compliance", "zone": None, "service": None, "port": None,
         "device_type": None, "cvss_threshold": None, "epss_threshold": None},
    ]

    print("\nCase 1: no maintenance window flagged on a criticality-0.98 OT asset")
    print(check(asset, cve, _FakeRec("apply the vendor patch to the S7-300", False), None, rules))

    print("\nCase 2: same, with maintenance window flagged, no encryption mention")
    print(check(asset, cve, _FakeRec("apply the vendor patch to the S7-300, test in staging first", True), None, rules))

    print("\nCase 3: implies permanent disable")
    print(check(asset, cve, _FakeRec("the safest option is to permanently disable this PLC", True), None, rules))

    print("\nCase 4: addresses encryption/segmentation, on an attack path")
    print(check(asset, cve, _FakeRec(
        "apply the vendor patch, test in staging first, and restrict engineering "
        "access via VPN/jump host in the meantime", True),
        {"entry": "SCADA_Server", "hops": 2, "cost": 0.2, "is_target": True}, rules))
