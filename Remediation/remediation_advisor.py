"""
CAVE-OT Remediation Advisor
============================
RAG-grounded, human-in-the-loop remediation recommendations. This never
auto-applies anything — it produces a candidate recommendation that
policy_gatekeeper.py then evaluates, and only a human Approve/Reject/Defer
click on the dashboard ever changes anything real.

Retrieval is plain TF-IDF + cosine similarity over a small inline knowledge
base — the same technique cve_discovery.py already uses for CVE matching.
At ~25 chunks for a 15-device testbed, a heavier RAG stack (embeddings,
FAISS) would be solving a problem this project doesn't have.

Generation calls Google's Gemini API (free tier) via the `google-genai`
package, with the response constrained to a Pydantic schema so the output
is always structured JSON, never free text to parse.

Run standalone for a smoke test:
    python Remediation/remediation_advisor.py
Needs GEMINI_API_KEY set in the environment (free key: aistudio.google.com).
"""

import os
import time
from pydantic import BaseModel, Field
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# ── Config ───────────────────────────────────────────────────────────────────
GEMINI_MODEL = "gemini-flash-lite-latest"  # swap here to move to a newer flash model
# Note: the free tier's daily quota is small (as of this writing, 20
# requests/day for the full "flash" model) and is tracked separately per
# model family — "flash-lite" has its own untouched allowance. If you start
# seeing 429 RESOURCE_EXHAUSTED errors again, either wait for the daily
# reset or try a different model from this same family.
TOP_K_CONTEXT = 5
_MODEL_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "model")
# ─────────────────────────────────────────────────────────────────────────────


# ── CVE description lookup ──────────────────────────────────────────────────
# vulnerabilities (Postgres) has no description column — the real text only
# lives in the trained model's cve_database.pkl. Same two files + same
# iterrows-into-dict pattern cave_monitor.py's build_cia_lookup() already uses.
_CVE_LOOKUP = None


def _load_cve_lookup():
    global _CVE_LOOKUP
    if _CVE_LOOKUP is not None:
        return _CVE_LOOKUP
    lookup = {}
    try:
        import joblib
        for fname in ("cve_database.pkl", "ot_cve_database.pkl"):
            path = os.path.join(_MODEL_FOLDER, fname)
            if not os.path.exists(path):
                continue
            db = joblib.load(path)
            for _, row in db.iterrows():
                if row["cve_id"] not in lookup:
                    lookup[row["cve_id"]] = row.get("description", "")
    except Exception as e:
        print(f"[remediation_advisor] CVE lookup load failed: {e}")
    _CVE_LOOKUP = lookup
    return lookup


def get_cve_description(cve_id: str) -> str:
    return _load_cve_lookup().get(cve_id, "")


# ── Knowledge base ──────────────────────────────────────────────────────────
# Curated for this testbed's actual 15 devices: 5 protocols in use (Modbus,
# S7comm, DNP3, BACnet, HTTP/HTTPS), IT/OT zone split, and the same 7 rules
# already seeded in policy_rules (db_schema_policy.sql) — so retrieval and
# the gatekeeper agree on what "addressing" a rule actually means.
KB_CHUNKS = [
    # Per-protocol mitigation
    {"topic": "modbus_no_auth", "text":
        "Modbus TCP and Modbus RTU have no built-in authentication or encryption — "
        "any host that can reach the port can issue read/write function codes. "
        "Mitigate with network segmentation (dedicated OT VLAN), a protocol-aware "
        "firewall or IDS rule restricting which source hosts may talk to the "
        "device, and disabling unused function codes at the PLC where supported."},
    {"topic": "s7comm_isolation", "text":
        "S7comm (Siemens S7-300/S7-1200/S7-1500) lacks native authentication in "
        "older firmware and is vulnerable to replay/manipulation of engineering "
        "traffic. Restrict engineering-station access to a jump host, use a VPN "
        "for remote programming access, and validate any firmware or program "
        "patch on an offline staging PLC before pushing to production."},
    {"topic": "dnp3_secure_auth", "text":
        "DNP3 (used by RTUs) supports Secure Authentication v5 (SAv5) but it is "
        "frequently left disabled. Where the RTU supports it, enable SAv5; where "
        "it doesn't, compensate with network-level ACLs restricting which SCADA "
        "master IPs may poll the RTU, and baseline normal poll timing in the IDS "
        "so unexpected write commands stand out."},
    {"topic": "bacnet_segmentation", "text":
        "BACnet (building/ventilation controllers) has no authentication in its "
        "common deployment mode. Segment BACnet devices onto a building-management "
        "VLAN separate from process-control OT, and disable unauthenticated "
        "Write-Property services where the device supports access control."},
    {"topic": "http_https_hardening", "text":
        "HTTP-based HMI/Historian web interfaces should be moved to HTTPS with a "
        "valid certificate (not self-signed, where a CA is available), directly "
        "satisfying the 'IT Zone HTTPS Only' policy. Add a reverse proxy/WAF in "
        "front of the interface if the device firmware can't be updated directly, "
        "and rotate certificates on a defined schedule."},

    # Device-role safety caveats
    {"topic": "plc_patch_safety", "text":
        "PLC firmware or logic patches must be validated on an offline staging "
        "replica of the same model/firmware before deployment to a production "
        "controller. Always confirm a documented rollback path (last-known-good "
        "firmware image or program backup) exists before applying any change to "
        "a device controlling a physical process."},
    {"topic": "rtu_patch_safety", "text":
        "RTU updates carry the same fail-safe requirement as PLCs — test in "
        "staging first. RTUs frequently have longer maintenance-window "
        "requirements than PLCs because they're often at unmanned remote sites; "
        "factor field-access logistics into any recommended timeline."},
    {"topic": "hmi_hardening", "text":
        "HMI web applications should be patched via the vendor's official update "
        "channel, not ad-hoc — verify checksums/signatures on any downloaded "
        "update package. Disable unused HMI services (e.g. legacy remote-config "
        "ports) and enforce session timeout on the operator interface."},
    {"topic": "scada_server_redundancy", "text":
        "Before applying any change to a SCADA server, confirm failover/redundancy "
        "status — if it's the active node, changes should target the standby node "
        "first, verify correct operation, then fail over. Never patch the only "
        "live SCADA path without a tested failover."},
    {"topic": "historian_data_integrity", "text":
        "Historian changes (patches, schema/version upgrades) should be preceded "
        "by a verified backup of the historical dataset, since data-integrity "
        "loss on a plant historian is often irreversible and has compliance "
        "implications independent of the security fix itself."},
    {"topic": "engineering_ws_hygiene", "text":
        "Engineering workstations should require jump-host access for remote "
        "connections, enforce unique (non-shared) credentials, and disable "
        "direct internet access — engineering workstations are a common "
        "IT-to-OT lateral-movement pivot point, matching this plant's own "
        "attack-path topology (SCADA Server / HMI / Engineering WS as entry "
        "points into OT-zone targets)."},

    # Zone / segmentation guidance (mirrors seeded policy_rules)
    {"topic": "iec62443_zone_conduit", "text":
        "IEC 62443 zone/conduit model: group assets of similar security "
        "requirements into zones (IT vs OT here) and control all traffic "
        "crossing a zone boundary through a defined, monitored conduit — "
        "typically a firewall or data diode. Any remediation for an OT-zone "
        "device should explicitly address how it maintains that boundary, not "
        "just the individual CVE."},
    {"topic": "nist_800_82_ot_encryption", "text":
        "NIST SP 800-82r3 section 6.2.3: communications within the OT zone "
        "should be encrypted where the protocol and device support it; where a "
        "legacy protocol (Modbus, S7comm, DNP3 without SAv5) cannot itself be "
        "encrypted, a compensating control — VPN tunnel, IPsec at the network "
        "layer, or physical segmentation — is the accepted substitute. This is "
        "the literal basis for the 'OT Zone Encryption' policy rule."},
    {"topic": "dmz_no_ot_protocols", "text":
        "A DMZ between IT and OT should never carry native OT protocols "
        "(Modbus/S7comm/DNP3/BACnet) directly — data should be relayed through "
        "an application-layer gateway or historian replication service instead "
        "of routing raw OT traffic through the DMZ."},

    # Patch / lifecycle guidance
    {"topic": "patch_validation_process", "text":
        "NIST SP 800-82r3 section 6 patch management guidance: validate any "
        "patch's functional and safety impact in a non-production environment, "
        "schedule production application during an approved maintenance window, "
        "and have a rollback plan ready before applying. This applies whether "
        "the patch addresses a CVE directly or is a compensating configuration "
        "change."},
    {"topic": "firmware_eol_compensating_controls", "text":
        "When a device's firmware has reached vendor end-of-life and immediate "
        "replacement isn't feasible, compensating controls are the interim "
        "posture: tighten network segmentation around the device, add "
        "IDS/Suricata signatures specific to its known vulnerabilities, and "
        "flag it for prioritized replacement in the next maintenance cycle "
        "rather than leaving it unmonitored."},

    # Severity prioritization
    {"topic": "kev_priority", "text":
        "A CVE listed in CISA's Known Exploited Vulnerabilities (KEV) catalog "
        "means it is confirmed being exploited in the wild right now, not just "
        "theoretically dangerous. KEV-listed findings should get a compensating "
        "control (IDS signature, network ACL) applied immediately, even before "
        "a full patch maintenance window can be scheduled — the interim control "
        "is not a substitute for the eventual patch, just a bridge."},
    {"topic": "epss_prioritization", "text":
        "EPSS (Exploit Prediction Scoring System) estimates the probability a "
        "vulnerability will actually be exploited in the next 30 days. A "
        "high-EPSS, moderate-CVSS finding often deserves faster action than a "
        "high-CVSS, near-zero-EPSS one — prioritize by realistic exploitation "
        "likelihood, not CVSS severity alone."},

    # Explicit OT-safety constraint (the literal basis for the prompt rule)
    {"topic": "never_disable_ics_device", "text":
        "For safety-critical industrial control devices (PLC, RTU, HMI, SCADA "
        "server, Historian), the default remediation posture is to patch or "
        "apply a compensating control — never to recommend permanently "
        "disabling, powering off, or decommissioning the device outright. "
        "Removing a device from an operating physical process is an "
        "organizational decision with safety implications far beyond the "
        "security finding that prompted it, and is outside the scope of an "
        "automated advisory."},

    # Attack-path / lateral-movement context
    {"topic": "lateral_movement_entry_points", "text":
        "In this plant's topology, HMI Interface, Backup HMI Interface, "
        "Engineering WS, and SCADA Server are the IT-zone entry points an "
        "attacker would pivot from into OT-zone process-control targets. A "
        "device found on a live attack path from one of these entry points "
        "should be treated as higher priority than its CVSS/risk score alone "
        "would suggest, since it represents a step in a realistic lateral-"
        "movement chain, not an isolated finding."},
    {"topic": "conduit_monitoring", "text":
        "Any conduit (firewall rule, routing path) that legitimately allows "
        "traffic from an IT-zone entry point to reach an OT-zone target should "
        "be actively monitored — an unexpected new connection along a known "
        "attack path is a stronger indicator of active exploitation than the "
        "same traffic pattern appearing in isolation."},

    # Water-treatment-specific safety notes
    {"topic": "dosing_pump_safety", "text":
        "Chemical dosing pump controllers (e.g. this plant's Dosing_Pump_PLC) "
        "directly affect water chemical treatment levels — any change to their "
        "logic or firmware must be tested against dosing-rate safety limits in "
        "staging before production deployment, since an incorrect dosing rate "
        "is a direct public-health and regulatory-compliance risk, not just an "
        "availability concern."},
    {"topic": "uv_disinfection_safety", "text":
        "UV disinfection controllers must maintain minimum treatment dosage for "
        "regulatory compliance — any remediation affecting this device should "
        "explicitly confirm the change doesn't interrupt or degrade disinfection "
        "coverage during the maintenance window, and that monitoring resumes "
        "immediately after the change."},
    {"topic": "reservoir_level_safety", "text":
        "Reservoir/water-level RTUs and PLCs interlock with pump control to "
        "prevent overflow or dry-running of pumps. Any firmware or "
        "configuration change to these devices should preserve the existing "
        "interlock logic, and the safety note should explicitly say so."},
]

_VECTORIZER = TfidfVectorizer(stop_words="english")
_KB_MATRIX = _VECTORIZER.fit_transform([c["text"] for c in KB_CHUNKS])


def retrieve_context(device_type, vendor, product, service, zone, cve_description, top_k=TOP_K_CONTEXT):
    """Top-k most relevant knowledge-base chunks for this device/CVE, by TF-IDF
    cosine similarity — same technique cve_discovery.py uses for CVE matching."""
    query = f"{device_type} {vendor} {product} {service} {zone} {cve_description}".lower()
    q_vec = _VECTORIZER.transform([query])
    scores = cosine_similarity(q_vec, _KB_MATRIX).flatten()
    top_idx = scores.argsort()[-top_k:][::-1]
    return [{**KB_CHUNKS[i], "similarity": round(float(scores[i]), 4)} for i in top_idx]


# ── LLM output schema ───────────────────────────────────────────────────────
class RemediationOutput(BaseModel):
    recommendation: str = Field(..., description="Concrete remediation action(s), 2-4 sentences")
    rationale: str = Field(..., description="Why this addresses the CVE/risk; cite the retrieved guidance")
    ot_safety_note: str = Field(..., description="Testing/rollback/fail-safe caveats before applying")
    requires_maintenance_window: bool = Field(..., description="True if applying this needs a scheduled window")
    confidence: float = Field(..., ge=0.0, le=1.0)
    references: list[str] = Field(default_factory=list,
        description="Which retrieved knowledge-base topics this recommendation draws on")


def _build_prompt(asset, cve, attack_path_info, policy_context, context_chunks):
    context_lines = "\n".join(
        f"[{i+1}] ({c['topic']}, similarity={c['similarity']:.2f}) {c['text']}"
        for i, c in enumerate(context_chunks)
    )
    attack_path_line = (
        f"This device is a target of an attack path from {attack_path_info['entry']}, "
        f"{attack_path_info['hops']} hops, cost {attack_path_info['cost']:.2f}."
        if attack_path_info else "Not currently on a known attack path."
    )

    return f"""You are an OT/ICS security remediation advisor for a water-treatment plant testbed.

Rules that MUST NOT be violated:
1. NEVER recommend permanently disabling, powering off, decommissioning, or removing
   a PLC/RTU/HMI/SCADA/Historian device. Recommend patching, mitigating, or compensating
   controls instead.
2. If the target device is in the OT zone, you MUST explicitly state whether applying
   this change requires a scheduled maintenance window (requires_maintenance_window).
3. Ground your rationale in the provided guidance excerpts below — do not invent
   standards or CVE details not given to you.

ASSET: {asset['device_type']} | vendor={asset['vendor']} product={asset['product']} firmware={asset.get('firmware','unknown')}
        zone={asset['zone']} criticality={asset['criticality']} service/protocol={asset['service']}

VULNERABILITY: {cve['cve_id']} | CVSS={cve['cvss']} EPSS={cve['epss']} KEV={cve['kev']} risk_score={cve['risk_score']} tier={cve['risk_tier']}
Description: {cve.get('description', '(no description available)')}

ATTACK PATH CONTEXT: {attack_path_line}

POLICY CONTEXT: {policy_context or 'No existing policy compliance record for this asset.'}

RETRIEVED GUIDANCE (cite by topic in your references field):
{context_lines}

Reminder: never suggest disabling the device. If this is an OT-zone device, you MUST set
requires_maintenance_window=true unless the change is provably non-disruptive (e.g. a
passive monitoring rule, not a firmware/config change)."""


def _get_client():
    from google import genai
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY not set. Get a free key at "
            "https://aistudio.google.com/app/apikey and set it as an environment variable."
        )
    return genai.Client(api_key=api_key)


def generate_remediation(asset, cve, attack_path_info=None, policy_context=None, attempts=3):
    """Retrieve context, call Gemini with a structured schema, return
    (RemediationOutput, context_chunks). Raises on persistent failure —
    caller decides how to surface that."""
    context_chunks = retrieve_context(
        asset["device_type"], asset["vendor"], asset["product"],
        asset["service"], asset["zone"], cve.get("description", ""),
    )
    prompt = _build_prompt(asset, cve, attack_path_info, policy_context, context_chunks)

    client = _get_client()
    last_exc = None
    for attempt in range(1, attempts + 1):
        try:
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
                config={
                    "response_mime_type": "application/json",
                    "response_schema": RemediationOutput,
                },
            )
            result = RemediationOutput.model_validate_json(response.text)
            return result, context_chunks
        except Exception as e:
            last_exc = e
            if "RESOURCE_EXHAUSTED" in str(e) or "429" in str(e):
                # Daily quota, not a transient blip — retrying within seconds
                # won't help, so fail fast with a clear, actionable message
                # instead of burning the remaining retry budget.
                raise RuntimeError(
                    f"Gemini free-tier daily quota exhausted for model '{GEMINI_MODEL}'. "
                    "Wait for the daily reset, or change GEMINI_MODEL in remediation_advisor.py "
                    "to a different model family (e.g. a '-lite' variant) which has its own "
                    "separate quota."
                ) from e
            if attempt < attempts:
                backoff = 5 * attempt
                print(f"  [retry {attempt}/{attempts}] {e} — retrying in {backoff}s...")
                time.sleep(backoff)
    raise last_exc


if __name__ == "__main__":
    print("=" * 60)
    print("REMEDIATION ADVISOR — SMOKE TEST")
    print("=" * 60)

    sample_asset = {
        "device_type": "Filtration_PLC", "vendor": "Siemens", "product": "S7-300",
        "firmware": "V3.2.5", "zone": "OT", "criticality": 0.98, "service": "S7comm",
    }
    sample_cve = {
        "cve_id": "CVE-2018-13800", "cvss": 7.3, "epss": 0.0063, "kev": 0,
        "risk_score": 10.0, "risk_tier": "CRITICAL",
        "description": "A vulnerability in the web server of Siemens SIMATIC S7-300 CPU "
                        "allows a remote attacker to cause a denial of service.",
    }

    print("\nRetrieved context:")
    for c in retrieve_context(sample_asset["device_type"], sample_asset["vendor"],
                               sample_asset["product"], sample_asset["service"],
                               sample_asset["zone"], sample_cve["description"]):
        print(f"  [{c['similarity']:.2f}] {c['topic']}")

    print("\nCalling Gemini...")
    result, chunks = generate_remediation(sample_asset, sample_cve)
    print("\nRESULT:")
    print(result.model_dump_json(indent=2))
