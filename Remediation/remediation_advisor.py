"""
CAVE-OT Remediation Advisor — Groq Edition
============================================
Generates structured remediation recommendations for OT/ICS assets.

Flow:
  1. Build a rich, asset-specific prompt with full context
  2. Call Groq API (qwen/qwen3.8-27b — fast, free)
  3. Parse structured JSON response
  4. Return (RemediationOutput, []) to caller
"""

import os
import json
import time
import urllib.request
import urllib.error
from pydantic import BaseModel, Field

# ── Config ────────────────────────────────────────────────────────────────────
GROQ_API_URL  = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL    = "qwen/qwen3.8-27b"
GROQ_API_KEY  = os.environ.get("GROQ_API_KEY", "")  # set via environment variable
_MODEL_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "model")
# ─────────────────────────────────────────────────────────────────────────────


# ── CVE description lookup ─────────────────────────────────────────────────────
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


# ── LLM output schema ─────────────────────────────────────────────────────────
class RemediationOutput(BaseModel):
    recommendation: str = Field(..., description="Concrete remediation action(s), 2-4 sentences")
    rationale: str      = Field(..., description="Why this addresses the CVE/risk")
    ot_safety_note: str = Field(..., description="Testing/rollback/fail-safe caveats before applying")
    requires_maintenance_window: bool = Field(...)
    confidence: float   = Field(..., ge=0.0, le=1.0)
    references: list[str] = Field(default_factory=list)


# ── System prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are CAVE-OT's OT/ICS cybersecurity remediation advisor for a water-treatment plant.

Generate precise, actionable remediation recommendations for specific OT/ICS assets and CVEs.

Hard constraints:
1. NEVER recommend disabling, powering off, or decommissioning any PLC, RTU, HMI, SCADA, or Historian
2. For OT-zone devices, set requires_maintenance_window=true unless change is purely passive
3. Be specific to the actual device model, vendor, firmware, and protocol
4. Include a concrete OT safety note

Output ONLY valid JSON — no markdown, no explanation outside JSON:
{
  "recommendation": "string (2-4 sentences, specific and actionable)",
  "rationale": "string",
  "ot_safety_note": "string",
  "requires_maintenance_window": boolean,
  "confidence": float,
  "references": ["CVE ID or standard"]
}"""


def _build_prompt(asset, cve, attack_path_info, policy_context):
    kev_flag  = " ⚠ ACTIVELY EXPLOITED — CISA KEV" if cve.get("kev") else ""
    epss_note = f" ({cve.get('epss', 0)*100:.2f}% exploitation probability)" if cve.get("epss") else ""

    attack_ctx = ""
    if attack_path_info:
        attack_ctx = (f"ATTACK PATH: This device is reachable from '{attack_path_info.get('entry','?')}' "
                      f"in {attack_path_info.get('hops','?')} hops (cost {attack_path_info.get('cost','?')}). "
                      f"ELEVATED PRIORITY — live lateral movement path.")
    else:
        attack_ctx = "ATTACK PATH: Not on a known active attack path."

    policy_ctx = f"POLICY: {policy_context}" if policy_context else "POLICY: No compliance record."

    return f"""Generate a remediation recommendation for this OT/ICS asset and CVE.

ASSET:
  Device    : {asset['device_type']} — {asset['vendor']} {asset['product']} fw={asset.get('firmware') or 'unknown'}
  Zone      : {asset['zone']} | Criticality: {float(asset.get('criticality', 0.5)):.0%}
  Protocol  : {asset['service']} port {asset.get('port', '?')}

CVE:
  ID        : {cve['cve_id']}{kev_flag}
  CVSS      : {cve['cvss']} | EPSS: {epss_note if epss_note else 'N/A'}
  Risk Score: {cve['risk_score']} ({cve['risk_tier']})
  Desc      : {cve.get('description') or 'No description available — search NVD for ' + cve['cve_id']}

{attack_ctx}
{policy_ctx}

Provide a specific remediation for {asset['vendor']} {asset['product']} firmware {asset.get('firmware') or 'unknown'} with {cve['cve_id']}.
Name any specific patch, version, or vendor advisory if you know it."""


# ── Groq client ───────────────────────────────────────────────────────────────
def _call_groq(user_prompt: str, attempts: int = 3) -> str:
    """Call Groq API and return the assistant message content."""
    api_key = os.environ.get("GROQ_API_KEY") or GROQ_API_KEY

    payload = json.dumps({
        "model":       GROQ_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_prompt},
        ],
        "temperature":  0.2,
        "max_tokens":   900,
        "response_format": {"type": "json_object"},
    }).encode("utf-8")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
        "User-Agent":    "Mozilla/5.0",
    }

    last_exc = None
    for attempt in range(1, attempts + 1):
        try:
            req = urllib.request.Request(GROQ_API_URL, data=payload, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as r:
                resp = json.loads(r.read().decode("utf-8"))
            return resp["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8")
            except Exception:
                pass
            last_exc = RuntimeError(f"Groq HTTP {e.code}: {body[:300]}")
            if e.code in (400, 401, 403):
                raise last_exc
            if e.code == 429:
                wait = 15 * attempt
                print(f"  [Groq] rate limited — waiting {wait}s...")
                time.sleep(wait)
            elif attempt < attempts:
                time.sleep(5 * attempt)
        except Exception as e:
            last_exc = e
            if attempt < attempts:
                print(f"  [retry {attempt}/{attempts}] {e} — waiting {5*attempt}s...")
                time.sleep(5 * attempt)

    raise last_exc


def _parse_response(content: str) -> RemediationOutput:
    """Extract and validate JSON from the LLM response."""
    import re
    text = content.strip()
    text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL).strip()
    text = re.sub(r'```(?:json)?\s*', '', text).replace('```', '').strip()
    text = re.sub(r'//[^\n]*', '', text)

    start = text.find("{")
    end   = text.rfind("}") + 1
    if start == -1 or end == 0:
        raise ValueError(f"No JSON in response: {text[:300]}")

    return RemediationOutput.model_validate_json(text[start:end])


# ── Main entry point ──────────────────────────────────────────────────────────
def generate_remediation(asset, cve, attack_path_info=None, policy_context=None, attempts=3):
    """
    Generate a remediation recommendation for an asset/CVE pair.
    Returns (RemediationOutput, [])
    """
    prompt  = _build_prompt(asset, cve, attack_path_info, policy_context)
    content = _call_groq(prompt, attempts=attempts)
    result  = _parse_response(content)
    return result, []


# ── Smoke test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print(f"CAVE-OT Remediation Advisor — Groq ({GROQ_MODEL})")
    print("=" * 60)

    sample_asset = {
        "device_type": "Filtration_PLC", "vendor": "Siemens", "product": "S7-300",
        "firmware": "V3.2.5", "zone": "OT", "criticality": 0.98,
        "service": "S7comm", "port": 10201,
    }
    sample_cve = {
        "cve_id": "CVE-2018-13800", "cvss": 7.3, "epss": 0.0063, "kev": 0,
        "risk_score": 10.0, "risk_tier": "CRITICAL",
        "description": "Siemens SIMATIC S7-300 CPU web server DoS vulnerability.",
    }

    print(f"\nAsset: {sample_asset['vendor']} {sample_asset['product']}")
    print(f"CVE  : {sample_cve['cve_id']} CVSS={sample_cve['cvss']}")
    print("\nCalling Groq...")

    result, _ = generate_remediation(sample_asset, sample_cve)
    print("\nRESULT:")
    print(result.model_dump_json(indent=2))
