"""
tests/test_attack_path_integration.py — Integration tests for attack_path.py

Three end-to-end and API-level tests that exercise the full pipeline (JSON
output only — attack_path.py has no DB dependency, see its module docstring)
and the Flask API endpoints (paths and node annotations). DB upsert
idempotency is tested separately in tests/test_sync_db_attack_paths.py,
against Database/sync_db.py's ingestion of attack_paths.json.

Requirements: 3.1, 3.7, 4.1, 6.1, 6.2, 6.6
"""

import json
import os
import sys
import tempfile
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Path setup — allow importing from project root and Dashboard/
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

ASSETS_DIR    = os.path.join(PROJECT_ROOT, "docker", "shared")
ASSETS_PATH   = os.path.join(ASSETS_DIR, "assets.json")
RISK_PATH     = os.path.join(ASSETS_DIR, "risk_scored_results.json")
SURICATA_PATH = os.path.join(ASSETS_DIR, "suricata_context.json")


# ===========================================================================
# Test 1 — Full pipeline writes a parseable attack_paths.json  (Req 3.1, 4.1)
# ===========================================================================

def test_full_pipeline_produces_json():
    """
    Call run_attack_path_analysis() with:
      - CAVE_DIR overridden to a temp directory (so the JSON is written there)
      - sync_to_shared patched to a no-op

    Verify that attack_paths.json is created in the temp dir, is parseable
    JSON, and contains a "paths" list key.

    Requirements: 3.1, 4.1
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Copy the three enrichment files into the temp dir so the pipeline
        # can read them from CAVE_DIR (they already live in Assets/).
        # We point only the output to tmpdir; the inputs can be read from their
        # real locations via patching the module-level CAVE_DIR constant and
        # falling back to the Assets/ copies for assets/risk/suricata.

        # The simplest approach: patch the CAVE_DIR constant inside attack_path
        # so all four path resolutions (assets, risk, suricata, out_path) land
        # in or near the expected places.  We keep the three *input* paths
        # pointing at the real Assets/ folder by symlinking or by copying.
        import shutil
        for filename in ("assets.json", "risk_scored_results.json", "suricata_context.json"):
            src = os.path.join(ASSETS_DIR, filename)
            if os.path.exists(src):
                shutil.copy(src, os.path.join(tmpdir, filename))

        import attack_path  # noqa: import inside test for clarity

        with patch.object(attack_path, "CAVE_DIR", tmpdir), \
             patch.object(attack_path, "sync_to_shared", return_value=None):
            attack_path.run_attack_path_analysis()

        out_path = os.path.join(tmpdir, "attack_paths.json")

        # 1. File must exist
        assert os.path.exists(out_path), (
            f"attack_paths.json was not created in {tmpdir}"
        )

        # 2. Must be parseable JSON
        with open(out_path) as f:
            try:
                payload = json.load(f)
            except json.JSONDecodeError as exc:
                pytest.fail(f"attack_paths.json is not valid JSON: {exc}")

        # 3. Must contain a "paths" list key
        assert "paths" in payload, (
            f"Expected top-level 'paths' key in attack_paths.json; got keys: {list(payload.keys())}"
        )
        assert isinstance(payload["paths"], list), (
            f"'paths' value must be a list, got {type(payload['paths'])}"
        )

        # 4. Sanity-check additional expected top-level keys from the schema
        assert "generated_at" in payload, "Missing 'generated_at' in attack_paths.json"
        assert "total_paths"  in payload, "Missing 'total_paths' in attack_paths.json"
        assert payload["total_paths"] == len(payload["paths"]), (
            f"total_paths ({payload['total_paths']}) != len(paths) ({len(payload['paths'])})"
        )
        assert payload["total_paths"] > 0, (
            "Full pipeline against real Assets/ data produced zero attack "
            "paths — the module runs without error but finds nothing, which "
            "makes the feature silently useless end-to-end"
        )

        # 5. "nodes" key must be present and cover all 15 devices (Requirement 3.7)
        assert "nodes" in payload, "Missing 'nodes' key in attack_paths.json"
        assert len(payload["nodes"]) == 15, (
            f"Expected all 15 devices in 'nodes', got {len(payload['nodes'])}"
        )


# ===========================================================================
# Test 2 — Flask API endpoint returns valid JSON  (Req 6.1, 6.2)
# ===========================================================================

def test_api_endpoint():
    """
    Use the Flask test client to GET /api/attack_paths.

    Acceptable outcomes (test env has no live PostgreSQL DB):
      - 200 with a JSON array  (DB available and table may be empty or populated)
      - 500 with a JSON object containing an "error" key  (DB unavailable)

    In either case the response body MUST be valid JSON.

    Requirements: 6.1, 6.2
    """
    # Import the Flask app — the policy_api import inside app.py is guarded
    # with try/except, so it is safe to import without the full DB environment.
    dashboard_dir = os.path.join(PROJECT_ROOT, "Dashboard")
    if dashboard_dir not in sys.path:
        sys.path.insert(0, dashboard_dir)

    # Also expose the Policy_Compliance folder that app.py injects into sys.path
    policy_dir = os.path.join(PROJECT_ROOT, "Policy_Compliance")
    if policy_dir not in sys.path:
        sys.path.insert(0, policy_dir)

    from Dashboard.app import app as flask_app  # type: ignore

    flask_app.config["TESTING"] = True

    with flask_app.test_client() as client:
        response = client.get("/api/attack_paths")

        # Status must be 200 or 500 — anything else is unexpected
        assert response.status_code in (200, 500), (
            f"Unexpected HTTP status: {response.status_code}"
        )

        # Response body must be valid JSON regardless of status code
        raw = response.get_data(as_text=True)
        try:
            body = json.loads(raw)
        except json.JSONDecodeError as exc:
            pytest.fail(
                f"Response body is not valid JSON (status {response.status_code}): {exc}\n"
                f"Body: {raw[:500]}"
            )

        if response.status_code == 200:
            # On success, the body must be a JSON array
            assert isinstance(body, list), (
                f"Expected a JSON array on 200 OK, got {type(body)}: {raw[:200]}"
            )
        else:
            # On 500, the body must be a JSON object with an "error" key
            assert isinstance(body, dict), (
                f"Expected a JSON object on 500, got {type(body)}: {raw[:200]}"
            )
            assert "error" in body, (
                f"Expected 'error' key in 500 response body, got: {list(body.keys())}"
            )


# ===========================================================================
# Test 2b — /api/attack_path_nodes returns valid JSON  (Req 6.6)
# ===========================================================================

def test_node_api_endpoint():
    """
    Use the Flask test client to GET /api/attack_path_nodes.

    Acceptable outcomes (test env has no live PostgreSQL DB):
      - 200 with a JSON object  (DB available; may be empty or populated)
      - 500 with a JSON object containing an "error" key  (DB unavailable)

    Mirrors test_api_endpoint() but for the node-annotation endpoint, whose
    contract is a dict keyed by device_name rather than an array of records.

    Requirements: 6.6
    """
    dashboard_dir = os.path.join(PROJECT_ROOT, "Dashboard")
    if dashboard_dir not in sys.path:
        sys.path.insert(0, dashboard_dir)
    policy_dir = os.path.join(PROJECT_ROOT, "Policy_Compliance")
    if policy_dir not in sys.path:
        sys.path.insert(0, policy_dir)

    from Dashboard.app import app as flask_app  # type: ignore

    flask_app.config["TESTING"] = True

    with flask_app.test_client() as client:
        response = client.get("/api/attack_path_nodes")

        assert response.status_code in (200, 500), (
            f"Unexpected HTTP status: {response.status_code}"
        )

        raw = response.get_data(as_text=True)
        try:
            body = json.loads(raw)
        except json.JSONDecodeError as exc:
            pytest.fail(
                f"Response body is not valid JSON (status {response.status_code}): {exc}\n"
                f"Body: {raw[:500]}"
            )

        # Either way the payload must be a JSON object, never an array —
        # {} on empty/200, {"error": ...} on 500.
        assert isinstance(body, dict), (
            f"Expected a JSON object, got {type(body)}: {raw[:200]}"
        )
        if response.status_code == 500:
            assert "error" in body, (
                f"Expected 'error' key in 500 response body, got: {list(body.keys())}"
            )
