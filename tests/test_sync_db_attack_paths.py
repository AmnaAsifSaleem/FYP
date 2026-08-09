"""
tests/test_sync_db_attack_paths.py — Unit tests for sync_db.py's attack-path ingestion

Database/sync_db.py is where attack_paths.json actually reaches PostgreSQL —
attack_path.py itself (running on the VM) only ever writes the JSON file, the
same way it does for assets.json/risk_scored_results.json/etc. These tests
cover sync_attack_paths(cur), the function that reads that JSON and upserts
into attack_paths + attack_path_nodes, using a mocked cursor (no live DB
connection needed).

Requirements: 5.1–5.7 (attack-path-analysis spec, DB Persistence — now
fulfilled by the host-side sync_db.py rather than attack_path.py directly)
"""

import json
import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_DIR = os.path.join(PROJECT_ROOT, "Database")
for p in (PROJECT_ROOT, DATABASE_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

import sync_db  # noqa: E402


SAMPLE_PAYLOAD = {
    "generated_at": "2026-07-17T20:00:00",
    "total_paths": 2,
    "paths": [
        {
            "entry": "HMI_Interface", "target": "Filtration_PLC",
            "path": ["HMI_Interface", "SCADA_Server", "Filtration_PLC"],
            "hops": 2, "cost": 0.2, "max_risk_on_path": 10.0,
        },
        {
            "entry": "SCADA_Server", "target": "Dosing_Pump_PLC",
            "path": ["SCADA_Server", "Dosing_Pump_PLC"],
            "hops": 1, "cost": 0.1, "max_risk_on_path": 9.5,
        },
    ],
    "nodes": {
        "HMI_Interface": {
            "zone": "IT", "criticality": 0.7, "vendor": "Siemens",
            "product": "WinCC OA", "risk_score": 10.0, "is_attacked": 0,
        },
        "SCADA_Server": {
            "zone": "IT", "criticality": 0.95, "vendor": "Dell",
            "product": "iDRAC 8", "risk_score": 10.0, "is_attacked": 1,
        },
    },
}


def _mock_cursor():
    return MagicMock()


# ---------------------------------------------------------------------------
# Test 1 — missing attack_paths.json returns (0, 0) with no DB calls
# ---------------------------------------------------------------------------

def test_sync_attack_paths_missing_file_returns_zero():
    """When attack_paths.json doesn't exist (e.g. VM cave_monitor.py without
    the hook wired in), sync_attack_paths must return (0, 0) and never touch
    the cursor."""
    cur = _mock_cursor()
    with patch.object(sync_db, "ATTACK_PATHS", "/nonexistent/attack_paths.json"):
        paths_saved, nodes_saved = sync_db.sync_attack_paths(cur)

    assert (paths_saved, nodes_saved) == (0, 0)
    cur.execute.assert_not_called()


# ---------------------------------------------------------------------------
# Test 2 — valid file upserts every path and every node
# ---------------------------------------------------------------------------

def test_sync_attack_paths_upserts_all_records():
    """With a real attack_paths.json, every path record and every node record
    must produce one upsert cur.execute() call each, after the CREATE TABLE
    statement."""
    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = os.path.join(tmpdir, "attack_paths.json")
        with open(json_path, "w") as f:
            json.dump(SAMPLE_PAYLOAD, f)

        cur = _mock_cursor()
        with patch.object(sync_db, "ATTACK_PATHS", json_path):
            paths_saved, nodes_saved = sync_db.sync_attack_paths(cur)

    assert paths_saved == 2
    assert nodes_saved == 2

    # 1 CREATE TABLE call + 2 path upserts + 2 node upserts = 5 execute() calls
    assert cur.execute.call_count == 5


# ---------------------------------------------------------------------------
# Test 3 — idempotent: calling twice with identical data upserts identically
# ---------------------------------------------------------------------------

def test_sync_attack_paths_idempotent():
    """Calling sync_attack_paths twice with the same JSON must issue the same
    shape of upserts each time (ON CONFLICT DO UPDATE, not duplicate INSERTs)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = os.path.join(tmpdir, "attack_paths.json")
        with open(json_path, "w") as f:
            json.dump(SAMPLE_PAYLOAD, f)

        cur = _mock_cursor()
        with patch.object(sync_db, "ATTACK_PATHS", json_path):
            first = sync_db.sync_attack_paths(cur)
            second = sync_db.sync_attack_paths(cur)

    assert first == second == (2, 2)
    # 2 calls x 5 execute()s each (1 CREATE + 2 paths + 2 nodes)
    assert cur.execute.call_count == 10


# ---------------------------------------------------------------------------
# Test 4 — path upsert SQL carries the correct entry/target/path_json
# ---------------------------------------------------------------------------

def test_sync_attack_paths_upsert_params_correct():
    """The params passed to the path upsert must match the JSON record —
    catches silent field-name mismatches between attack_path.py's output
    schema and sync_db.py's ingestion."""
    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = os.path.join(tmpdir, "attack_paths.json")
        with open(json_path, "w") as f:
            json.dump(SAMPLE_PAYLOAD, f)

        cur = _mock_cursor()
        with patch.object(sync_db, "ATTACK_PATHS", json_path):
            sync_db.sync_attack_paths(cur)

    # Second execute() call (index 1, after the CREATE TABLE at index 0) is
    # the first path upsert
    _sql, params = cur.execute.call_args_list[1].args
    assert params["entry"] == "HMI_Interface"
    assert params["target"] == "Filtration_PLC"
    assert params["hops"] == 2
    assert params["max_risk"] == 10.0
    assert json.loads(params["path_json"]) == ["HMI_Interface", "SCADA_Server", "Filtration_PLC"]
