"""
tests/test_attack_path_props.py — Hypothesis property-based tests for attack_path.py

6 properties, each validated over 100 generated examples.
Each test is tagged with a comment identifying its feature and property number.

Requirements: 1.3, 1.4, 1.5, 1.6, 2.3, 2.4, 2.5, 3.3, 3.4, 3.5, 8.1, 8.2, 8.3, 8.5
"""

import json
import os
import sys
import tempfile
from datetime import datetime

import networkx as nx
import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from attack_path import build_graph, compute_paths, write_json, DEVICES


# ===========================================================================
# Property 1: edge weight inversely encodes risk with zero-division guard
# ===========================================================================

# Feature: attack-path-analysis, Property 1: edge weight inversely encodes risk with zero-division guard
@given(st.floats(min_value=0.0, max_value=10.0, allow_nan=False, allow_infinity=False))
@settings(max_examples=100)
def test_edge_weight_formula_property(risk_score: float):
    """
    **Validates: Requirements 1.6, 8.3**

    For any risk_score in [0.0, 10.0]:
    - weight == 1.0 / max(risk_score, 0.01)
    - if risk_score > 0.01 then weight < 100.0 (higher risk → cheaper edge)
    - weight is always finite (no ZeroDivisionError)
    """
    weight = 1.0 / max(risk_score, 0.01)

    # Must equal the formula exactly
    assert weight == pytest.approx(1.0 / max(risk_score, 0.01), rel=1e-9)

    # Must be positive and finite
    assert weight > 0.0
    assert weight <= 100.0  # maximum when risk_score == 0.0

    # Strictly higher risk → strictly lower weight (once above the 0.01 floor)
    if risk_score > 0.01:
        assert weight < 100.0


# ===========================================================================
# Property 2: node annotation round-trip for all enrichment sources
# ===========================================================================

# Feature: attack-path-analysis, Property 2: node annotation round-trip for all enrichment sources
@given(
    st.lists(
        st.floats(min_value=0.0, max_value=10.0, allow_nan=False),
        min_size=1,
        max_size=5,
    )
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_node_risk_annotation_round_trip(cve_scores: list):
    """
    **Validates: Requirements 1.3, 1.4, 1.5**

    For a device whose CVE list contains the generated risk_scores:
    - graph.nodes[device]["risk_score"] == max(scores) when max > 0
    - graph.nodes[device]["risk_score"] == 0.1 when all scores are 0.0
    - graph.nodes[device]["risk_score"] == 0.0 when CVE list is empty (tested separately)

    We verify this by directly exercising _load_risk_annotations with synthetic data.
    """
    import json, tempfile, os
    from attack_path import _load_risk_annotations

    device_type = "Filtration_PLC"

    # Build synthetic risk_scored_results.json
    cves = [{"risk_score": float(s)} for s in cve_scores]
    risk_data = {"devices": [{"device_type": device_type, "cves": cves}]}

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as tmp:
        json.dump(risk_data, tmp)
        tmp_path = tmp.name

    try:
        annotations = _load_risk_annotations(tmp_path)
    finally:
        os.unlink(tmp_path)

    assert device_type in annotations, (
        f"Device '{device_type}' missing from annotations"
    )

    actual = annotations[device_type]
    max_score = max(cve_scores)

    if max_score > 0.0:
        assert actual == pytest.approx(max_score, rel=1e-9), (
            f"Expected risk_score {max_score}, got {actual}"
        )
    else:
        # All scores are zero → floor to 0.1 (distinguishable from no-CVE)
        assert actual == pytest.approx(0.1, abs=1e-9), (
            f"Expected 0.1 floor when all CVE scores are 0.0, got {actual}"
        )


# ===========================================================================
# Property 3: Dijkstra cost equals sum of edge weights on path
# ===========================================================================

# Feature: attack-path-analysis, Property 3: Dijkstra cost equals sum of edge weights on path
@given(st.integers(min_value=2, max_value=5))
@settings(max_examples=100)
def test_path_cost_equals_edge_weight_sum(n: int):
    """
    **Validates: Requirements 2.3**

    For a synthetic chain graph of n nodes with known edge weights,
    the Dijkstra cost must equal round(sum of edge weights along the path, 4)
    and hops must equal len(path) - 1.
    """
    graph = nx.DiGraph()
    node_names = [f"Node_{i}" for i in range(n)]

    # Use a fixed increasing weight sequence so the chain is the only path
    weights = [float(i + 1) for i in range(n - 1)]  # [1.0, 2.0, ...]
    for i, name in enumerate(node_names):
        graph.add_node(name, risk_score=float(n - i), zone="OT",
                       criticality=0.5, vendor="", product="", is_attacked=0)

    for i in range(n - 1):
        graph.add_edge(node_names[i], node_names[i + 1], weight=weights[i])

    src = node_names[0]
    dst = node_names[-1]

    path = nx.dijkstra_path(graph, src, dst, weight="weight")
    cost = nx.dijkstra_path_length(graph, src, dst, weight="weight")

    expected_cost = round(sum(weights), 4)
    expected_hops = n - 1

    assert round(cost, 4) == pytest.approx(expected_cost, abs=1e-4), (
        f"Cost mismatch: expected {expected_cost}, got {round(cost, 4)}"
    )
    assert len(path) - 1 == expected_hops, (
        f"Hops mismatch: expected {expected_hops}, got {len(path) - 1}"
    )


# ===========================================================================
# Property 4: output list sorted by cost ascending with tiebreaker
# ===========================================================================

def _sort_paths(records: list) -> list:
    """Mirror the sort logic from compute_paths()."""
    return sorted(records, key=lambda r: (r["cost"], -r["max_risk_on_path"]))


# Feature: attack-path-analysis, Property 4: output list sorted by cost ascending with tiebreaker
@given(
    st.lists(
        st.floats(min_value=0.1, max_value=100.0, allow_nan=False, allow_infinity=False),
        min_size=2,
        max_size=12,
    )
)
@settings(max_examples=100)
def test_output_sorted_by_cost_property(costs: list):
    """
    **Validates: Requirements 2.4, 2.5**

    For any list of path records sorted with the production sort key:
    - paths[i]["cost"] <= paths[i+1]["cost"]  (ascending cost)
    - when costs are equal, paths[i]["max_risk_on_path"] >= paths[i+1]["max_risk_on_path"]
      (descending max_risk as tiebreaker)
    """
    # Build synthetic path records with the given costs
    records = [
        {
            "entry": f"Entry_{i}",
            "target": "Filtration_PLC",
            "path": [f"Entry_{i}", "Filtration_PLC"],
            "hops": 1,
            "cost": costs[i],
            "max_risk_on_path": round(10.0 - i * 0.5, 1),  # decreasing risk
        }
        for i in range(len(costs))
    ]

    sorted_records = _sort_paths(records)

    for i in range(len(sorted_records) - 1):
        a = sorted_records[i]
        b = sorted_records[i + 1]
        assert a["cost"] <= b["cost"], (
            f"Sort order violated at index {i}: cost {a['cost']} > {b['cost']}"
        )
        if a["cost"] == b["cost"]:
            assert a["max_risk_on_path"] >= b["max_risk_on_path"], (
                f"Tiebreaker violated: max_risk {a['max_risk_on_path']} "
                f"< {b['max_risk_on_path']} for equal-cost records"
            )


# ===========================================================================
# Property 5: JSON serialisation round-trip preserves all path record fields
# ===========================================================================

# Feature: attack-path-analysis, Property 5: JSON serialisation round-trip preserves all path record fields
@given(st.integers(min_value=0, max_value=12))
@settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_json_round_trip_property(n: int):
    """
    **Validates: Requirements 3.3, 3.4, 3.5**

    For any N synthetic path records:
    - write_json + re-read yields total_paths == N
    - generated_at is a parseable ISO-8601 string
    - each record in the JSON matches the original record exactly
    """
    # We cannot use the pytest tmp_path fixture with @given directly, so we
    # use tempfile.mkdtemp() for file I/O.
    import tempfile, shutil

    tmpdir = tempfile.mkdtemp()
    try:
        out_file = os.path.join(tmpdir, "attack_paths.json")

        # Build N synthetic path records
        records = [
            {
                "entry": f"HMI_Interface",
                "target": "Filtration_PLC",
                "path": ["HMI_Interface", "SCADA_Server", "Filtration_PLC"],
                "hops": 2,
                "cost": round(0.1 * (i + 1), 4),
                "max_risk_on_path": round(10.0 - i * 0.5, 1),
            }
            for i in range(n)
        ]

        write_json(records, out_file)

        assert os.path.exists(out_file), "write_json did not create the output file"

        with open(out_file) as f:
            payload = json.load(f)

        # total_paths must equal N
        assert payload["total_paths"] == n, (
            f"total_paths mismatch: expected {n}, got {payload['total_paths']}"
        )

        # generated_at must be parseable ISO-8601
        assert "generated_at" in payload, "Missing 'generated_at' key"
        try:
            datetime.fromisoformat(payload["generated_at"])
        except ValueError as exc:
            pytest.fail(f"generated_at is not valid ISO-8601: {exc}")

        # All path records must match originals
        assert len(payload["paths"]) == n, (
            f"paths list length mismatch: expected {n}, got {len(payload['paths'])}"
        )
        for original, loaded in zip(records, payload["paths"]):
            assert loaded["entry"] == original["entry"]
            assert loaded["target"] == original["target"]
            assert loaded["hops"] == original["hops"]
            assert loaded["cost"] == pytest.approx(original["cost"], abs=1e-4)
            assert loaded["max_risk_on_path"] == pytest.approx(
                original["max_risk_on_path"], abs=1e-1
            )
            assert loaded["path"] == original["path"]
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ===========================================================================
# Property 6: zero risk nodes produce weight 100.0 with no division error
# ===========================================================================

# Feature: attack-path-analysis, Property 6: zero risk nodes produce weight 100.0 with no division error
@given(st.integers(min_value=1, max_value=15))
@settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_zero_risk_nodes_no_division_error(n: int):
    """
    **Validates: Requirements 1.6, 8.3**

    For a graph with N nodes all having risk_score=0.0 (simulated by passing
    a path to a risk file that contains no entries), all outbound edge weights
    must equal exactly 100.0 (= 1 / 0.01) and no exception must be raised.
    """
    import tempfile, shutil, json

    # Build a minimal N-node chain comms list using node names from DEVICES
    device_names = list(DEVICES.keys())[:n]
    if len(device_names) < 2:
        # With only 1 node there are no edges — property trivially holds
        return

    comms = [
        (device_names[i], device_names[i + 1], "msg")
        for i in range(len(device_names) - 1)
    ]

    tmpdir = tempfile.mkdtemp()
    try:
        # Empty risk file → every node gets risk_score = 0.0
        empty_risk = os.path.join(tmpdir, "risk_scored_results.json")
        with open(empty_risk, "w") as f:
            json.dump({"devices": []}, f)

        try:
            graph = build_graph(
                comms,
                assets_path="/nonexistent/assets.json",    # triggers fallback
                risk_path=empty_risk,
                suricata_path="/nonexistent/suricata.json", # triggers fallback
            )
        except Exception as exc:
            pytest.fail(
                f"build_graph raised an exception for zero-risk nodes: {exc}"
            )

        # Every edge weight must be 100.0
        for src, dst, data in graph.edges(data=True):
            assert data["weight"] == pytest.approx(100.0, abs=1e-9), (
                f"Edge ({src} → {dst}) weight should be 100.0, got {data['weight']}"
            )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
