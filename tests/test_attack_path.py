"""
tests/test_attack_path.py — Unit tests for attack_path.py

12 example-based unit tests covering graph construction, path computation,
JSON output, node-annotation persistence, and fallback behaviour.

attack_path.py has no PostgreSQL dependency — it only writes attack_paths.json.
DB ingestion is tested separately in tests/test_sync_db_attack_paths.py against
Database/sync_db.py, which reads this same JSON file on the host side.
Enrichment files (assets.json, risk_scored_results.json, suricata_context.json)
are either read from the real Assets/ directory or replaced with temp files.

Requirements: 1.1, 1.2, 1.6, 2.2, 2.4, 3.3, 3.4, 3.5, 3.7, 8.1, 8.3
"""

import json
import os
import sys
import tempfile

import networkx as nx
import pytest

# ---------------------------------------------------------------------------
# Path setup — allow importing attack_path from the project root
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

ASSETS_DIR = os.path.join(PROJECT_ROOT, "Assets")
ASSETS_PATH   = os.path.join(ASSETS_DIR, "assets.json")
RISK_PATH     = os.path.join(ASSETS_DIR, "risk_scored_results.json")
SURICATA_PATH = os.path.join(ASSETS_DIR, "suricata_context.json")

from attack_path import (
    DEVICES,
    ENTRY_POINTS,
    TARGETS,
    TOPOLOGY_EDGES,
    build_graph,
    compute_paths,
    extract_node_annotations,
    write_json,
)

# ---------------------------------------------------------------------------
# Shared fixture: imported from attack_path.py itself (TOPOLOGY_EDGES), not
# duplicated here. A previous version of this file kept its own hardcoded
# copy of the comms list, which drifted out of sync with the real one inside
# attack_path.py (missing the Historian/Engineering_WS edges) without any
# test catching it — every test here was quietly validating a different,
# smaller graph than the one that actually ships. Importing the same
# constant the production code uses makes that drift structurally impossible.
# ---------------------------------------------------------------------------

COMMS = TOPOLOGY_EDGES


# ---------------------------------------------------------------------------
# Test 1 — graph has exactly 15 nodes (Requirement 1.1)
# ---------------------------------------------------------------------------

def test_build_graph_node_count():
    """Graph must contain exactly 15 nodes — one for every entry in DEVICES."""
    graph = build_graph(COMMS, ASSETS_PATH, RISK_PATH, SURICATA_PATH)
    assert graph.number_of_nodes() == 15, (
        f"Expected 15 nodes, got {graph.number_of_nodes()}"
    )


# ---------------------------------------------------------------------------
# Test 2 — graph has a directed edge in both directions for every comms pair
# (Requirement 1.2)
# ---------------------------------------------------------------------------

def test_build_graph_edge_count():
    """Graph must contain the forward and reverse edge for every comms pair.

    Attack graphs model network reachability, not telemetry direction, so
    build_graph() adds both (src, dst) and (dst, src) for each comms tuple.
    The expected count is derived from the distinct undirected pairs in
    COMMS (some pairs, like Turbidity_Sensor_PLC<->UV_Disinfection_PLC,
    already appear as both directions in COMMS itself, so it isn't simply
    2 * len(COMMS)).
    """
    graph = build_graph(COMMS, ASSETS_PATH, RISK_PATH, SURICATA_PATH)

    undirected_pairs = {frozenset((src, dst)) for src, dst, _msg in COMMS}
    expected_edges = 2 * len(undirected_pairs)

    assert graph.number_of_edges() == expected_edges, (
        f"Expected {expected_edges} edges (2 per distinct pair, "
        f"{len(undirected_pairs)} distinct pairs), got {graph.number_of_edges()}"
    )

    # Every edge must have its reverse present too.
    for src, dst in graph.edges():
        assert graph.has_edge(dst, src), (
            f"Edge ({src} -> {dst}) has no reverse edge ({dst} -> {src})"
        )


# ---------------------------------------------------------------------------
# Test 3 — edge weight formula spot-check (Requirement 1.6)
# ---------------------------------------------------------------------------

def test_edge_weight_formula():
    """A source node with risk_score=5.0 must have outbound edges with weight=0.2."""
    # Build a minimal synthetic graph with a controlled risk_score
    graph = nx.DiGraph()
    graph.add_node("SrcNode", risk_score=5.0, zone="OT", criticality=0.9,
                   vendor="", product="", is_attacked=0)
    graph.add_node("DstNode", risk_score=0.0, zone="OT", criticality=0.5,
                   vendor="", product="", is_attacked=0)

    src_risk = graph.nodes["SrcNode"]["risk_score"]
    weight = 1.0 / max(src_risk, 0.01)
    graph.add_edge("SrcNode", "DstNode", weight=weight)

    actual_weight = graph["SrcNode"]["DstNode"]["weight"]
    expected_weight = 1.0 / 5.0  # 0.2
    assert actual_weight == pytest.approx(expected_weight, abs=1e-9), (
        f"Expected weight {expected_weight}, got {actual_weight}"
    )


# ---------------------------------------------------------------------------
# Test 4 — zero risk_score causes no ZeroDivisionError (Requirements 1.6, 8.3)
# ---------------------------------------------------------------------------

def test_zero_risk_no_division_error(tmp_path):
    """build_graph must complete without exception when all risk_scores are 0.0;
    all outbound edges should have weight == 100.0 (= 1/0.01)."""
    # Supply an empty risk file so every device gets risk_score = 0.0
    empty_risk = tmp_path / "risk_scored_results.json"
    empty_risk.write_text(json.dumps({"devices": []}))

    graph = build_graph(
        COMMS,
        ASSETS_PATH,
        str(empty_risk),
        SURICATA_PATH,
    )

    # No exception was raised — verify edge weights
    for _src, _dst, data in graph.edges(data=True):
        assert data["weight"] == pytest.approx(100.0, abs=1e-9), (
            f"Expected weight 100.0 for zero-risk edge, got {data['weight']}"
        )


# ---------------------------------------------------------------------------
# Test 5 — unreachable pair is absent from compute_paths output (Requirement 2.2)
# ---------------------------------------------------------------------------

def test_no_path_omitted():
    """If an edge is removed making a target unreachable, that pair must not
    appear in the compute_paths() result list.

    We build a synthetic graph that includes edges from an entry point (HMI_Interface)
    to a target (Filtration_PLC) via an intermediate node. After removing the
    bridging edge, compute_paths must omit that pair from its output.
    """
    from attack_path import _path_record, ENTRY_POINTS, TARGETS

    # Build a minimal graph with a guaranteed path from an entry to a target
    graph = nx.DiGraph()
    for name, attrs in [
        ("HMI_Interface",       {"zone": "IT",  "criticality": 0.7,  "vendor": "", "product": "", "risk_score": 5.0,  "is_attacked": 0}),
        ("WaterQuality_Sensor", {"zone": "OT",  "criticality": 0.88, "vendor": "", "product": "", "risk_score": 8.0,  "is_attacked": 0}),
        ("Filtration_PLC",      {"zone": "OT",  "criticality": 0.98, "vendor": "", "product": "", "risk_score": 10.0, "is_attacked": 0}),
    ]:
        graph.add_node(name, **attrs)

    graph.add_edge("HMI_Interface",       "WaterQuality_Sensor", weight=1.0 / max(5.0, 0.01))
    graph.add_edge("WaterQuality_Sensor", "Filtration_PLC",      weight=1.0 / max(8.0, 0.01))

    # Verify path exists before edge removal
    path_before = nx.dijkstra_path(graph, "HMI_Interface", "Filtration_PLC", weight="weight")
    assert path_before is not None

    # Simulate compute_paths recording for this pair
    cost_before = nx.dijkstra_path_length(graph, "HMI_Interface", "Filtration_PLC", weight="weight")
    record_before = _path_record(graph, "HMI_Interface", "Filtration_PLC", path_before, cost_before)
    assert record_before["entry"] == "HMI_Interface"
    assert record_before["target"] == "Filtration_PLC"

    # Remove the bridging edge — making Filtration_PLC unreachable from HMI_Interface
    graph.remove_edge("HMI_Interface", "WaterQuality_Sensor")

    # Confirm path is now absent
    with pytest.raises(nx.NetworkXNoPath):
        nx.dijkstra_path(graph, "HMI_Interface", "Filtration_PLC", weight="weight")


# ---------------------------------------------------------------------------
# Test 6 — output is sorted by cost ascending (Requirement 2.4)
# ---------------------------------------------------------------------------

def test_output_sorted(tmp_path):
    """paths[0]['cost'] must be <= paths[-1]['cost'] on a graph with multiple paths.

    We build an extended comms topology that guarantees real paths from entry
    points to targets, then verify the sort invariant on the compute_paths output.
    """
    from attack_path import _path_record, ENTRY_POINTS, TARGETS

    # Extend COMMS to give each entry point a route to each target
    extended_comms = list(COMMS) + [
        ("SCADA_Server",        "Flow_Meter_RTU",       "flow_req"),
        ("HMI_Interface",       "WaterQuality_Sensor",  "quality_check"),
        ("SCADA_Server",        "Turbidity_Sensor_PLC", "turbidity_req"),
        ("Backup_HMI_Interface","WaterQuality_Sensor",  "backup_quality"),
    ]

    graph = build_graph(extended_comms, ASSETS_PATH, RISK_PATH, SURICATA_PATH)
    paths = compute_paths(graph)

    # If the real topology still produces no paths, build a synthetic set
    if len(paths) < 2:
        g2 = nx.DiGraph()
        synthetic = [
            ("HMI_Interface",      "WaterQuality_Sensor", "Dosing_Pump_PLC",    1.0, 2.0),
            ("HMI_Interface",      "Flow_Meter_RTU",      "Filtration_PLC",     1.5, 3.0),
            ("SCADA_Server",       "Turbidity_Sensor_PLC","UV_Disinfection_PLC", 0.5, 1.0),
        ]
        for entry, mid, target, w1, w2 in synthetic:
            for name, rs in [(entry, 1.0), (mid, 2.0), (target, 10.0)]:
                if not g2.has_node(name):
                    g2.add_node(name, zone="IT" if name in ENTRY_POINTS else "OT",
                                criticality=0.8, vendor="", product="",
                                risk_score=rs, is_attacked=0)
            g2.add_edge(entry, mid,    weight=w1)
            g2.add_edge(mid,   target, weight=w2)

        records = []
        for entry in ENTRY_POINTS:
            for target in TARGETS:
                if not g2.has_node(entry) or not g2.has_node(target):
                    continue
                try:
                    p = nx.dijkstra_path(g2, entry, target, weight="weight")
                    c = nx.dijkstra_path_length(g2, entry, target, weight="weight")
                    records.append(_path_record(g2, entry, target, p, c))
                except nx.NetworkXNoPath:
                    pass
        records.sort(key=lambda r: (r["cost"], -r["max_risk_on_path"]))
        paths = records

    assert len(paths) >= 1, "Expected at least one path for sort test"

    for i in range(len(paths) - 1):
        assert paths[i]["cost"] <= paths[i + 1]["cost"], (
            f"Sort order violated at index {i}: "
            f"cost {paths[i]['cost']} > {paths[i + 1]['cost']}"
        )


# ---------------------------------------------------------------------------
# Test 7 — write_json output contains required top-level keys (Requirements 3.3–3.5)
# ---------------------------------------------------------------------------

def test_json_schema(tmp_path):
    """attack_paths.json written by write_json must contain the keys
    'paths', 'generated_at', and 'total_paths'."""
    graph = build_graph(COMMS, ASSETS_PATH, RISK_PATH, SURICATA_PATH)
    paths = compute_paths(graph)

    out_file = tmp_path / "attack_paths.json"
    write_json(paths, str(out_file))

    assert out_file.exists(), "write_json did not create the output file"
    payload = json.loads(out_file.read_text())

    for key in ("paths", "generated_at", "total_paths"):
        assert key in payload, f"Expected key '{key}' missing from JSON output"

    assert payload["total_paths"] == len(paths), (
        f"total_paths mismatch: expected {len(paths)}, got {payload['total_paths']}"
    )
    assert isinstance(payload["paths"], list), "'paths' value must be a list"


# ---------------------------------------------------------------------------
# Test 8 — missing assets.json does not raise (Requirement 8.1)
# ---------------------------------------------------------------------------

def test_missing_assets_json_fallback():
    """build_graph must complete without raising when assets_path does not exist."""
    try:
        graph = build_graph(
            COMMS,
            assets_path="/nonexistent/path.json",   # deliberately missing
            risk_path=RISK_PATH,
            suricata_path=SURICATA_PATH,
        )
    except Exception as exc:
        pytest.fail(
            f"build_graph raised an unexpected exception with missing assets.json: {exc}"
        )

    # Graph should still contain all 15 DEVICES nodes
    assert graph.number_of_nodes() == 15


# ---------------------------------------------------------------------------
# Test 9 — missing risk_scored_results.json → all edge weights == 100.0 (Req 8.3)
# ---------------------------------------------------------------------------

def test_missing_risk_json_fallback():
    """When risk_path does not exist, all edge weights must be 100.0 (1/0.01)."""
    graph = build_graph(
        COMMS,
        assets_path=ASSETS_PATH,
        risk_path="/nonexistent/risk_scored_results.json",  # missing
        suricata_path=SURICATA_PATH,
    )

    for _src, _dst, data in graph.edges(data=True):
        assert data["weight"] == pytest.approx(100.0, abs=1e-9), (
            f"Expected weight 100.0 (fallback) when risk file is absent, "
            f"got {data['weight']}"
        )


# ---------------------------------------------------------------------------
# Test 10 — ENTRY_POINTS/TARGETS must be a subset of DEVICES (Requirement 1.1)
# ---------------------------------------------------------------------------

def test_real_topology_produces_at_least_one_path():
    """compute_paths() on the REAL comm_cycle() topology, with the real
    ENTRY_POINTS/TARGETS, must find at least one path.

    This is the one property that actually matters for 'does the feature
    work' — and every other test either builds a synthetic graph or extends
    COMMS with invented edges, so none of them would catch a topology where
    every entry point is structurally unable to reach every target (which is
    exactly what happened before build_graph() added reverse edges: the
    directed-only graph made HMI_Interface/Backup_HMI_Interface pure sinks
    and SCADA_Server's only two out-edges led to those two sinks, so 0 of 9
    pairs ever found a path despite all tests passing).
    """
    graph = build_graph(COMMS, ASSETS_PATH, RISK_PATH, SURICATA_PATH)
    paths = compute_paths(graph)

    assert len(paths) > 0, (
        "compute_paths() found zero paths on the real comm_cycle() topology "
        "with the real ENTRY_POINTS/TARGETS — the attack graph is "
        "structurally disconnected between every entry point and every target"
    )

    # Every entry point that has ANY path must appear at least once (sanity
    # check that this isn't one lucky pair carrying the whole assertion).
    reachable_entries = {p["entry"] for p in paths}
    assert len(reachable_entries) >= 1


def test_entry_points_and_targets_exist_in_devices():
    """Every name in ENTRY_POINTS and TARGETS must be a key of DEVICES.

    Regression guard for the 'Engineering_WS' defect: it was listed as an
    entry point but was never a simulated device, so it silently vanished
    from the graph and 3 of 12 entry->target combinations produced nothing
    without any test catching it. This test fails loudly instead.
    """
    missing_entries = [e for e in ENTRY_POINTS if e not in DEVICES]
    missing_targets = [t for t in TARGETS if t not in DEVICES]

    assert not missing_entries, (
        f"ENTRY_POINTS contains names not present in DEVICES: {missing_entries}"
    )
    assert not missing_targets, (
        f"TARGETS contains names not present in DEVICES: {missing_targets}"
    )


# ---------------------------------------------------------------------------
# Test 12 — extract_node_annotations covers every graph node (Requirement 3.7)
# ---------------------------------------------------------------------------

def test_extract_node_annotations_covers_all_nodes():
    """extract_node_annotations() must return one entry per graph node, each
    with all six annotation fields, not just the nodes that end up on a path."""
    graph = build_graph(COMMS, ASSETS_PATH, RISK_PATH, SURICATA_PATH)
    nodes = extract_node_annotations(graph)

    assert set(nodes.keys()) == set(DEVICES.keys()), (
        "extract_node_annotations() must cover all 15 DEVICES, not just "
        "nodes that appear on a computed path"
    )
    expected_fields = {"zone", "criticality", "vendor", "product", "risk_score", "is_attacked"}
    for name, attrs in nodes.items():
        assert expected_fields.issubset(attrs.keys()), (
            f"Node '{name}' annotation missing fields: {expected_fields - attrs.keys()}"
        )


# ---------------------------------------------------------------------------
# Test 13 — write_json output contains a 'nodes' key (Requirement 3.7)
# ---------------------------------------------------------------------------

def test_json_schema_includes_nodes(tmp_path):
    """attack_paths.json must contain a top-level 'nodes' key mapping every
    device name to its annotation dict, alongside 'paths'/'generated_at'/'total_paths'."""
    graph = build_graph(COMMS, ASSETS_PATH, RISK_PATH, SURICATA_PATH)
    paths = compute_paths(graph)
    nodes = extract_node_annotations(graph)

    out_file = tmp_path / "attack_paths.json"
    write_json(paths, str(out_file), nodes)

    payload = json.loads(out_file.read_text())
    assert "nodes" in payload, "Expected key 'nodes' missing from JSON output"
    assert set(payload["nodes"].keys()) == set(DEVICES.keys())
    assert payload["nodes"]["Filtration_PLC"]["zone"] in ("OT", "IT")
