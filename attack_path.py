"""
attack_path.py — Attack Path Analysis for CAVE-OT

Builds a risk-weighted directed graph from the water-treatment plant's 15-device
OT/ICS communication topology, computes the cheapest (highest-risk) Dijkstra paths
from internet-facing IT entry points to high-criticality OT targets, and writes
the results to attack_paths.json for the Windows host to pick up.

Called by cave_monitor.run_discovery() as the final pipeline step. Runs entirely
on the VM — it has no PostgreSQL dependency (the VM's "localhost" isn't the
Windows host running Postgres, and reaching across the VM/host network boundary
for a direct DB write would mean opening the database to the VM's subnet, which
is the wrong tradeoff for a testbed whose whole point is modelling untrusted
lateral movement). Ingestion into attack_paths/attack_path_nodes happens on the
host side, in Database/sync_db.py, the same way every other pipeline JSON output
already gets into Postgres via file_watcher.py.
"""

import os
import json
import datetime

import networkx as nx

# ── cave_monitor imports — guarded for test isolation ────────────────────────
try:
    from cave_monitor import CAVE_DIR, DEVICES, log_event, sync_to_shared
except ImportError:
    # Stubs used when running tests without the full cave_monitor environment
    CAVE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)))

    DEVICES = {
        "Dosing_Pump_PLC":        {"port": 502,   "proto": "modbus", "zone": "OT", "delay": 0,  "container": "conpot"},
        "Filtration_PLC":         {"port": 10201, "proto": "s7",     "zone": "OT", "delay": 0,  "container": "conpot"},
        "Ventilation_Controller": {"port": 47808, "proto": "bacnet", "zone": "OT", "delay": 0,  "container": "conpot"},
        "Water_Level_RTU":        {"port": 20000, "proto": "dnp3",   "zone": "OT", "delay": 0,  "container": "conpot"},
        "WaterQuality_Sensor":    {"port": 5020,  "proto": "modbus", "zone": "OT", "delay": 0,  "container": "conpot"},
        "SCADA_Server":           {"port": 6230,  "proto": "tcp",    "zone": "IT", "delay": 0,  "container": "conpot"},
        "HMI_Interface":          {"port": 80,    "proto": "http",   "zone": "IT", "delay": 0,  "container": "conpot"},
        "Turbidity_Sensor_PLC":   {"port": 5031,  "proto": "modbus", "zone": "OT", "delay": 0,  "container": "conpot_turbidity"},
        "UV_Disinfection_PLC":    {"port": 5032,  "proto": "modbus", "zone": "OT", "delay": 0,  "container": "conpot_uv"},
        "Flow_Meter_RTU":         {"port": 20001, "proto": "dnp3",   "zone": "OT", "delay": 0,  "container": "conpot_flowmeter"},
        "Backup_HMI_Interface":   {"port": 8080,  "proto": "http",   "zone": "IT", "delay": 0,  "container": "conpot_backup_hmi"},
        "Historian":              {"port": 443,   "proto": "http",   "zone": "IT", "delay": 0,  "container": "conpot_historian"},
        "Engineering_WS":         {"port": 2222,  "proto": "tcp",    "zone": "IT", "delay": 0,  "container": "conpot_engineering_ws"},
        "Reservoir_Level_PLC":    {"port": 10203, "proto": "s7",     "zone": "OT", "delay": 15, "container": "conpot_reservior"},
        "Booster_Pump_PLC":       {"port": 10204, "proto": "s7",     "zone": "OT", "delay": 25, "container": "conpot_booster"},
    }

    def log_event(msg, color=""):
        """Stub log_event used when cave_monitor is not available."""
        print(f"[attack_path] {msg}", flush=True)

    def sync_to_shared(*filenames):
        """Stub sync_to_shared used when cave_monitor is not available."""
        pass

# ── Constants ────────────────────────────────────────────────────────────────

# Internet-facing IT assets that a remote attacker could reach first.
# NOTE: must be a subset of DEVICES — see test_entry_points_and_targets_exist_in_devices().
# "Engineering_WS" was previously removed from this list because it wasn't a
# simulated device in DEVICES at the time. DEVICES now includes it (2026-07-17,
# replacing "DMZ_Gateway", which was a stale one-off never used anywhere else
# in the codebase — sync_db.py/smart_discover.py/the VM's live cave_monitor.py
# all already used "Engineering_WS"), so it's back as a legitimate entry point.
ENTRY_POINTS = [
    "HMI_Interface",
    "Backup_HMI_Interface",
    "SCADA_Server",
    "Engineering_WS",
]

# High-criticality OT process-control assets — compromise has greatest physical impact.
# Booster_Pump_PLC/Reservoir_Level_PLC added 2026-07-17: both are graph-connected
# and reachable from every entry point but were never queried as a Dijkstra
# destination, so they silently never appeared in output despite being
# among the highest-criticality OT assets (0.93/0.91 — see CRITICALITY_MAP
# in smart_discover.py).
TARGETS = [
    "Filtration_PLC",
    "Dosing_Pump_PLC",
    "UV_Disinfection_PLC",
    "Booster_Pump_PLC",
    "Reservoir_Level_PLC",
]

# Static replica of cave_monitor.comm_cycle()'s comms list — extracted to a
# single module-level constant (rather than a local list duplicated inside
# run_attack_path_analysis() and, separately, in every test file) specifically
# so it can only drift out of sync with the live topology in one place instead
# of several. It still can't be the *live* comms list — comm_cycle() runs in
# an infinite loop and only exists inside a running cave_monitor.py process —
# but at least there is now exactly one copy to keep in sync, not three.
# Must match cave_monitor.py's comm_cycle() exactly.
TOPOLOGY_EDGES = [
    ("Water_Level_RTU",       "SCADA_Server",         "level"),
    ("Turbidity_Sensor_PLC",  "UV_Disinfection_PLC",  "NTU"),
    ("WaterQuality_Sensor",   "Dosing_Pump_PLC",       "Cl"),
    ("Flow_Meter_RTU",        "Filtration_PLC",        "flow"),
    ("Reservoir_Level_PLC",   "Booster_Pump_PLC",      "res"),
    ("Ventilation_Controller","SCADA_Server",           "vent"),
    ("SCADA_Server",          "HMI_Interface",          "dashboard"),
    ("SCADA_Server",          "Backup_HMI_Interface",   "dashboard"),
    ("Filtration_PLC",        "WaterQuality_Sensor",    "req quality"),
    ("Dosing_Pump_PLC",       "Water_Level_RTU",        "confirm level"),
    ("UV_Disinfection_PLC",   "Turbidity_Sensor_PLC",   "confirm NTU"),
    ("Booster_Pump_PLC",      "Flow_Meter_RTU",         "confirm flow"),
    ("Historian",             "SCADA_Server",           "data archive"),
    ("Engineering_WS",        "SCADA_Server",           "eng access"),
    ("SCADA_Server",          "Historian",              "log data"),
    ("SCADA_Server",          "Engineering_WS",         "status push"),
]

# ── Graph annotation helpers ─────────────────────────────────────────────────

def _load_asset_annotations(path: str) -> dict:
    """Return asset annotation data keyed by device_type from assets.json.

    Args:
        path: Absolute path to assets.json.

    Returns:
        dict mapping device_type (str) to a dict with keys:
        zone, criticality, vendor, product. Returns an empty dict if the
        file is missing or cannot be parsed.
    """
    result = {}
    try:
        with open(path) as f:
            assets = json.load(f)
        for entry in assets:
            dt = entry.get("device_type")
            if dt:
                result[dt] = {
                    "zone":        entry.get("zone", "OT"),
                    "criticality": float(entry.get("criticality", 0.5)),
                    "vendor":      entry.get("vendor", ""),
                    "product":     entry.get("product", ""),
                }
    except FileNotFoundError:
        log_event(f"attack_path: assets.json not found at {path} — asset enrichment skipped")
    except Exception as e:
        log_event(f"attack_path: failed to load assets.json: {e}")
    return result


def _load_risk_annotations(path: str) -> dict:
    """Return risk info keyed by device_type from risk_scored_results.json.

    For each device, risk_score is the maximum CVE risk_score across all of
    its CVE entries — and top_cve_id/top_cve_cvss/top_cve_tier identify
    *which* CVE produced that max, so a node isn't just labelled "risky" with
    no explanation of what's actually exploitable there. Devices with no CVE
    entries get risk_score=0.0 and no top_cve_id. Devices with CVE entries
    but all-zero scores get risk_score=0.1 (distinguishable from no-data).

    Args:
        path: Absolute path to risk_scored_results.json.

    Returns:
        dict mapping device_type (str) to a dict with keys: risk_score,
        top_cve_id, top_cve_cvss, top_cve_tier. Returns an empty dict if the
        file is missing or cannot be parsed.
    """
    result = {}
    try:
        with open(path) as f:
            data = json.load(f)
        for entry in data.get("devices", []):
            dt = entry.get("device_type")
            if not dt:
                continue
            cves = entry.get("cves", [])
            if not cves:
                result[dt] = {"risk_score": 0.0, "top_cve_id": None,
                               "top_cve_cvss": None, "top_cve_tier": None}
            else:
                top = max(cves, key=lambda c: float(c.get("risk_score", 0.0)))
                max_score = float(top.get("risk_score", 0.0))
                result[dt] = {
                    # Floor: CVEs present but all zero → 0.1 so distinguishable from no-data
                    "risk_score":   max_score if max_score > 0.0 else 0.1,
                    "top_cve_id":   top.get("cve_id"),
                    "top_cve_cvss": float(top.get("cvss", 0.0)),
                    "top_cve_tier": top.get("risk_tier"),
                }
    except FileNotFoundError:
        log_event(f"attack_path: risk_scored_results.json not found at {path} — all risk_score=0.0")
    except Exception as e:
        log_event(f"attack_path: failed to load risk_scored_results.json: {e}")
    return result


def _load_cve_descriptions(cve_ids: set) -> dict:
    """Return {cve_id: description} for the given CVE IDs, from the trained
    OT CVE database (model/ot_cve_database.pkl) — the same corpus
    cve_discovery.py matches against. Best-effort: returns {} if the model
    isn't available (e.g. not copied into this environment) rather than
    failing the whole attack-path run over a "nice to have" description.
    """
    if not cve_ids:
        return {}
    try:
        import joblib
        db_path = os.path.join(CAVE_DIR, "model", "ot_cve_database.pkl")
        if not os.path.exists(db_path):
            return {}
        db = joblib.load(db_path)
        matched = db[db["cve_id"].isin(cve_ids)]
        return dict(zip(matched["cve_id"], matched["description"]))
    except Exception as e:
        log_event(f"attack_path: CVE description lookup failed (non-fatal): {e}")
        return {}


def _load_suricata_annotations(path: str) -> dict:
    """Return is_attacked flag keyed by device_type from suricata_context.json.

    Args:
        path: Absolute path to suricata_context.json.

    Returns:
        dict mapping device_type (str) to int (0 or 1). Returns an empty dict
        if the file is missing or cannot be parsed.
    """
    result = {}
    try:
        with open(path) as f:
            data = json.load(f)
        # suricata_context.json may be a list of dicts or a dict keyed by device_type
        if isinstance(data, list):
            for entry in data:
                dt = entry.get("device_type")
                if dt:
                    result[dt] = int(entry.get("is_attacked", 0))
        elif isinstance(data, dict):
            for dt, entry in data.items():
                if isinstance(entry, dict):
                    result[dt] = int(entry.get("is_attacked", 0))
                else:
                    result[dt] = int(entry)
    except FileNotFoundError:
        log_event(f"attack_path: suricata_context.json not found at {path} — all is_attacked=0")
    except Exception as e:
        log_event(f"attack_path: failed to load suricata_context.json: {e}")
    return result


# ── Graph construction ───────────────────────────────────────────────────────

def build_graph(
    comms: list,
    assets_path: str,
    risk_path: str,
    suricata_path: str,
) -> nx.DiGraph:
    """Build an annotated directed graph from comm pairs and three JSON sources.

    Constructs a networkx.DiGraph with all 15 CAVE-OT devices as nodes and the
    12 directed communication edges from comm_cycle(). Each node is annotated
    with zone, criticality, vendor, product (from assets.json), risk_score (from
    risk_scored_results.json), and is_attacked (from suricata_context.json).
    Edge weights are set to 1.0 / max(source_risk_score, 0.01) so that
    higher-risk devices produce cheaper edges for Dijkstra.

    Args:
        comms: List of (src, dst, msg) tuples defining directed communication edges.
        assets_path: Absolute path to assets.json.
        risk_path: Absolute path to risk_scored_results.json.
        suricata_path: Absolute path to suricata_context.json.

    Returns:
        nx.DiGraph: Annotated directed graph ready for Dijkstra path computation.
    """
    graph = nx.DiGraph()

    # Step 1: Add all 15 known devices as nodes with zero-filled defaults
    for name, info in DEVICES.items():
        graph.add_node(name, **{
            "zone":            info.get("zone", "OT"),
            "criticality":     0.5,
            "vendor":          "",
            "product":         "",
            "risk_score":      0.0,
            "is_attacked":     0,
            "top_cve_id":      None,
            "top_cve_cvss":    None,
            "top_cve_tier":    None,
            "top_cve_desc":    None,
        })

    # Step 2: Load enrichment sources
    asset_data    = _load_asset_annotations(assets_path)
    risk_data     = _load_risk_annotations(risk_path)
    suricata_data = _load_suricata_annotations(suricata_path)

    # Step 3: Apply asset annotations (zone, criticality, vendor, product)
    for name in graph.nodes:
        if name in asset_data:
            graph.nodes[name].update(asset_data[name])

    # Step 4: Apply risk score + top-CVE annotations — this is what lets the
    # dashboard explain *which* vulnerability makes a node exploitable,
    # rather than just showing an unexplained risk number.
    for name in graph.nodes:
        if name in risk_data:
            info = risk_data[name]
            graph.nodes[name]["risk_score"]   = info["risk_score"]
            graph.nodes[name]["top_cve_id"]   = info["top_cve_id"]
            graph.nodes[name]["top_cve_cvss"] = info["top_cve_cvss"]
            graph.nodes[name]["top_cve_tier"] = info["top_cve_tier"]

    # Step 4b: Look up plain-English descriptions for every top CVE found,
    # in one batched query against the CVE corpus rather than one per node.
    top_cve_ids = {attrs["top_cve_id"] for _, attrs in graph.nodes(data=True) if attrs.get("top_cve_id")}
    descriptions = _load_cve_descriptions(top_cve_ids)
    for name in graph.nodes:
        cve_id = graph.nodes[name].get("top_cve_id")
        if cve_id and cve_id in descriptions:
            graph.nodes[name]["top_cve_desc"] = descriptions[cve_id]

    # Step 5: Apply IDS attack flag annotations
    for name in graph.nodes:
        if name in suricata_data:
            graph.nodes[name]["is_attacked"] = suricata_data[name]

    # Step 6: Add communication edges with weights, in both directions.
    #
    # comm_cycle()'s pairs describe legitimate telemetry direction (sensor
    # reports to controller, controller confirms back to sensor) — but attack
    # graphs model network reachability, not application-level data flow. A
    # compromised node can attempt outbound connections to anything it has a
    # network path to, regardless of which way "normal" traffic flows on that
    # link. Treating comms as directed-only made every entry point a dead end
    # (HMI_Interface/Backup_HMI_Interface only ever appear as a destination in
    # comm_cycle(), so no path to any target could ever be found — see the
    # attack-path-analysis spec revision notes). Adding the reverse edge for
    # each pair fixes that while still charging Dijkstra by the traversed
    # node's own risk_score in each direction.
    for src, dst, _msg in comms:
        if not graph.has_node(src):
            graph.add_node(src, zone="OT", criticality=0.5, vendor="",
                           product="", risk_score=0.0, is_attacked=0)
        if not graph.has_node(dst):
            graph.add_node(dst, zone="OT", criticality=0.5, vendor="",
                           product="", risk_score=0.0, is_attacked=0)
        src_risk = graph.nodes[src]["risk_score"]
        dst_risk = graph.nodes[dst]["risk_score"]
        graph.add_edge(src, dst, weight=1.0 / max(src_risk, 0.01))
        graph.add_edge(dst, src, weight=1.0 / max(dst_risk, 0.01))

    return graph


def extract_node_annotations(graph: nx.DiGraph) -> dict:
    """Return every graph node's annotation fields keyed by device name.

    This is the data build_graph() already computed (zone, criticality,
    vendor, product, risk_score, is_attacked, top CVE detail) — captured here
    so it can be persisted alongside the path records instead of being
    discarded once the graph goes out of scope.

    Args:
        graph: The annotated DiGraph produced by build_graph().

    Returns:
        dict mapping device name (str) to a dict with keys: zone,
        criticality, vendor, product, risk_score, is_attacked, top_cve_id,
        top_cve_cvss, top_cve_tier, top_cve_desc. The top_cve_* fields
        identify *which* vulnerability produced that node's risk_score —
        answering "what would an attacker actually exploit here" rather than
        just showing an unexplained number — and are None when the device
        has no CVE data.
    """
    nodes = {}
    for name, attrs in graph.nodes(data=True):
        nodes[name] = {
            "zone":         attrs.get("zone", "OT"),
            "criticality":  attrs.get("criticality", 0.5),
            "vendor":       attrs.get("vendor", ""),
            "product":      attrs.get("product", ""),
            "risk_score":   attrs.get("risk_score", 0.0),
            "is_attacked":  attrs.get("is_attacked", 0),
            "top_cve_id":   attrs.get("top_cve_id"),
            "top_cve_cvss": attrs.get("top_cve_cvss"),
            "top_cve_tier": attrs.get("top_cve_tier"),
            "top_cve_desc": attrs.get("top_cve_desc"),
        }
    return nodes


# ── Path computation ─────────────────────────────────────────────────────────

def _path_record(
    graph: nx.DiGraph,
    entry: str,
    target: str,
    path: list,
    cost: float,
) -> dict:
    """Build a single path record dict from Dijkstra output.

    Args:
        graph: The annotated DiGraph (used to extract max_risk_on_path).
        entry: Name of the entry-point device.
        target: Name of the target device.
        path: Ordered list of device names from entry to target.
        cost: Dijkstra path cost (sum of edge weights).

    Returns:
        dict with keys: entry, target, path, hops, cost, max_risk_on_path.
    """
    max_risk = max(graph.nodes[n]["risk_score"] for n in path)
    return {
        "entry":            entry,
        "target":           target,
        "path":             path,
        "hops":             len(path) - 1,
        "cost":             round(cost, 4),
        "max_risk_on_path": round(max_risk, 1),
    }


def compute_paths(graph: nx.DiGraph) -> list:
    """Run Dijkstra for all entry→target pairs and return sorted path records.

    Attempts every combination of ENTRY_POINTS × TARGETS (9 with the current
    3x3 sets). Pairs where no path exists or whose nodes are absent from the
    graph are skipped and logged.
    The resulting list is sorted ascending by cost; tiebreaker is max_risk_on_path
    descending (highest risk surfaces first on equal cost).

    Args:
        graph: Annotated DiGraph produced by build_graph().

    Returns:
        list[dict]: Sorted path records, each with keys:
            entry, target, path, hops, cost, max_risk_on_path.
    """
    records = []

    for entry in ENTRY_POINTS:
        if not graph.has_node(entry):
            log_event(f"attack_path: entry node '{entry}' not in graph — skipped")
            continue
        for target in TARGETS:
            if not graph.has_node(target):
                log_event(f"attack_path: target node '{target}' not in graph — skipped")
                continue
            try:
                path = nx.dijkstra_path(graph, entry, target, weight="weight")
                cost = nx.dijkstra_path_length(graph, entry, target, weight="weight")
                records.append(_path_record(graph, entry, target, path, cost))
            except nx.NetworkXNoPath:
                log_event(f"attack_path: no path from '{entry}' to '{target}' — omitted")
            except nx.NodeNotFound as e:
                log_event(f"attack_path: node not found during path computation: {e}")

    # Sort: cost ascending; tiebreaker: max_risk_on_path descending
    records.sort(key=lambda r: (r["cost"], -r["max_risk_on_path"]))
    return records


# ── Output ───────────────────────────────────────────────────────────────────

def write_json(paths: list, out_path: str, nodes: dict = None) -> None:
    """Serialise attack path results to attack_paths.json.

    Writes a JSON object with keys: generated_at, total_paths, paths, nodes.
    Filesystem errors (OSError, IOError) are caught and logged without
    propagating; all other exceptions propagate normally.

    Args:
        paths: List of path record dicts produced by compute_paths().
        out_path: Absolute file path where the JSON file will be written.
        nodes: Optional dict of per-device annotations produced by
            extract_node_annotations(), keyed by device name. Defaults to
            an empty dict so existing callers/tests remain valid.
    """
    payload = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "total_paths":  len(paths),
        "paths":        paths,
        "nodes":        nodes if nodes is not None else {},
    }
    try:
        with open(out_path, "w") as f:
            json.dump(payload, f, indent=2)
        log_event(f"attack_path: wrote {len(paths)} paths to {os.path.basename(out_path)}")
    except (OSError, IOError) as e:
        log_event(f"attack_path: failed to write {out_path}: {e}")


# ── Public entry point ───────────────────────────────────────────────────────

def run_attack_path_analysis() -> None:
    """Run the full attack path analysis pipeline as the final discovery step.

    Reads the three enrichment JSON sources from CAVE_DIR, builds the annotated
    directed graph, computes Dijkstra paths for all entry→target pairs, and
    writes attack_paths.json to CAVE_DIR before syncing it to the shared folder.
    PostgreSQL ingestion happens on the host side (Database/sync_db.py reads
    this same JSON file) — see the module docstring for why.

    Called by cave_monitor.run_discovery() after _score_and_display() completes.
    Any unhandled exception will propagate to the caller's try/except guard in
    run_discovery() and will be caught there without interrupting the monitor loop.
    """
    assets_path   = os.path.join(CAVE_DIR, "assets.json")
    risk_path     = os.path.join(CAVE_DIR, "risk_scored_results.json")
    suricata_path = os.path.join(CAVE_DIR, "suricata_context.json")
    out_path      = os.path.join(CAVE_DIR, "attack_paths.json")

    log_event("attack_path: building attack graph...")
    graph = build_graph(TOPOLOGY_EDGES, assets_path, risk_path, suricata_path)

    log_event(f"attack_path: graph built — {graph.number_of_nodes()} nodes, "
              f"{graph.number_of_edges()} edges")

    paths = compute_paths(graph)
    log_event(f"attack_path: computed {len(paths)} paths")

    nodes = extract_node_annotations(graph)

    write_json(paths, out_path, nodes)
    sync_to_shared("attack_paths.json")

    log_event("attack_path: analysis complete")
