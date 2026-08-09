# Design Document — Attack Path Analysis

## Overview

The Attack Path Analysis module extends CAVE-OT with automated lateral-movement modelling for the water-treatment plant's 15-device OT/ICS network. It builds a risk-weighted directed graph from the communication topology already defined in `cave_monitor.py`, computes the cheapest (highest-risk) Dijkstra paths from four internet-facing IT entry points to five high-criticality OT targets, persists the results, and visualises them on the Flask dashboard.

> **Revision note (entry points, 2026-07-17a):** the entry-point set originally included a fourth device, `Engineering_WS`, carried over from the FYP-2 roadmap proposal. It was removed because it is not one of the 15 simulated devices in `cave_monitor.py`'s `DEVICES`/`comm_cycle()` — it never appeared in the graph, so those 3 of 12 combinations silently produced nothing. `ENTRY_POINTS` is now a verified subset of `DEVICES` (see `test_entry_points_and_targets_exist_in_devices`).
>
> **Revision note (edge direction, 2026-07-17b):** even after fixing the entry-point set, running the module against the real `comm_cycle()` topology produced **zero** paths for all 9 remaining combinations. Tracing the directed edges showed `HMI_Interface`/`Backup_HMI_Interface` are pure sinks (only ever a destination in `comm_cycle()`) and `SCADA_Server`'s only two out-edges lead to those two sinks — so no entry point could structurally reach any target. `build_graph()` now adds the reverse edge for every comms pair, since attack graphs model network reachability rather than which direction telemetry happens to flow.
>
> **Revision note (device roster + full topology + more targets, 2026-07-17c):** after wiring the module into the *live* VM (not just host-side testing), diffing the VM's real `cave_monitor.py` against the repo's copy showed the repo had `DMZ_Gateway` where the VM (and every other file in the codebase — `sync_db.py`, `smart_discover.py`) already used `Engineering_WS`. Fixed the repo's `DEVICES` to match, which makes `Engineering_WS` a legitimate entry point again. Separately, `attack_path.py`'s own hardcoded comms replica (duplicated by hand in three places — see the Requirement 1.2 revision note) was still the old 12-edge version even after the VM fix, silently modelling `Historian`/`Engineering_WS` as fully isolated; extracted the replica to one module-level constant, `TOPOLOGY_EDGES` (16 edges → 26 directed after mirroring), imported by both `run_attack_path_analysis()` and the test suite. Also added `Booster_Pump_PLC`/`Reservoir_Level_PLC` to `TARGETS` — both were graph-connected and reachable but never queried as a Dijkstra destination. Net effect on the live dataset: 16 real paths (up from 6), 11 distinct nodes appearing on a path (up from 7) — and the dashboard graph now renders the full 15-node/26-edge topology regardless of which nodes land on a path, so even `Historian` (a dead-end that structurally can never be on a *shortest* path) is visible. See `test_build_graph_edge_count`, `test_real_topology_produces_at_least_one_path`.

The module is implemented as a single Python file, `attack_path.py`, that runs on the Ubuntu VM as the final step of `run_discovery()`. Its outputs are:

- `attack_paths.json` in `CAVE_DIR` / Shared_Folder — includes both the ranked `paths` list and a `nodes` object carrying the full per-device annotations (zone, criticality, vendor, product, risk_score, is_attacked) that `build_graph()` computes, so consumers aren't limited to path-level `max_risk_on_path`
- Rows upserted into the `attack_paths` and `attack_path_nodes` PostgreSQL tables
- `attack_paths.html` page served by the Flask dashboard on the Windows host, via `/api/attack_paths` and `/api/attack_path_nodes`

### Key Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Graph library | `networkx.DiGraph` | Native Dijkstra, well-tested, pip-installable on Ubuntu |
| Edge directionality | Both `(src, dst)` and `(dst, src)` per comms pair | Attack graphs model network reachability, not telemetry direction. A directed-only graph (mirroring `comm_cycle()` literally) made `HMI_Interface`/`Backup_HMI_Interface` pure sinks and left every Entry_Point unable to reach any Target — 0 of 9 pairs ever found a path. See revision note below and Requirement 2.6. |
| Edge-weight formula | `1.0 / max(risk_score, 0.01)` | Higher risk → cheaper edge → Dijkstra finds highest-risk path |
| Fallback for devices with CVEs but all-zero scores | `risk_score = 0.1` | Distinguishable from zero-CVE devices (score = 0.0) |
| Upsert key | `(entry_asset, target_asset)` | One canonical record per entry→target pair; refreshed on every cycle |
| Dashboard integration | Read from DB; fallback to JSON file | Decouples VM pipeline from Windows dashboard |

---

## Architecture

```mermaid
flowchart TD
    subgraph VM ["Ubuntu VM — cave_monitor.py"]
        A[comm_cycle comms list] -->|16 pairs, both directions| B[attack_path.py\nbuild_graph]
        C[assets.json] -->|zone, criticality, vendor, product| B
        D[risk_scored_results.json] -->|risk_score per device| B
        E[suricata_context.json] -->|is_attacked flag| B
        B --> F[annotated DiGraph\n15 nodes, 26 edges]
        F --> G[compute_paths\nDijkstra × 20 pairs]
        F --> K[extract_node_annotations]
        G --> H[attack_paths.json\npaths + nodes]
        K --> H
        H --> I[sync_to_shared]
        G --> J[upsert → PostgreSQL\nattack_paths table]
        K --> L[upsert → PostgreSQL\nattack_path_nodes table]
    end

    subgraph Shared ["Shared Folder / PostgreSQL"]
        I --> K[/mnt/hgfs/shared folder/\nattack_paths.json]
        J --> L[(cave_ot DB\nattack_paths table)]
    end

    subgraph Dashboard ["Windows Host — Flask Dashboard"]
        L -->|GET /api/attack_paths| M[attack_paths.html\nD3 force-directed graph\n+ ranked table]
        K -->|fallback if DB unreachable| M
    end
```

The module is intentionally stateless: it re-reads all three JSON data sources on every invocation and rebuilds the graph from scratch. This ensures results always reflect the latest CVE scoring and IDS alert data without requiring in-memory state across pipeline cycles.

---

## Components and Interfaces

### `attack_path.py` — Module Layout

```python
# ── Public entry point ───────────────────────────────────────────────────────
def run_attack_path_analysis() -> None
    """Called by cave_monitor.run_discovery() as the final pipeline step."""

# ── Graph construction ───────────────────────────────────────────────────────
def build_graph(
    comms: list[tuple[str, str, str]],
    assets_path: str,
    risk_path: str,
    suricata_path: str,
) -> nx.DiGraph
    """Build annotated DiGraph from comm pairs and three JSON sources."""

def _load_asset_annotations(path: str) -> dict[str, dict]
    """Return {device_type: {zone, criticality, vendor, product}} from assets.json."""

def _load_risk_annotations(path: str) -> dict[str, float]
    """Return {device_type: max_risk_score} from risk_scored_results.json."""

def _load_suricata_annotations(path: str) -> dict[str, int]
    """Return {device_type: is_attacked} from suricata_context.json."""

# ── Path computation ─────────────────────────────────────────────────────────
def compute_paths(graph: nx.DiGraph) -> list[dict]
    """Run Dijkstra for all 20 entry→target pairs (4 ENTRY_POINTS × 5 TARGETS);
    return sorted path records."""

def extract_node_annotations(graph: nx.DiGraph) -> dict[str, dict]
    """Return {device_name: {zone, criticality, vendor, product, risk_score,
    is_attacked}} for every graph node — persists the annotations build_graph()
    computed so they survive past the in-memory graph."""

def _path_record(
    graph: nx.DiGraph,
    entry: str,
    target: str,
    path: list[str],
    cost: float,
) -> dict
    """Build a single path record dict from Dijkstra output."""

# ── Output ───────────────────────────────────────────────────────────────────
def write_json(paths: list[dict], out_path: str, nodes: dict = None) -> None
    """Serialise results to attack_paths.json — no PostgreSQL calls here or
    anywhere else in this file. See the module docstring / Requirement 5
    revision note: DB ingestion moved to Database/sync_db.py on the host."""
```

### Integration Point in `cave_monitor.py`

`run_discovery()` is extended with a guarded call at the very end:

```python
# Step 4 (NEW): Attack path analysis
risk_path = os.path.join(CAVE_DIR, "risk_scored_results.json")
if not os.path.exists(risk_path):
    log_event("Attack path skipped — risk_scored_results.json missing", Y)
else:
    try:
        from attack_path import run_attack_path_analysis
        run_attack_path_analysis()
    except Exception as e:
        log_event(f"Attack path error: {e}", R)
```

### Flask API — `app.py` additions

Two routes are added to the existing `app.py`:

| Route | Method | Returns |
|---|---|---|
| `/api/attack_paths` | GET | JSON array of path records ordered by `cost` asc |
| `/attack_paths` | GET | Renders `attack_paths.html` template |

### `attack_paths.html` — Template Structure

```
attack_paths.html
├── extends base.html
├── Stat cards row (total paths, highest-risk entry, highest-risk target)
├── Force-directed graph (D3.js v7 SVG, 800×500 px)
│   ├── Node circles (colour by role, size by risk_score, pulse on is_attacked)
│   ├── Directed edges (arrowheads)
│   └── Hover tooltips
└── Ranked path table
    └── Columns: Rank, Entry, Path (arrows), Target, Hops, Cost, Max Risk
```

---

## Data Models

### Graph Node Attributes

Each node in the `networkx.DiGraph` carries:

```python
{
    "zone":        str,   # "OT" | "IT"
    "criticality": float, # 0.0 – 1.0, from assets.json
    "vendor":      str,
    "product":     str,
    "risk_score":  float, # max CVE risk score; 0.0 if no CVE data
    "is_attacked": int,   # 0 | 1, from suricata_context.json
}
```

Annotation pipeline (applied in order, with fallbacks):

1. **Base** — zero-filled defaults for all 15 device names in `DEVICES`
2. **assets.json** — overwrite `zone`, `criticality`, `vendor`, `product` matching on `device_type`
3. **risk_scored_results.json** — overwrite `risk_score` as `max(cve["risk_score"] for cve in entry["cves"])`, with 0.0 for no CVE data and 0.1 if all scores are zero
4. **suricata_context.json** — overwrite `is_attacked` matching on `device_type`

### Edge Attributes

```python
{
    "weight": float  # 1.0 / max(src_node["risk_score"], 0.01)
}
```

The weight is computed after all node annotations are complete, so the final `risk_score` (including the 0.1 floor for CVE-but-zero devices) is used.

### Path Record (in-memory and JSON)

```python
{
    "entry":            str,   # e.g. "HMI_Interface"
    "target":           str,   # e.g. "Filtration_PLC"
    "path":             list[str],  # ordered node names
    "hops":             int,
    "cost":             float, # rounded to 4 d.p.
    "max_risk_on_path": float, # rounded to 1 d.p.
}
```

### `attack_paths.json` Schema

```json
{
  "generated_at": "2025-07-14T12:00:00",
  "total_paths":  9,
  "paths": [
    {
      "entry":            "HMI_Interface",
      "target":           "Filtration_PLC",
      "path":             ["HMI_Interface", "SCADA_Server", "Filtration_PLC"],
      "hops":             2,
      "cost":             0.2000,
      "max_risk_on_path": 10.0
    }
  ],
  "nodes": {
    "HMI_Interface": {
      "zone": "IT", "criticality": 0.7, "vendor": "", "product": "",
      "risk_score": 2.1, "is_attacked": 0
    },
    "Filtration_PLC": {
      "zone": "OT", "criticality": 0.98, "vendor": "Schneider Electric",
      "product": "Modicon M340", "risk_score": 10.0, "is_attacked": 1
    }
  }
}
```

The `nodes` object covers every node in the graph (all 15 devices), not just the ones that appear in a computed path — it is the durable copy of the annotations `build_graph()` computes in memory (see Data Models → Graph Node Attributes above).

### PostgreSQL Table — `attack_paths`

```sql
CREATE TABLE IF NOT EXISTS attack_paths (
    id               SERIAL PRIMARY KEY,
    entry_asset      VARCHAR(60)  NOT NULL,
    target_asset     VARCHAR(60)  NOT NULL,
    hops             INTEGER      NOT NULL,
    cost             FLOAT        NOT NULL,
    max_risk_on_path FLOAT        NOT NULL,
    path_json        TEXT         NOT NULL,   -- JSON-serialised list of node names
    computed_at      TIMESTAMP    DEFAULT NOW(),
    CONSTRAINT uq_attack_path UNIQUE (entry_asset, target_asset)
);

CREATE INDEX IF NOT EXISTS idx_ap_cost ON attack_paths (cost ASC);
```

The upsert SQL pattern:

```sql
INSERT INTO attack_paths
    (entry_asset, target_asset, hops, cost, max_risk_on_path, path_json, computed_at)
VALUES (%s, %s, %s, %s, %s, %s, NOW())
ON CONFLICT (entry_asset, target_asset) DO UPDATE SET
    hops             = EXCLUDED.hops,
    cost             = EXCLUDED.cost,
    max_risk_on_path = EXCLUDED.max_risk_on_path,
    path_json        = EXCLUDED.path_json,
    computed_at      = NOW();
```

### PostgreSQL Table — `attack_path_nodes`

Companion table that persists the per-device annotations from `extract_node_annotations()` — one row per device, refreshed every discovery cycle. This is what makes Requirement 7.2–7.4 (attacked-node pulse, risk-scaled node size, accurate tooltip) reflect real data for every node instead of only the target of the top path.

```sql
CREATE TABLE IF NOT EXISTS attack_path_nodes (
    device_name  VARCHAR(60) PRIMARY KEY,
    zone         VARCHAR(10) NOT NULL,
    criticality  FLOAT       NOT NULL,
    vendor       VARCHAR(120) DEFAULT '',
    product      VARCHAR(120) DEFAULT '',
    risk_score   FLOAT       NOT NULL,
    is_attacked  INTEGER     NOT NULL,
    updated_at   TIMESTAMP   DEFAULT NOW()
);
```

Upserted on `device_name` (not composite — one row per device regardless of how many paths it appears on), served to the dashboard via `GET /api/attack_path_nodes` as `{device_name: {zone, criticality, vendor, product, risk_score, is_attacked, updated_at}}`.

---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Edge weight inversely encodes risk with zero-division guard

*For any* set of graph nodes with arbitrary `risk_score` values (including 0.0), every outbound edge weight SHALL equal `1.0 / max(source_node_risk_score, 0.01)`. Specifically, a strictly higher `risk_score` produces a strictly lower weight, and a `risk_score` of 0.0 produces a weight of exactly `100.0` rather than a `ZeroDivisionError`.

**Validates: Requirements 1.6, 8.3**

### Property 2: Node annotation round-trip for all enrichment sources

*For any* device present in any combination of the three enrichment files (`assets.json`, `risk_scored_results.json`, `suricata_context.json`), after `build_graph()` completes the node's `zone`, `criticality`, `vendor`, `product`, `risk_score`, and `is_attacked` attributes SHALL equal the values from those source files. For the `risk_score`, the value SHALL be the maximum `risk_score` across all CVEs for that device; devices with no CVE entries SHALL get `0.0`; devices with CVE entries but all zero scores SHALL get `0.1`.

**Validates: Requirements 1.3, 1.4, 1.5**

### Property 3: Dijkstra cost equals sum of edge weights on path

*For any* computed attack path record, the `cost` field SHALL equal the sum of the `weight` attributes of every directed edge traversed along the `path` node list (i.e., `sum(graph[path[i]][path[i+1]]["weight"] for i in range(len(path)-1))`), rounded to 4 decimal places, and `hops` SHALL equal `len(path) - 1`.

**Validates: Requirements 2.3**

### Property 4: Output list is sorted by cost ascending with tiebreaker

*For any* pair of consecutive records `paths[i]` and `paths[i+1]` in the computed output list, `paths[i]["cost"] <= paths[i+1]["cost"]` SHALL hold; when `paths[i]["cost"] == paths[i+1]["cost"]`, then `paths[i]["max_risk_on_path"] >= paths[i+1]["max_risk_on_path"]` SHALL hold.

**Validates: Requirements 2.4, 2.5**

### Property 5: JSON serialisation round-trip preserves all path record fields

*For any* list of N path records written to `attack_paths.json`, reading and parsing the file SHALL yield a JSON object where `total_paths == N`, `paths` is a list of N records with field values equal to the originals (accounting for float rounding), and a parseable ISO-8601 `generated_at` string is present.

**Validates: Requirements 3.3, 3.4, 3.5**

### Property 6: Graceful degradation defaults when input files are absent

*For any* graph constructed with one or more of the enrichment files missing, all nodes SHALL have `is_attacked = 0` when `suricata_context.json` is absent, all nodes SHALL have `risk_score = 0.0` and all edges SHALL have `weight = 1.0` when `risk_scored_results.json` is absent, and in all such degraded-mode scenarios `build_graph()` and `compute_paths()` SHALL complete without raising an exception and SHALL produce a well-formed (possibly empty) output structure.

**Validates: Requirements 8.1, 8.2, 8.3, 8.5**

### Property 7: Upsert idempotency — row count equals unique entry→target pairs

*For any* list of path records with unique `(entry, target)` pairs, calling `sync_attack_paths(cur)` (in `Database/sync_db.py`, not `attack_path.py` — see Requirement 5 revision note) any number of times with the same `attack_paths.json` contents SHALL result in exactly `len(records)` rows in the `attack_paths` table (not a multiple), and the latest values SHALL reflect the most recent call. Verified in `tests/test_sync_db_attack_paths.py::test_sync_attack_paths_idempotent`.

**Validates: Requirements 5.2**

### Property 8: API response preserves and sorts all stored path records

*For any* set of rows present in the `attack_paths` table, a GET request to `/api/attack_paths` SHALL return a JSON array where every row is represented, each record contains all required fields (`entry_asset`, `target_asset`, `hops`, `cost`, `max_risk_on_path`, `path_json`, `computed_at`), and the array is ordered by `cost` ascending.

**Validates: Requirements 6.1, 6.4**

---

## Error Handling

### File I/O Failures

All three JSON data sources (`assets.json`, `risk_scored_results.json`, `suricata_context.json`) are loaded with individual `try/except` blocks. The fallback behaviour per source:

| Missing source | Fallback |
|---|---|
| `assets.json` | Use static `DEVICES` dict for zone data; skip vendor/product; log warning |
| `risk_scored_results.json` | All `risk_score = 0.0`, all edge weights `= 1.0`; log warning |
| `suricata_context.json` | All `is_attacked = 0`; log warning |

Writing `attack_paths.json` catches `OSError` / `IOError` specifically, logs via `log_event()`, and returns without propagating — matching Requirement 3.6. Non-filesystem exceptions during write propagate normally.

### Database Failures

`attack_path.py` has no database code to fail — it only writes JSON. On the host side, `sync_attack_paths(cur)` runs inside `sync_db.py`'s existing connection/transaction; if `attack_paths.json` is missing it returns `(0, 0)` without issuing any DB calls (Requirement 5.3), and any DB error during the sync surfaces the same way a failure syncing assets/CVEs already would — it isn't given special-case swallowing, since by this point the JSON file already landed successfully and is the durable record regardless of what Postgres does with it.

### Missing Entry/Target Nodes

Before calling `nx.dijkstra_path()`, `compute_paths()` checks `graph.has_node(name)` for every entry and target device. Missing devices are skipped and logged — matching Requirement 8.4.

### No Path Exists

`nx.dijkstra_path()` raises `nx.NetworkXNoPath` when no route exists. This is caught per pair; the pair is omitted from output and a warning is logged — matching Requirement 2.2.

### Pipeline Guard in `run_discovery()`

The entire `run_attack_path_analysis()` call is wrapped in `try/except Exception` inside `cave_monitor.py`. Any unhandled exception from the module is caught, logged, and swallowed so the outer monitoring loop continues — matching Requirement 4.3.

---

## Testing Strategy

### Unit Tests (example-based)

Located in `tests/test_attack_path.py`. These cover specific behaviours and edge cases:

- `test_build_graph_node_count` — graph has exactly 15 nodes
- `test_build_graph_edge_count` — graph has both directions of every distinct comms pair (26 edges for the current 16-pair `TOPOLOGY_EDGES`, computed dynamically from `len(TOPOLOGY_EDGES)` rather than hardcoded, so this assertion can't silently go stale again)
- `test_real_topology_produces_at_least_one_path` — `compute_paths()` on the real `comm_cycle()` topology with the real `ENTRY_POINTS`/`TARGETS` finds at least one path (regression guard for the directed-only-graph defect)
- `test_edge_weight_formula` — spot-check weight = `1.0 / max(risk_score, 0.01)`
- `test_zero_risk_no_division_error` — graph builds when all risk_scores are 0.0
- `test_no_path_omitted` — unreachable pair is absent from output list
- `test_output_sorted` — `paths[0]["cost"] <= paths[-1]["cost"]`
- `test_json_schema` — `attack_paths.json` contains `"paths"`, `"generated_at"`, `"total_paths"`
- `test_missing_assets_json_fallback` — module completes without raising when assets.json absent
- `test_missing_risk_json_fallback` — all edge weights are 1.0 when risk file absent
- `test_real_topology_produces_at_least_one_path` — regression guard: `compute_paths()` on the real `comm_cycle()` topology with the real `ENTRY_POINTS`/`TARGETS` must find at least one path (this is the property that actually matters — every other test uses a synthetic or extended graph and would stay green even if the real topology were fully disconnected, which it was until `build_graph()` added reverse edges)
- `test_entry_points_and_targets_exist_in_devices` — regression guard: every name in `ENTRY_POINTS`/`TARGETS` must exist in `DEVICES`, so a dead entry point (e.g. the removed `Engineering_WS`) can't silently reappear
- `test_extract_node_annotations_covers_all_nodes` — `extract_node_annotations()` returns all 15 devices with the six expected fields
- `test_json_schema_includes_nodes` — `attack_paths.json` contains a `"nodes"` key alongside `"paths"`/`"generated_at"`/`"total_paths"`

DB-upsert tests (`test_db_unavailable_no_crash`, `test_upsert_nodes_db_no_crash`, `test_db_upsert_idempotent`) were removed along with `upsert_db()`/`upsert_nodes_db()` — see `tests/test_sync_db_attack_paths.py` below for their replacements, now testing `Database/sync_db.py` instead.

### Host-Side Ingestion Tests (`tests/test_sync_db_attack_paths.py`)

Four tests against `sync_attack_paths(cur)` in `Database/sync_db.py`, using a `MagicMock` cursor (no live DB needed, same pattern the old `upsert_db` tests used):

- `test_sync_attack_paths_missing_file_returns_zero` — no `attack_paths.json` → `(0, 0)`, zero `cur.execute()` calls
- `test_sync_attack_paths_upserts_all_records` — N paths + M nodes → exactly `1 + N + M` execute() calls (1 `CREATE TABLE`, then one upsert per record)
- `test_sync_attack_paths_idempotent` — calling twice with identical JSON doubles the call count but doesn't change `(paths_saved, nodes_saved)`
- `test_sync_attack_paths_upsert_params_correct` — the params passed to the first path upsert match the source JSON record field-for-field (catches schema drift between `attack_path.py`'s output and `sync_db.py`'s ingestion)

### Property-Based Tests (`hypothesis`)

Located in `tests/test_attack_path_props.py`. The `hypothesis` library is used with a minimum of 100 examples per property.

PBT is appropriate here because:
- `build_graph()` and `compute_paths()` are pure-function-style transformations with clear input/output behaviour
- The edge-weight formula, Dijkstra cost invariant, sort order, and serialisation round-trip all express universal properties over a wide input space
- The logic is in-process and cost-free to run 100+ times

Tag format used in comments: `# Feature: attack-path-analysis, Property {N}: {text}`

```python
# Feature: attack-path-analysis, Property 1: edge weight inversely encodes risk
@given(risk_score=st.floats(min_value=0.0, max_value=10.0, allow_nan=False))
@settings(max_examples=100)
def test_edge_weight_formula_property(risk_score):
    weight = 1.0 / max(risk_score, 0.01)
    assert weight == pytest.approx(1.0 / max(risk_score, 0.01))
    if risk_score > 0.01:
        assert weight < 1.0 / 0.01  # higher risk → strictly lower weight

# Feature: attack-path-analysis, Property 2: node annotation round-trip
@given(devices=st.lists(device_strategy(), min_size=1, max_size=15, unique_by=...))
@settings(max_examples=100)
def test_node_risk_annotation_round_trip(devices):
    graph = build_graph_from_synthetic(devices)
    for d in devices:
        expected = max(c["risk_score"] for c in d["cves"]) if d["cves"] else 0.0
        assert graph.nodes[d["device_type"]]["risk_score"] == expected

# Feature: attack-path-analysis, Property 3: Dijkstra cost equals sum of edge weights
@given(path_data=path_strategy())
@settings(max_examples=100)
def test_path_cost_equals_edge_weight_sum(path_data):
    graph, path, cost = path_data
    expected = sum(graph[path[i]][path[i+1]]["weight"] for i in range(len(path)-1))
    assert cost == pytest.approx(round(expected, 4), abs=1e-3)

# Feature: attack-path-analysis, Property 4: output list sorted by cost ascending
@given(paths=st.lists(path_record_strategy(), min_size=2, max_size=12))
@settings(max_examples=100)
def test_output_sorted_by_cost(paths):
    sorted_paths = sort_paths(paths)
    for i in range(len(sorted_paths) - 1):
        assert sorted_paths[i]["cost"] <= sorted_paths[i+1]["cost"]

# Feature: attack-path-analysis, Property 5: JSON round-trip preserves records
@given(paths=st.lists(path_record_strategy(), min_size=0, max_size=12))
@settings(max_examples=100)
def test_json_round_trip(paths, tmp_path):
    out = tmp_path / "attack_paths.json"
    write_json(paths, str(out))
    loaded = json.loads(out.read_text())["paths"]
    assert loaded == paths

# Feature: attack-path-analysis, Property 6: zero risk does not divide by zero
@given(n_zero=st.integers(min_value=1, max_value=15))
@settings(max_examples=100)
def test_zero_risk_nodes_no_division_error(n_zero):
    # Synthesise a graph where n_zero nodes have risk_score=0.0
    graph = build_graph_with_zero_risk(n_zero)
    for u, v, data in graph.edges(data=True):
        assert data["weight"] == pytest.approx(100.0)  # 1/0.01
```

### Integration Tests

A separate `tests/test_attack_path_integration.py` covers the full end-to-end pipeline with real JSON files from the `Assets/` directory:

- `test_full_pipeline_produces_json` — run `run_attack_path_analysis()` against real data files; verify `attack_paths.json` is written and parseable
- `test_api_endpoint` — Flask test client GET `/api/attack_paths` returns 200 and a JSON array
- `test_node_api_endpoint` — Flask test client GET `/api/attack_path_nodes` returns 200/500 with a JSON object

(DB-upsert idempotency now lives in `tests/test_sync_db_attack_paths.py`, against `sync_db.py` — see above.)

### Performance

The 15-node, 26-edge graph is trivially small. Dijkstra over 20 entry→target pairs completes in < 1 ms. `run_attack_path_analysis()` wall-clock time (file I/O only — no DB round-trip on the VM side anymore) should remain well under the 10-second budget (Requirement 4.4) even on the Ubuntu VM.
