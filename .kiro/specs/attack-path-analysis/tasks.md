# Implementation Plan: Attack Path Analysis

## Overview

Implement the Attack Path Analysis module for CAVE-OT as a single Python file (`attack_path.py`) that builds a risk-weighted directed graph from the existing communication topology, computes Dijkstra attack paths, persists results to JSON and PostgreSQL, and visualises them on the Flask dashboard via a D3.js force-directed graph and ranked table.

The implementation follows the order: database schema → core module → pipeline integration → Flask API → HTML template → nav update → tests.

---

## Tasks

- [x] 1. Add `attack_paths` table DDL to `Database/db_schema.sql`
  - [x] 1.1 Append `CREATE TABLE IF NOT EXISTS attack_paths` DDL after the existing `alerts` table definition
    - Columns: `id SERIAL PRIMARY KEY`, `entry_asset VARCHAR(60) NOT NULL`, `target_asset VARCHAR(60) NOT NULL`, `hops INTEGER NOT NULL`, `cost FLOAT NOT NULL`, `max_risk_on_path FLOAT NOT NULL`, `path_json TEXT NOT NULL`, `computed_at TIMESTAMP DEFAULT NOW()`
    - Add `CONSTRAINT uq_attack_path UNIQUE (entry_asset, target_asset)`
    - Add `CREATE INDEX IF NOT EXISTS idx_ap_cost ON attack_paths (cost ASC)`
    - _Requirements: 5.1, 5.4_

- [x] 2. Create `attack_path.py` in the shared folder / `CAVE_DIR` — loaders and graph construction
  - [x] 2.1 Scaffold the module: imports, constants, and `_get_db_conn()`
    - Import `os`, `json`, `datetime`, `networkx as nx`, `psycopg2`; import `CAVE_DIR`, `DEVICES`, `log_event`, `sync_to_shared` from `cave_monitor` (guard with `try/except ImportError` for test isolation)
    - Define `ENTRY_POINTS` = `["HMI_Interface", "Backup_HMI_Interface", "SCADA_Server"]` and `TARGETS` = `["Filtration_PLC", "Dosing_Pump_PLC", "UV_Disinfection_PLC"]` — `Engineering_WS` was removed post-review (2026-07-17): it is not one of the 15 devices in `DEVICES`, so it never matched a graph node and silently dropped 3 of 12 combinations without ever failing loudly
    - Implement `_get_db_conn()` returning a `psycopg2` connection using the same `DB_CONFIG` dict as `cave_monitor`
    - _Requirements: 1.1, 5.1_

  - [x] 2.2 Implement `_load_asset_annotations(path: str) -> dict[str, dict]`
    - Open `path`, parse JSON list; build dict keyed on `device_type` with values `{zone, criticality, vendor, product}`
    - Wrap in `try/except`; on failure call `log_event()` with warning and return `{}`
    - _Requirements: 1.3, 8.1_

  - [x] 2.3 Implement `_load_risk_annotations(path: str) -> dict[str, float]`
    - Parse `risk_scored_results.json`; for each device compute `max(cve["risk_score"] for cve in entry["cves"])` → 0.0 if no CVEs, 0.1 if all scores are zero
    - Wrap in `try/except`; on failure call `log_event()` and return `{}`
    - _Requirements: 1.4, 8.3_

  - [x] 2.4 Implement `_load_suricata_annotations(path: str) -> dict[str, int]`
    - Parse `suricata_context.json`; build dict `{device_type: is_attacked}` (integer 0 or 1)
    - Wrap in `try/except`; on failure call `log_event()` and return `{}`
    - _Requirements: 1.5, 8.2_

  - [x] 2.5 Implement `build_graph(comms, assets_path, risk_path, suricata_path) -> nx.DiGraph`
    - Initialise all 15 nodes from `DEVICES` with zero-filled default attributes `{zone, criticality, vendor, product, risk_score: 0.0, is_attacked: 0}`
    - Apply annotations in order: assets → risk → suricata (later layers overwrite earlier ones)
    - Add directed edges from `comms` list; set each edge `weight = 1.0 / max(src_node["risk_score"], 0.01)`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6_

  - [x]* 2.6 Write property test for `build_graph` — Property 1: edge weight inversely encodes risk
    - **Property 1: Edge weight inversely encodes risk with zero-division guard**
    - **Validates: Requirements 1.6, 8.3**
    - In `tests/test_attack_path_props.py`, use `@given(st.floats(min_value=0.0, max_value=10.0, allow_nan=False))` to verify `weight == 1.0 / max(risk_score, 0.01)` and that higher risk_score produces strictly lower weight

  - [x]* 2.7 Write property test for `build_graph` — Property 2: node annotation round-trip
    - **Property 2: Node annotation round-trip for all enrichment sources**
    - **Validates: Requirements 1.3, 1.4, 1.5**
    - Generate synthetic device lists with random `risk_score` values; verify `graph.nodes[d]["risk_score"]` equals `max(cve risk scores)`, with 0.0/0.1 fallback rules applied correctly

  - [ ]* 2.8 Write property test for `build_graph` — Property 6: graceful degradation on missing files
    - **Property 6: Graceful degradation defaults when input files are absent**
    - **Validates: Requirements 8.1, 8.2, 8.3, 8.5**
    - Call `build_graph` with nonexistent paths; verify no exception raised, all nodes have `is_attacked=0` and `risk_score=0.0`, all edge weights equal 100.0 when risk file absent

- [x] 3. Implement `compute_paths`, `_path_record`, and sorting logic in `attack_path.py`
  - [x] 3.1 Implement `_path_record(graph, entry, target, path, cost) -> dict`
    - Build and return `{entry, target, path, hops: len(path)-1, cost: round(cost, 4), max_risk_on_path: round(max(graph.nodes[n]["risk_score"] for n in path), 1)}`
    - _Requirements: 2.3_

  - [x] 3.2 Implement `compute_paths(graph) -> list[dict]`
    - Iterate all 12 `(entry, target)` pairs; check `graph.has_node()` for both — skip + log if missing (Req 8.4)
    - Call `nx.dijkstra_path()` and `nx.dijkstra_path_length()`; catch `nx.NetworkXNoPath` — skip + log (Req 2.2)
    - Collect `_path_record()` results; sort ascending by `cost`, with `max_risk_on_path` descending as tiebreaker (Req 2.4, 2.5)
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 8.4_

  - [x]* 3.3 Write property test for `compute_paths` — Property 3: Dijkstra cost equals sum of edge weights
    - **Property 3: Dijkstra cost equals sum of edge weights on path**
    - **Validates: Requirements 2.3**
    - For any computed path record, verify `cost == round(sum(graph[path[i]][path[i+1]]["weight"] for i in range(len(path)-1)), 4)` and `hops == len(path) - 1`

  - [x]* 3.4 Write property test for `compute_paths` — Property 4: output list sorted by cost ascending with tiebreaker
    - **Property 4: Output list is sorted by cost ascending with tiebreaker**
    - **Validates: Requirements 2.4, 2.5**
    - For any list of path records, after sorting verify `paths[i]["cost"] <= paths[i+1]["cost"]`; when costs are equal verify `paths[i]["max_risk_on_path"] >= paths[i+1]["max_risk_on_path"]`

- [x] 4. Implement `write_json` and `upsert_db` in `attack_path.py`
  - [x] 4.1 Implement `write_json(paths: list[dict], out_path: str) -> None`
    - Serialise `{"generated_at": ISO-8601 string, "total_paths": len(paths), "paths": paths}` to `out_path`
    - Catch `OSError`/`IOError` specifically → log via `log_event()` and return; let other exceptions propagate
    - _Requirements: 3.1, 3.3, 3.4, 3.5, 3.6_

  - [x]* 4.2 Write property test for `write_json` — Property 5: JSON serialisation round-trip
    - **Property 5: JSON serialisation round-trip preserves all path record fields**
    - **Validates: Requirements 3.3, 3.4, 3.5**
    - Generate arbitrary lists of path records (0–12); write and re-read; assert `total_paths == len(paths)`, `generated_at` is parseable ISO-8601, and all records match originals (accounting for float rounding)

  - [x] 4.3 Implement `upsert_db(paths: list[dict]) -> None`
    - Connect via `_get_db_conn()`; for each path run the `INSERT … ON CONFLICT (entry_asset, target_asset) DO UPDATE SET …` upsert with `path_json = json.dumps(record["path"])`
    - Wrap entire function in `try/except Exception`; on failure log via `log_event()` and return without raising
    - _Requirements: 5.2, 5.3_

  - [x]* 4.4 Write property test for `upsert_db` — Property 7: upsert idempotency
    - **Property 7: Upsert idempotency — row count equals unique entry→target pairs**
    - **Validates: Requirements 5.2**
    - Use a real or in-memory test DB; call `upsert_db()` twice with the same records; assert row count == `len(records)` and values reflect the second call

- [x] 5. Implement `run_attack_path_analysis()` public entry point in `attack_path.py`
  - [x] 5.1 Implement `run_attack_path_analysis() -> None`
    - Resolve file paths relative to `CAVE_DIR`: `assets_path`, `risk_path`, `suricata_path`, `out_path`
    - Call `build_graph(comms, assets_path, risk_path, suricata_path)` where `comms` is the same list as in `cave_monitor.comm_cycle()`; then `compute_paths(graph)`; then `write_json(paths, out_path)`; then `sync_to_shared("attack_paths.json")`; then `upsert_db(paths)`
    - Log start and completion via `log_event()`
    - _Requirements: 3.2, 4.1_

- [x] 6. Checkpoint — Verify core module
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 7. Integrate Attack Path Analysis into `cave_monitor.py` `run_discovery()`
  - [x] 7.1 Add the guarded call at the end of `run_discovery()`, after `_score_and_display()` completes
    - Check `os.path.exists(risk_path)` where `risk_path = os.path.join(CAVE_DIR, "risk_scored_results.json")`; if missing call `log_event("Attack path skipped — risk_scored_results.json missing", Y)` and skip
    - Wrap the `from attack_path import run_attack_path_analysis; run_attack_path_analysis()` call in `try/except Exception as e: log_event(f"Attack path error: {e}", R)`
    - _Requirements: 4.1, 4.2, 4.3_

- [x] 8. Add Flask API routes to `Dashboard/app.py`
  - [x] 8.1 Add the `GET /api/attack_paths` JSON endpoint
    - Query `SELECT * FROM attack_paths ORDER BY cost ASC`; convert `computed_at` datetime to string; return `jsonify(rows)`
    - On empty table return `jsonify([])` with status 200; on any exception return `jsonify({"error": str(e)})` with status 500
    - _Requirements: 6.1, 6.2, 6.3, 6.4_

  - [x] 8.2 Add the `GET /attack_paths` page route
    - Return `render_template("attack_paths.html")`
    - _Requirements: 6.5_

  - [x]* 8.3 Write property test for `/api/attack_paths` — Property 8: API response preserves and sorts all stored records
    - **Property 8: API response preserves and sorts all stored path records**
    - **Validates: Requirements 6.1, 6.4**
    - Use Flask test client; seed DB with arbitrary rows; assert every row appears in response, all required fields present, response ordered by cost ascending

- [x] 9. Create `Dashboard/templates/attack_paths.html`
  - [x] 9.1 Create the template extending `base.html` with stat cards row
    - `{% extends "base.html" %}` with `{% block title %}Attack Paths{% endblock %}` and `{% block page_heading %}ATTACK PATHS{% endblock %}`
    - Three stat cards: Total Paths (cyan), Highest-Risk Entry (red), Highest-Risk Target (orange) — populated via `/api/attack_paths` on `DOMContentLoaded`
    - _Requirements: 7.1, 7.7_

  - [x] 9.2 Add D3.js v7 force-directed graph SVG (800×500 px)
    - Load D3 v7 from CDN (`https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js`)
    - Build nodes/links from API data; colour by role: Entry_Point = `#00d4ff` (blue), Target = `#ff3355` (red), intermediate OT = `#ff8c00` (orange), intermediate IT = `#5a8a9f` (grey)
    - Scale node radius: `r = 8 + (risk_score / 10) * 16` (range 8–24 px)
    - Add CSS `@keyframes pulse` animation on nodes where `is_attacked == 1` (pulsing border or drop-shadow)
    - Add directed arrowhead markers via `<defs>` `<marker>` SVG element
    - _Requirements: 7.1, 7.2, 7.3_

  - [x] 9.3 Add hover tooltips and fallback detail panel to the D3 graph
    - On `mouseover` show a `<div>` tooltip with: device name, zone, criticality, risk_score, is_attacked status
    - Add a static `#detail-panel` below the SVG that mirrors the same info when tooltip cannot render (e.g., empty state default text when no node selected)
    - _Requirements: 7.4_

  - [x] 9.4 Add ranked path table below the graph
    - Columns: Rank, Entry Point, Path (arrow-separated `→`), Target, Hops, Cost, Max Risk
    - Apply Bootstrap `table-danger` class to the row with the lowest cost (index 0 of sorted API response)
    - Display `<tr><td colspan="7">No attack paths computed yet.</td></tr>` when API returns empty array
    - _Requirements: 7.5, 7.6_

- [x] 10. Add "Attack Paths" nav link to `Dashboard/templates/base.html`
  - [x] 10.1 Insert new `<a>` nav-link entry in the sidebar `MONITORING` section of `base.html`
    - Add after the existing "Policy Compliance" link: `<a href="/attack_paths" class="nav-link {% if request.path == '/attack_paths' %}active{% endif %}"><i class="bi bi-diagram-3-fill"></i><span>Attack Paths</span></a>`
    - _Requirements: 7.7_

- [x] 11. Write unit tests in `tests/test_attack_path.py`
  - [x] 11.1 Implement the 10 example-based unit tests
    - `test_build_graph_node_count` — graph has exactly 15 nodes (_Requirements: 1.1_)
    - `test_build_graph_edge_count` — graph has exactly 12 directed edges (_Requirements: 1.2_)
    - `test_edge_weight_formula` — spot-check `weight == 1.0 / max(risk_score, 0.01)` for a node with known risk_score (_Requirements: 1.6_)
    - `test_zero_risk_no_division_error` — `build_graph` completes without exception when all risk_scores are 0.0 (_Requirements: 1.6, 8.3_)
    - `test_no_path_omitted` — unreachable entry→target pair absent from `compute_paths` output (_Requirements: 2.2_)
    - `test_output_sorted` — `paths[0]["cost"] <= paths[-1]["cost"]` on real graph data (_Requirements: 2.4_)
    - `test_json_schema` — `attack_paths.json` written by `write_json` contains keys `"paths"`, `"generated_at"`, `"total_paths"` (_Requirements: 3.3, 3.4, 3.5_)
    - `test_missing_assets_json_fallback` — `build_graph` completes without raising when `assets_path` does not exist (_Requirements: 8.1_)
    - `test_missing_risk_json_fallback` — all edge weights are `1.0` when `risk_path` does not exist (_Requirements: 8.3_)
    - `test_db_unavailable_no_crash` — `upsert_db()` returns without raising when psycopg2 connection fails (_Requirements: 5.3_)
    - _Requirements: 1.1, 1.2, 1.6, 2.2, 2.4, 3.3, 3.4, 3.5, 5.3, 8.1, 8.3_

- [x] 12. Write property-based tests in `tests/test_attack_path_props.py`
  - [x] 12.1 Implement all 6 Hypothesis property tests (100 examples each)
    - Each test tagged with `# Feature: attack-path-analysis, Property N: <title>` comment above the `@given` decorator
    - Properties covered: 1 (edge weight formula), 2 (node annotation round-trip), 3 (Dijkstra cost == sum of edge weights), 4 (sorted output with tiebreaker), 5 (JSON round-trip), 6 (zero risk no division error)
    - Use `@settings(max_examples=100)` on each test
    - _Requirements: 1.3, 1.4, 1.5, 1.6, 2.3, 2.4, 2.5, 3.3, 3.4, 3.5, 8.1, 8.2, 8.3, 8.5_

- [ ] 13. Write integration tests in `tests/test_attack_path_integration.py`
  - [x] 13.1 Implement end-to-end and API integration tests
    - `test_full_pipeline_produces_json` — call `run_attack_path_analysis()` against real files in `Assets/`; verify `attack_paths.json` is written, parseable, and contains `"paths"` list (_Requirements: 3.1, 3.3, 4.1_)
    - `test_api_endpoint` — use Flask `app.test_client()` to GET `/api/attack_paths`; assert status 200 and response is a JSON array (_Requirements: 6.1, 6.2_)
    - `test_db_upsert_idempotent` — call `upsert_db()` twice with the same 3 records; assert row count in `attack_paths` table remains 3 (_Requirements: 5.2_)
    - _Requirements: 3.1, 4.1, 5.2, 6.1, 6.2_

- [ ] 14. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

---

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP
- The property tests in tasks 2.6–2.8, 3.3–3.4, 4.2, 4.4, and 8.3 correspond directly to Properties 1–8 in the design's "Correctness Properties" section
- `attack_path.py` is placed in `CAVE_DIR` on the Ubuntu VM (`/home/caveot/cave_ot_test`); for local development/testing it can be imported directly from the project root with the `cave_monitor` import guarded
- (Superseded 2026-07-17) `Engineering_WS` was removed from `ENTRY_POINTS` rather than relying on the `graph.has_node()` fallback to hide it — a device permanently absent from every run isn't a degraded-mode scenario (Requirement 8.4 is for missing/unreachable devices at runtime), it was a spec error. `test_entry_points_and_targets_exist_in_devices` guards against this recurring.
- `attack_paths.json` now also carries a `nodes` object (Requirement 3.7) and there is a companion `attack_path_nodes` DB table + `/api/attack_path_nodes` endpoint (Requirements 5.5–5.7, 6.6) so the dashboard tooltip/pulse (Requirement 7.2–7.4) reflects real per-device data instead of JS-side heuristics
- (Superseded 2026-07-17) `build_graph()` now adds the reverse edge for every comms pair, not just the forward one. Running the module against the real `Assets/` data after the `Engineering_WS` fix revealed `compute_paths()` still returned zero paths — `HMI_Interface`/`Backup_HMI_Interface` are pure sinks in `comm_cycle()` and `SCADA_Server`'s only out-edges lead to those sinks, so no entry point could structurally reach any target through directed-only edges. This wasn't caught earlier because every existing test either built a synthetic graph or extended `COMMS` with invented edges — none exercised the real topology end-to-end. `test_real_topology_produces_at_least_one_path` now guards this.
- D3.js v7 is loaded from CDN; if offline, the CDN script tag should be replaced with a local static asset copy
- The `db_schema.sql` change uses `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS` so it is safe to re-run on an existing database
- (Superseded 2026-07-17) `upsert_db()`/`upsert_nodes_db()`/`_get_db_conn()` removed from `attack_path.py` entirely. Wiring the attack-path hook into the VM's live `cave_monitor.py` and actually running it surfaced two problems the earlier isolated (host-only) testing never would: (1) the VM needed `networkx`/`psycopg2` installed separately (PEP 668 externally-managed-environment on modern Ubuntu — `apt install python3-networkx python3-psycopg2`, not pip), and (2) even once psycopg2 was available, `DB_CONFIG["host"]="localhost"` resolves to the VM's own loopback, not the Windows host running Postgres, so every DB upsert from the VM silently failed. Rather than opening Postgres to the VM's subnet (rejected — see Requirement 5 revision note), attack-path ingestion now goes through `Database/sync_db.py` on the host, the same path every other pipeline JSON output already uses via `file_watcher.py`. Verified against the live VM run: `attack_paths.json` landed correctly, `sync_db.py` picked it up, and both `attack_paths`/`attack_path_nodes` tables updated with a fresh timestamp.
- (Superseded 2026-07-17) Diffing the VM's actual live `cave_monitor.py` against the repo's copy (prompted by "why does the attack-path graph only show 7 of 15 nodes") found the repo's `DEVICES` had `DMZ_Gateway` where the VM — and `sync_db.py`/`smart_discover.py` — already used `Engineering_WS`. Fixed the repo to match. This also exposed that `attack_path.py`'s own comms replica (separately hand-copied in the file and in the test suite) was stale relative to the VM's real 16-edge `comm_cycle()`, silently modelling `Historian`/`Engineering_WS` as isolated even after the device-roster fix. Extracted a single `TOPOLOGY_EDGES` module constant that both the pipeline and the tests import, so there's exactly one copy left to go stale instead of three. Also expanded `ENTRY_POINTS` (+`Engineering_WS`, now legitimate) and `TARGETS` (+`Booster_Pump_PLC`, +`Reservoir_Level_PLC` — both reachable and high-criticality but never previously queried as a Dijkstra destination), and changed `attack_paths.html` to render the full static topology (client-side `GRAPH_EDGES`, mirroring `TOPOLOGY_EDGES`) with computed-path edges highlighted, instead of only drawing nodes that happened to land on a path. Net result on the live dataset: 16 paths (was 6), 15 nodes always visible in the graph (was 7, and only when they happened to be on a path). **Caveat verified empirically**: because `attack_path` is imported successfully by the VM's `cave_monitor.py` process (unlike the earlier `networkx` ImportError, which evicted the module from `sys.modules` and forced a fresh reimport on the next cycle), overwriting `attack_path.py` on disk while `cave_monitor.py` keeps running does **not** pick up code changes — confirmed by watching two full cycles land with the old 6-path output after the file was already replaced. A `cave_monitor.py` restart is required for `attack_path.py` changes to take effect once the module has successfully imported at least once.

---

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["2.1"] },
    { "id": 2, "tasks": ["2.2", "2.3", "2.4"] },
    { "id": 3, "tasks": ["2.5"] },
    { "id": 4, "tasks": ["2.6", "2.7", "2.8", "3.1"] },
    { "id": 5, "tasks": ["3.2"] },
    { "id": 6, "tasks": ["3.3", "3.4", "4.1", "4.3"] },
    { "id": 7, "tasks": ["4.2", "4.4", "5.1"] },
    { "id": 8, "tasks": ["7.1", "8.1", "8.2", "9.1"] },
    { "id": 9, "tasks": ["8.3", "9.2", "10.1"] },
    { "id": 10, "tasks": ["9.3"] },
    { "id": 11, "tasks": ["9.4", "11.1"] },
    { "id": 12, "tasks": ["12.1", "13.1"] }
  ]
}
```
