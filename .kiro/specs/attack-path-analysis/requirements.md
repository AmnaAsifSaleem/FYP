# Requirements Document

## Introduction

The Attack Path Analysis module is a FYP-2 deliverable for CAVE-OT (Context-Aware Vulnerability Engine for OT/ICS Networks). The module extends the existing CAVE-OT pipeline by computing risk-weighted attack paths through the water-treatment plant's 15-device OT/ICS network.

Using the directed communication topology already defined in `cave_monitor.py`'s `comm_cycle()` as the attack graph, the module constructs a NetworkX directed graph, annotates each node with live threat context (zone, criticality, risk score, IDS attack flag), and runs Dijkstra's shortest-path algorithm from internet-facing IT entry points to the highest-criticality OT process-control targets. Results are written to `attack_paths.json`, persisted in a new PostgreSQL table, and visualised as an interactive force-directed graph on the CAVE-OT Flask dashboard.

---

## Glossary

- **Attack_Graph**: A directed graph whose nodes are CAVE-OT device names and whose edges correspond to the communication pairs in `comm_cycle()`'s `comms` list.
- **Attack_Path_Analyzer**: The Python module (`attack_path.py`) responsible for building the Attack_Graph, computing paths, and writing output files.
- **Attack_Path**: A sequence of device nodes from an Entry_Point to a Target, representing a potential lateral-movement route through the network.
- **Entry_Point**: An internet- or user-facing IT asset that a remote attacker could reach first. Defined as the fixed set: `{HMI_Interface, Backup_HMI_Interface, SCADA_Server, Engineering_WS}` — a strict subset of `DEVICES`. (Revision history: `Engineering_WS` was removed on 2026-07-17 because `DEVICES` at the time had `DMZ_Gateway` instead; it was added back the same day once `DEVICES` itself was corrected to use `Engineering_WS` — see the Requirement 1.1 revision note.)
- **Target**: A high-criticality OT process-control asset whose compromise has the greatest physical impact. Defined as the fixed set: `{Filtration_PLC (0.98), Dosing_Pump_PLC (0.97), UV_Disinfection_PLC (0.96), Booster_Pump_PLC (0.93), Reservoir_Level_PLC (0.91)}`. The last two were added 2026-07-17: both are graph-connected and reachable from every Entry_Point but were never queried as a Dijkstra destination under the original 3-target set, so they silently never appeared in output despite being among the highest-criticality OT assets.
- **Edge_Weight**: A per-edge cost computed as `1 / risk_score` of the source node, where `risk_score` is the highest CVE risk score for that device from `risk_scored_results.json`. A higher risk score on a device makes its outbound edges cheaper (easier to traverse). Devices with no CVE data use a fallback weight of `1.0`.
- **Path_Cost**: The sum of Edge_Weights along an Attack_Path, as returned by Dijkstra's algorithm. Lower cost = higher overall risk.
- **Max_Risk_On_Path**: The maximum `risk_score` value across all nodes in an Attack_Path, indicating the single highest-severity stepping stone.
- **Hops**: The number of directed edges (device-to-device transitions) in an Attack_Path.
- **CAVE_DIR**: `/home/caveot/cave_ot_test` — the directory on the Ubuntu VM where pipeline JSON files are written.
- **Shared_Folder**: `/mnt/hgfs/shared folder` — the VMware HGFS mount point used to transfer files between the VM and the Windows host running the dashboard.
- **DB_Table_attack_paths**: The PostgreSQL table `attack_paths` in the `cave_ot` database that stores computed path records.
- **Dashboard**: The Flask web application in `Dashboard/app.py` served at `http://localhost:5000`.
- **Force_Directed_Graph**: A browser-rendered SVG network diagram using D3.js (or equivalent) that visualises attack paths as node-link topology.

---

## Requirements

### Requirement 1: Attack Graph Construction

**User Story:** As a security analyst, I want the CAVE-OT engine to build a directed attack graph from the known device communication topology, so that I have a machine-readable model of all possible lateral-movement edges.

#### Acceptance Criteria

1. THE Attack_Path_Analyzer SHALL construct a `networkx.DiGraph` whose node set equals the 15 device names defined in `cave_monitor.py`'s `DEVICES` dictionary. Both `ENTRY_POINTS` and `TARGETS` SHALL be subsets of `DEVICES`; a name in either set that is not a key of `DEVICES` SHALL be treated as a specification defect.

   > **Revision note (2026-07-17):** the repo's `cave_monitor.py` `DEVICES` dict had `DMZ_Gateway` where every other file in the codebase (`Database/sync_db.py`, `smart_discover.py`'s `PORT_MAP`, and the VM's actual live `cave_monitor.py`) already used `Engineering_WS`. `DMZ_Gateway` was a one-off, referenced nowhere else. Swapped `DMZ_Gateway` → `Engineering_WS` (port 2222, matching every other definition exactly) so the repo's device roster matches the rest of the system instead of being the odd one out.

2. THE Attack_Path_Analyzer SHALL add a directed edge `(src, dst)` AND its reverse `(dst, src)` for every `(src, dst, msg)` tuple in `comm_cycle()`'s `comms` list. Attack-path modelling reflects network reachability, not application-level telemetry direction: a compromised node can attempt outbound connections along a link regardless of which direction "legitimate" traffic normally flows on it. (Directed-only edges were tried first and found to make every Entry_Point structurally unable to reach any Target — see Requirement 2.6.)

   > **Revision note (2026-07-17):** the comms list was previously duplicated by hand in three places — `cave_monitor.comm_cycle()`, a local list inside `attack_path.run_attack_path_analysis()`, and a fixture in `tests/test_attack_path.py` — and the two `attack_path.py`-side copies had drifted to a 12-edge topology missing the `Historian`/`Engineering_WS` edges the VM's real `comm_cycle()` has (16 edges: 12 process edges + `Historian<->SCADA_Server` + `Engineering_WS<->SCADA_Server`). Both devices were being modelled as fully isolated on every live VM run despite having real edges. Extracted the list to a single module-level constant, `attack_path.TOPOLOGY_EDGES`, that `run_attack_path_analysis()` and the test suite both import — eliminating the duplication that let this drift happen silently in the first place.
3. WHEN `assets.json` is loaded, THE Attack_Path_Analyzer SHALL annotate each graph node with the fields `zone`, `criticality`, `vendor`, and `product` sourced from the matching `device_type` entry in `assets.json`.
4. WHEN `risk_scored_results.json` is loaded, THE Attack_Path_Analyzer SHALL annotate each graph node with the field `risk_score` equal to the highest `risk_score` value among all CVEs for that device; IF a device has no CVE entries in `risk_scored_results.json`, THEN THE Attack_Path_Analyzer SHALL assign `risk_score = 0.0` to that node; IF a device has CVE entries but all computed risk scores are zero, THEN THE Attack_Path_Analyzer SHALL assign `risk_score = 0.1` to that node so that devices with vulnerabilities are distinguishable from devices with no vulnerability data.
5. WHEN `suricata_context.json` is loaded, THE Attack_Path_Analyzer SHALL annotate each graph node with the field `is_attacked` equal to the `is_attacked` integer value (0 or 1) for the matching `device_type` entry.
6. THE Attack_Path_Analyzer SHALL assign each directed edge an `weight` attribute equal to `1.0 / max(node_risk_score, 0.01)` for the source node of that edge, ensuring no division by zero.

---

### Requirement 2: Path Computation

**User Story:** As a security analyst, I want the engine to compute the cheapest (highest-risk) attack paths from every entry point to every target, so that the most dangerous lateral-movement routes are ranked and surfaced automatically.

#### Acceptance Criteria

1. THE Attack_Path_Analyzer SHALL attempt Dijkstra's shortest-path computation for every pair `(entry, target)` where `entry ∈ {HMI_Interface, Backup_HMI_Interface, SCADA_Server, Engineering_WS}` and `target ∈ {Filtration_PLC, Dosing_Pump_PLC, UV_Disinfection_PLC, Booster_Pump_PLC, Reservoir_Level_PLC}`, yielding up to 20 entry–target combinations (4 entries × 5 targets).
2. WHEN no path exists between an entry–target pair in the Attack_Graph, THE Attack_Path_Analyzer SHALL omit that pair from the output and SHALL log a warning message identifying the unreachable pair.
3. FOR each reachable entry–target pair, THE Attack_Path_Analyzer SHALL record the following fields: `entry` (device name string), `target` (device name string), `path` (ordered list of device name strings including entry and target), `hops` (integer count of edges), `cost` (float, sum of edge weights, rounded to 4 decimal places), and `max_risk_on_path` (float, maximum node risk_score along the path, rounded to 1 decimal place).
4. THE Attack_Path_Analyzer SHALL sort the output list of attack paths in ascending order of `cost` (lowest cost first, representing highest combined risk).
5. WHEN two or more paths share the same `cost`, THE Attack_Path_Analyzer SHALL use `max_risk_on_path` descending as the tiebreaker.
6. THE Attack_Path_Analyzer, when run against the live `comm_cycle()` topology and the real `ENTRY_POINTS`/`TARGETS` sets, SHALL find at least one path. (This is verified by `test_real_topology_produces_at_least_one_path()` and by the `total_paths > 0` assertion in the full-pipeline integration test — added after discovering that a directed-only graph made this 0 for every combination without any test catching it, since all other tests exercised synthetic or extended topologies.)

---

### Requirement 3: Output File Generation

**User Story:** As a developer, I want the computed attack paths written to a JSON file in the shared folder, so that other pipeline components and the dashboard can consume the results without a direct database dependency.

#### Acceptance Criteria

1. WHEN path computation completes, THE Attack_Path_Analyzer SHALL write a file named `attack_paths.json` to `CAVE_DIR`.
2. THE Attack_Path_Analyzer SHALL copy `attack_paths.json` to the Shared_Folder using the same `sync_to_shared()` pattern used for other pipeline outputs.
3. THE `attack_paths.json` file SHALL contain a JSON object with a top-level key `"paths"` whose value is the sorted list of attack-path records produced in Requirement 2.
4. THE `attack_paths.json` file SHALL contain a top-level key `"generated_at"` with an ISO-8601 timestamp string reflecting the time of computation.
5. THE `attack_paths.json` file SHALL contain a top-level key `"total_paths"` with an integer count of successfully computed paths.
6. IF writing `attack_paths.json` fails due to a filesystem error, THEN THE Attack_Path_Analyzer SHALL catch that specific filesystem error, log it using `log_event()`, and SHALL continue pipeline execution without raising an unhandled exception; all other exception types raised during the same file-write operation SHALL propagate normally.
7. THE `attack_paths.json` file SHALL contain a top-level key `"nodes"` whose value is an object mapping every device name in the Attack_Graph (all 15, not only those on a computed path) to its `zone`, `criticality`, `vendor`, `product`, `risk_score`, and `is_attacked` annotation values, so that Requirement 7's visualisation can render accurate per-node detail for nodes other than a path's target.

---

### Requirement 4: Pipeline Integration

**User Story:** As a system operator, I want attack path analysis to run automatically after every discovery cycle, so that the results always reflect the latest CVE risk scores and IDS alert data.

#### Acceptance Criteria

1. THE `cave_monitor.py` module SHALL invoke the Attack_Path_Analyzer as the final step of `run_discovery()`, executing after `_score_and_display()` completes successfully.
2. WHEN `risk_scored_results.json` does not exist at the time `run_discovery()` completes, THE `cave_monitor.py` module SHALL skip attack path analysis and SHALL log a warning via `log_event()`.
3. WHEN the Attack_Path_Analyzer raises an unhandled exception during pipeline execution, THE `cave_monitor.py` module SHALL catch the exception, log the error message via `log_event()`, and SHALL allow `run_discovery()` to return normally so the broader monitoring loop is not interrupted.
4. THE Attack_Path_Analyzer SHALL complete execution within 10 seconds on the 15-node, 12-edge graph for the nominal dataset, ensuring the pipeline cycle is not materially delayed.

---

### Requirement 5: Database Persistence

**User Story:** As a dashboard developer, I want attack path results stored in PostgreSQL, so that the dashboard can query historical path data and the data survives across pipeline restarts.

> **Revision note (2026-07-17):** this requirement originally had the Attack_Path_Analyzer (running on the VM) upsert directly into PostgreSQL via `psycopg2`, mirroring `upsert_db()`. Live VM testing showed this doesn't work: the VM's `DB_CONFIG["host"] = "localhost"` resolves to the VM's own loopback, not the Windows host running Postgres, so every upsert attempt silently failed (caught by its own try/except, non-fatal, but the DB was never actually populated from a live VM run). The architectural fix — matching how every other pipeline JSON output already reaches Postgres — is host-side ingestion: `file_watcher.py` watches for `attack_paths.json` the same way it already watches `assets.json`/`risk_scored_results.json`/etc., and `Database/sync_db.py` reads it and performs the upserts. `attack_path.py` itself now has zero PostgreSQL dependency. The alternative (open Postgres to network connections from the VM's subnet) was considered and rejected: it hands a compromised/adversarial VM — which is the literal subject this module analyzes — a credentialed network path to the real database, undermining the segmentation story the whole project is about.

#### Acceptance Criteria

1. THE `cave_ot` PostgreSQL database SHALL contain a table named `attack_paths` with at minimum the columns: `id` (serial primary key), `entry_asset` (VARCHAR), `target_asset` (VARCHAR), `hops` (INTEGER), `cost` (FLOAT), `max_risk_on_path` (FLOAT), `path_json` (TEXT storing the JSON-serialised path node list), and `computed_at` (TIMESTAMP DEFAULT NOW()).
2. WHEN `attack_paths.json` changes in the shared folder, THE host-side `file_watcher.py` SHALL trigger `Database/sync_db.py`, which SHALL upsert each path record into the `attack_paths` table via `sync_attack_paths(cur)`, matching on the composite key `(entry_asset, target_asset)`; existing records SHALL be updated with the latest values.
3. IF `attack_paths.json` does not exist yet (e.g. an older `cave_monitor.py` without the hook wired in) WHEN `sync_attack_paths(cur)` runs, THEN it SHALL return `(0, 0)` without raising and without issuing any DB calls, leaving the rest of `sync_db.py`'s sync unaffected.
4. THE `db_schema.sql` file SHALL be updated to include the `CREATE TABLE attack_paths` DDL so that the schema can be recreated from scratch; `sync_attack_paths(cur)` SHALL also issue `CREATE TABLE IF NOT EXISTS` itself so ingestion works even against a database that hasn't had `db_schema.sql` re-applied.
5. THE `cave_ot` PostgreSQL database SHALL contain a table named `attack_path_nodes` with at minimum the columns: `device_name` (VARCHAR primary key), `zone` (VARCHAR), `criticality` (FLOAT), `vendor` (VARCHAR), `product` (VARCHAR), `risk_score` (FLOAT), `is_attacked` (INTEGER), and `updated_at` (TIMESTAMP DEFAULT NOW()).
6. WHEN `attack_paths.json` changes, `sync_attack_paths(cur)` SHALL upsert one row per device into the `attack_path_nodes` table (from the JSON's `nodes` key), matching on `device_name`; existing rows SHALL be updated with the latest values.
7. THE `db_schema.sql` file SHALL be updated to include the `CREATE TABLE attack_path_nodes` DDL so that the schema can be recreated from scratch.
8. THE Attack_Path_Analyzer (`attack_path.py`, running on the VM) SHALL have no PostgreSQL dependency — no `import psycopg2`, no DB connection config, no upsert calls. Its only durable output is `attack_paths.json`.

---

### Requirement 6: Dashboard API

**User Story:** As a security analyst, I want a REST API endpoint that returns the computed attack paths as JSON, so that the dashboard front-end can fetch and render the results dynamically.

#### Acceptance Criteria

1. THE Dashboard SHALL expose a GET endpoint at `/api/attack_paths` that returns a JSON array of attack-path records ordered by `cost` ascending.
2. WHEN the `attack_paths` table exists but contains no rows, THE Dashboard SHALL return an empty JSON array `[]` with HTTP status 200; WHEN the database is unreachable or the `attack_paths` table does not exist, THE Dashboard SHALL return a JSON object `{"error": "<message>"}` with HTTP status 500.
3. WHEN the database query for `/api/attack_paths` raises an exception, THE Dashboard SHALL return a JSON object `{"error": "<message>"}` with HTTP status 500.
4. THE `/api/attack_paths` response for each record SHALL include the fields: `entry_asset`, `target_asset`, `hops`, `cost`, `max_risk_on_path`, `path_json`, and `computed_at`.
5. THE Dashboard SHALL expose a GET endpoint at `/attack_paths` that renders the `attack_paths.html` template containing the force-directed graph visualisation and the ranked path table.
6. THE Dashboard SHALL expose a GET endpoint at `/api/attack_path_nodes` that returns a JSON object mapping `device_name` to its `zone`, `criticality`, `vendor`, `product`, `risk_score`, `is_attacked`, and `updated_at` fields, sourced from the `attack_path_nodes` table; the same empty-result and error-handling behaviour as Requirement 6.2/6.3 SHALL apply (empty object `{}` with HTTP 200 when the table has no rows, `{"error": "<message>"}` with HTTP 500 on failure).

---

### Requirement 7: Dashboard Visualisation

**User Story:** As a security analyst, I want a dashboard page that visualises attack paths as a force-directed network graph and lists them in a ranked table, so that I can quickly understand which routes pose the greatest risk to OT targets.

#### Acceptance Criteria

1. THE `attack_paths.html` template SHALL render a force-directed graph using D3.js (loaded from CDN or local static asset) that displays every node and edge in the full plant communication topology (the client-side `GRAPH_EDGES` constant, mirroring `attack_path.TOPOLOGY_EDGES`) — not only nodes/edges that happen to lie on a currently-computed attack path.

   > **Revision note (2026-07-17):** originally scoped to "all nodes present in any computed attack path" — but that meant unreached-but-real devices (e.g. `Historian`, a dead-end off `SCADA_Server` that never appears on a *shortest* path even though it has a real edge; the isolated `Turbidity_Sensor_PLC`/`UV_Disinfection_PLC` pair) were invisible, silently making the graph look smaller/simpler than the actual network. Rendering the full static topology and highlighting which edges currently lie on a computed path (bright red, `stroke-width` 2.5, full opacity) versus background topology (dim grey, `stroke-width` 1.5, 35% opacity) shows the whole attack surface, not just the routes that happened to win Dijkstra this cycle.

2. THE force-directed graph SHALL colour nodes using the following scheme: Entry_Point nodes in blue, Target nodes in red, intermediate OT nodes in orange, and intermediate IT nodes in grey; nodes with `is_attacked = 1` SHALL display a distinct visual indicator (e.g., pulsing border or alert icon).
3. THE force-directed graph SHALL scale node size proportionally to the node's `risk_score`, with a minimum radius of 8 px and a maximum radius of 24 px.
4. WHEN a user hovers over a node in the force-directed graph, THE Dashboard SHALL display a tooltip showing: device name, zone, criticality, risk_score, and is_attacked status, sourced from `/api/attack_path_nodes` (Requirement 6.6) for every node — not only nodes that are the target of a path — so the values reflect real annotation data rather than a heuristic guess; IF the tooltip cannot be displayed (e.g., due to a touch-only device or CSS rendering failure), THE Dashboard SHALL display the same information in a static detail panel below the graph as a fallback.
5. THE `attack_paths.html` template SHALL render a ranked table below the graph listing all computed paths with columns: Rank, Entry Point, Path (arrow-separated device names), Target, Hops, Cost, and Max Risk.
6. THE ranked table SHALL highlight the row with the lowest cost (highest risk) using a distinct background colour (e.g., Bootstrap `table-danger`); WHEN no attack paths exist, THE ranked table SHALL display an empty-state message (e.g., "No attack paths computed yet.") instead of attempting to highlight a non-existent row.
7. THE `attack_paths.html` template SHALL be linked from the Dashboard navigation bar (defined in `base.html`) with a label of "Attack Paths".

---

### Requirement 8: Resilience and Fallback Behaviour

**User Story:** As a system operator, I want the attack path module to degrade gracefully when input files are missing or partially populated, so that the rest of the CAVE-OT pipeline is never blocked.

#### Acceptance Criteria

1. IF `assets.json` is missing or unreadable when the Attack_Path_Analyzer runs, THEN THE Attack_Path_Analyzer SHALL construct the graph using only the static `DEVICES` dictionary from `cave_monitor.py` and SHALL log a warning that asset enrichment was skipped.
2. IF `suricata_context.json` is missing or unreadable, THEN THE Attack_Path_Analyzer SHALL default `is_attacked = 0` for all nodes and SHALL log a warning.
3. IF `risk_scored_results.json` is missing or unreadable, THEN THE Attack_Path_Analyzer SHALL default `risk_score = 0.0` for all nodes, assign all edge weights to `1.0`, and SHALL log a warning.
4. WHEN a device listed in an entry point or target set is absent from the Attack_Graph (e.g., its container was never started), THE Attack_Path_Analyzer SHALL skip that device and SHALL log a warning identifying the missing device by name.
5. THE Attack_Path_Analyzer SHALL produce a valid (possibly empty) `attack_paths.json` file in all degraded-mode scenarios described above.
