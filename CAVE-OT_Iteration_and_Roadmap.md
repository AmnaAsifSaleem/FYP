# CAVE-OT — Completed Iteration Report & FYP-2 Feature Roadmap

**Project:** Context-Aware Vulnerability Engine for OT/ICS Networks (CAVE-OT)
**Team:** Amna Asif (22I-8777) · Abdul Mueed Malik (22I-1622) · M. Nameer Khan (22I-1695)
**Supervisor:** Dr. Subhanullah — NUCES-FAST Islamabad
**Scope of this document:** ground-truth status of the codebase (verified directly against `github.com/mueedmak/CAVE-OT`, not the aspirational proposal doc) + a concrete implementation plan for the three FYP-2 Module 2 deliverables: **Attack Path Analysis**, **LLM-Based Remediation Advisor**, **Policy Enforcement ("Gatekeeper")**.

---

## Part 1 — Completed Iteration (verified against live code)

### 1.1 What actually runs today

The live system is a single orchestrator process, `cave_monitor.py`, running inside the Ubuntu VM (`caveot` user, `/home/caveot/cave_ot_test`). Everything else either feeds it or consumes its output.

```
┌─────────────────────────────── VM: caveot ───────────────────────────────┐
│                                                                            │
│  13 Conpot containers  ──►  comm_cycle()  ──►  real Modbus/S7/DNP3/       │
│  (simulated PLCs/RTUs/       (bg thread)        BACnet/HTTP traffic       │
│   HMIs/sensors)                                 between 15 DEVICES        │
│                                                                            │
│  Suricata (pcap mode, -i lo) ──► /var/log/suricata/fast.log               │
│         │                              │                                  │
│         │                       read_alerts() (bg thread, poll 2s)        │
│         │                              │  new port seen? → run_discovery()│
│         ▼                              ▼                                  │
│  pcap_loop() (bg thread, every 10s) ──► run_discovery()                   │
│         │                                                                 │
│         │   1. capture_pcap()      tcpdump -i lo -c 200 → test_all.pcap   │
│         │   2. smart_discover.py   pcap + fast.log → assets.json +        │
│         │                           suricata_context.json                 │
│         │   3. cve_discovery.py    TF-IDF cosine sim (vendor+product+     │
│         │                           firmware vs 6k OT CVE corpus)         │
│         │                           → vulnerability_scan_results.json     │
│         │   4. _score_and_display() CVSS-Environmental formula            │
│         │                           → risk_scored_results.json            │
│         ▼                                                                 │
│  sync_to_shared() → VMware hgfs shared folder                             │
└────────────────────────────────────┬──────────────────────────────────────┘
                                      │
┌─────────────────────────── Windows Host ───────────────────────────────┐
│  file_watcher.py → Database/db_ingestor.py → PostgreSQL                 │
│                                                     │                    │
│                                            Dashboard/app.py (Flask)      │
│                                            → http://localhost:5000      │
└───────────────────────────────────────────────────────────────────────┘
```

### 1.2 Confirmed dead / superseded files (do not reference these in the report as "in use")

| Old name | Superseded by |
|---|---|
| `new_tui.py`, `final_tui.py`, `tui_pipeline.py` | `cave_monitor.py` (TUI is now built in) |
| `discover.py`, `discover_old.py`, `newdiscover.py` | `smart_discover.py` |
| `traffic.py`, `live_comms.py`, `coordinator.py` | the individual `*_traffic.py` files + `comm_cycle()` inside `cave_monitor.py` |
| `CVE_Pipeline/risk_scorer.py` | `risk_scorer_v2.py` (logic now inlined in `cave_monitor.py` as `score_cve()`) |

### 1.3 Risk scoring formula actually implemented

```
temporal      = cvss × exploit_maturity(epss) × remediation(kev)
cia           = (c_impact × 0.20) + (i_impact × 0.30) + (a_impact × 0.50)
environmental = min(temporal × cia × asset_criticality × 10, 10.0)
if kev == 1: environmental × 1.10   (capped at 10.0)
suricata_factor = min((alert_count × severity_weight) / 30, 1.0) × 1.5
final = min(environmental + suricata_factor, 10.0)
```
Tiers: 🔴 CRITICAL ≥8.0 · 🟠 HIGH 6.0–7.9 · 🟡 MEDIUM 4.0–5.9 · 🟢 LOW <4.0

**Note for the report:** this is CVSS-Environmental + NIST SP 800-82 weighting, **not** the RF/XGBoost classifier the FYP-1 proposal document describes for Module 2 FR3. Flag this explicitly as a design decision (deterministic, explainable formula chosen over a black-box classifier for a safety-critical OT context) rather than letting an evaluator catch it as an inconsistency.

### 1.4 What's built but NOT wired into the live loop

This matters for your report — these aren't "not started," they're "built standalone, not integrated":

| Component | State |
|---|---|
| `Policy_Compliance/policy_predictor.py` + trained `.pkl` classifier | Works as a **batch script** against the PostgreSQL `assets` table. Not called from `cave_monitor.py`, not called from the dashboard automatically. |
| `Database/db_schema_policy.sql` | Full schema exists — `policy_compliance`, `policy_violations`, `policy_rules` tables, seeded with 7 NIST SP 800-82r3 / CISA DiD / NERC CIP-007-6 rules. Unused by the live pipeline. |
| Attack path analysis | **Not implemented at all.** Confirmed zero `networkx` references anywhere in the repo. |
| LLM remediation advisor | **Not implemented at all.** Zero LLM/RAG code in the repo. |

This is exactly the FYP-2 gap: your Iteration 03/04 timeline (Attack Path + Policy enforcement, then Dashboard + LLM Advisor) maps directly onto these three missing pieces. Below is a concrete design for each, built to plug into the existing pipeline rather than replace it.

---

## Part 2 — Next Features

### 2.1 Attack Path Analysis (Iteration 03)

**Why it's easy to bolt on:** `cave_monitor.py`'s `comm_cycle()` already hardcodes a directed communication topology (which device legitimately talks to which). That list *is* your attack graph's edge set — nobody has to invent a topology, just formalize the one already driving the simulation.

**New file:** `shared folder/attack_path.py`

- Build a `networkx.DiGraph` from the same edges as `comm_cycle()`'s `comms` list.
- Annotate each node with: `zone` (IT/OT), `criticality` (from `assets.json`), `risk_score` (top CVE risk from `risk_scored_results.json`), `is_attacked` (from `suricata_context.json`).
- Edge weight = `1 / risk_score` of the source node — an attacker pivots more cheaply through a node that's already highly exploitable.
- Entry points = internet/user-facing IT assets: `HMI_Interface`, `Backup_HMI_Interface`, `Engineering_WS`, `SCADA_Server`.
- Targets = highest-criticality OT process-control assets: `Filtration_PLC` (0.98), `Dosing_Pump_PLC` (0.97), `UV_Disinfection_PLC` (0.96).
- Run `nx.shortest_path` (Dijkstra) weighted by the risk-based edge cost, for every entry→target pair.
- Output `attack_paths.json`: ranked list of `{entry, target, path, hops, cost, max_risk_on_path}`.

**Wiring:** one line added to `run_discovery()` in `cave_monitor.py`, right after `_score_and_display()`:
```python
subprocess.run(["python3", f"{CAVE_DIR}/attack_path.py"], capture_output=True, text=True)
sync_to_shared("attack_paths.json")
```
So every 10s pcap cycle recomputes attack paths using live Suricata/CVE data — not a static one-off analysis.

**DB + dashboard:** add `attack_paths` table (`entry_asset`, `target_asset`, `hops`, `cost`, `max_risk_on_path`, `path_json`) mirroring how `risk_scored_results.json` already feeds `db_ingestor.py`; add a dashboard page rendering the top paths, ideally as a force-directed graph (D3/vis.js — `Dashboard/static` already has chart.js loaded, so the frontend dependency story is cheap).

---

### 2.2 LLM-Based Remediation Advisor (Iteration 04)

**Design goal from your own proposal doc:** *"Generates explainable, OT-safe recommendations without automatic patching... human-in-the-loop decision interface."* So this is explicitly advisory, never actuating.

**Architecture — RAG over your own risk output, not a general chatbot:**

```
risk_scored_results.json + attack_paths.json + policy_compliance (DB)
                    │
                    ▼
        Retrieval layer (per flagged CVE/asset):
          - CVE description + CVSS vector (from cve_database.pkl)
          - NIST SP 800-82 / IEC 62443 mitigation text (small local corpus,
            chunked + embedded — this is your "RAG" knowledge base)
          - the asset's position in any attack_paths.json entry
          - the asset's policy_compliance status/violations
                    │
                    ▼
        Prompt template → LLM (Claude/GPT via API, or local model if the
        FYP requires no external API calls)
                    │
                    ▼
        Structured output (JSON, not free text):
          { asset, cve_id, risk_score, recommendation,
            rationale, ot_safety_note, requires_maintenance_window,
            confidence }
                    │
                    ▼
        → policy gatekeeper (2.3) validates recommendation
                    │
                    ▼
        Dashboard: shown to SOC analyst for approval — never auto-applied
```

**Concretely, new module:** `Remediation/remediation_advisor.py`
- Build a small local knowledge base: NIST SP 800-82r3 sections + IEC 62443 zone/conduit guidance + CISA ICS advisories relevant to your 15 simulated devices. Chunk it, embed with a lightweight local embedding model (e.g. `sentence-transformers`), store in a simple vector store (FAISS is enough at this scale — you don't need a hosted vector DB for a 15-device testbed).
- For each CRITICAL/HIGH-tier device in `risk_scored_results.json`: retrieve top-k relevant chunks, retrieve any attack path it sits on, retrieve its policy violations, assemble a grounded prompt, call the LLM, force JSON-schema output.
- **Force "OT-safe" behavior explicitly in the prompt**: never recommend disabling a PLC/RTU outright, always flag if a fix requires a maintenance window, always cite the specific CVE/rule it's responding to (this is what makes it "explainable" for the report — you can literally show the retrieved context next to the recommendation).
- Output: `remediation_advice.json`, ingested into a new `remediation_advice` table, surfaced in the dashboard next to each vulnerability with an **Approve / Reject / Defer** control — that's your human-in-the-loop interface.

This is the piece most worth prototyping early, since "LLM + RAG" is the highest-effort, highest-risk item on your timeline — get a thin end-to-end version working on 2–3 devices before polishing.

---

### 2.3 Policy Gatekeeper (Iteration 03 — "policy enforcement integration")

You already have 80% of this built; it's just not a *gate*, it's a *report*. Right now `policy_predictor.py` classifies assets as COMPLIANT/NON_COMPLIANT independently. A "gatekeeper" means: **no remediation recommendation or risk-driven action reaches the analyst without first being checked against policy.**

**Where it sits in the flow:**

```
remediation_advisor.py produces a candidate recommendation
                    │
                    ▼
        policy_gatekeeper.check(asset, recommendation)
          1. Pull asset's current policy_compliance row (or run
             policy_predictor.predict() fresh if stale)
          2. Pull matching rows from policy_rules (zone/service/port match)
          3. Rule-based hard gates (deterministic, not ML):
               - is target device OT + criticality > 0.9?
                    → recommendation MUST include requires_maintenance_window=true
               - does recommendation imply taking a device offline
                 during business hours / without a scheduled window?
                    → BLOCK, return "requires manual override"
               - does asset's zone require encryption per policy_rules
                 and recommendation doesn't address it?
                    → flag as PARTIAL, don't silently pass
          4. ML layer (existing policy_predictor.pkl) as a soft signal:
             compliance_score attached as metadata, not a blocker by itself
                    │
                    ▼
        gatekeeper verdict: ALLOW / BLOCK / NEEDS_REVIEW + reasons[]
                    │
                    ▼
        only ALLOW/NEEDS_REVIEW recommendations are shown to the analyst;
        BLOCK is logged (audit trail) but suppressed from the action list
```

**New file:** `Policy_Compliance/policy_gatekeeper.py`
- Deterministic rule engine first (cheap, explainable, auditable — this is what a real OT security team would trust), the existing trained classifier second (as a confidence signal layered on top, not the sole decision-maker). This split matters for your defense: an evaluator will ask "would you trust an ML model alone to gate actions on a water treatment plant?" — the honest answer is no, and your architecture should already say no.
- Every gatekeeper decision writes an audit row (`asset_id`, `recommendation_id`, `verdict`, `reasons`, `timestamp`) — this becomes your compliance evidence trail for the report (maps directly to "Policy enforcement mechanisms ensure that remediation decisions align with organizational security rules and industrial constraints").

**Minimal schema addition:**
```sql
CREATE TABLE gatekeeper_decisions (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER REFERENCES assets(id),
    recommendation_id INTEGER,
    verdict VARCHAR(20) CHECK (verdict IN ('ALLOW','BLOCK','NEEDS_REVIEW')),
    reasons JSONB,
    decided_at TIMESTAMP DEFAULT NOW()
);
```

---

## Part 3 — How the three pieces connect (the actual Module 2 pipeline)

```
risk_scored_results.json  ──┐
attack_paths.json          ─┼──►  remediation_advisor.py  ──►  candidate
policy_compliance (DB)     ─┘        (LLM + RAG)                recommendation
                                                                       │
                                                                       ▼
                                                          policy_gatekeeper.py
                                                          (rules + ML classifier)
                                                                       │
                                              ┌────────────────────────┼────────────────────────┐
                                              ▼                        ▼                         ▼
                                            BLOCK                 NEEDS_REVIEW                 ALLOW
                                      (logged, hidden)      (shown, flagged)          (shown, ready to approve)
                                                                       │
                                                                       ▼
                                                        Dashboard: analyst Approve/Reject/Defer
```

This is a defensible, evaluator-friendly Module 2: attack paths give *situational awareness*, the LLM advisor gives *explainable recommendations*, and the gatekeeper gives *the industrial-safety constraint* your problem statement claims IT-native tools lack. None of it auto-patches anything — every action still ends at a human.

---

## Part 4 — Suggested build order (mapped to your existing timeline)

| Iteration | Task | Depends on |
|---|---|---|
| 03 (Aug–Oct) | `attack_path.py` + DB table + wiring into `run_discovery()` | live `risk_scored_results.json`, `suricata_context.json` (already exist) |
| 03 (Aug–Oct) | `policy_gatekeeper.py` rule engine (deterministic part first) | existing `policy_rules` table (already seeded) |
| 04 (Nov) | `remediation_advisor.py` — thin prototype on 2–3 devices | attack_paths.json, gatekeeper for validation |
| 04 (Nov) | Dashboard: attack path graph view, remediation approve/reject UI, gatekeeper audit trail view | all of the above |
| 04 (Dec) | Testing/evaluation write-up: attack path precision on known topology, gatekeeper block/allow accuracy against manually-labeled cases, LLM recommendation quality (human eval rubric) | full pipeline |

---

*Generated from a direct read of the `mueedmak/CAVE-OT` repository (commit as of 2026-07-16), cross-referenced against `PROJECT_STRUCTURE.md` and `Reports/PROJECT_STATUS_SUMMARY.md`.*
