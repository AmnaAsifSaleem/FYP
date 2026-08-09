# CAVE-OT

**Context-Aware Vulnerability Engine for OT/ICS Networks**

A testbed and analysis engine for OT/ICS security: it passively discovers
devices on a simulated water-treatment plant network, maps them to real CVEs
using TF-IDF similarity, scores risk with an OT-weighted CVSS-Environmental
formula (availability weighted highest, matching physical-safety priorities
rather than generic IT CIA weighting), models lateral-movement attack paths
through the plant topology, and checks assets against NIST/NERC/CISA policy
rules — all surfaced on a live web dashboard.

**Team:** Amna Asif · Abdul Mueed Malik · M. Nameer Khan — NUCES-FAST Islamabad

---

## What's actually running

```
┌─────────────────────────────────────────────────────────────────┐
│  Simulated plant (Docker or VM)                                  │
│                                                                    │
│  15 simulated devices (PLCs/RTUs/HMIs/sensors) talking real       │
│  Modbus/S7/DNP3/BACnet/HTTP  →  Suricata IDS  →  passive          │
│  discovery  →  TF-IDF CVE matching  →  CVSS-Environmental risk    │
│  scoring  →  Dijkstra attack-path analysis                        │
└──────────────────────────────┬──────────────────────────────────┘
                                │ JSON output → shared folder
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  Windows host                                                     │
│  file_watcher.py → Database/sync_db.py → PostgreSQL               │
│                                          → Dashboard/app.py        │
│                                            → http://localhost:5000 │
└─────────────────────────────────────────────────────────────────┘
```

Two ways to run the "simulated plant" half — pick one:

- **Docker** (recommended — see [`docker/README.md`](docker/README.md) for
  full architecture details) — two containers, no VM required, works
  identically for every teammate who clones this repo.
- **VM** (Ubuntu Server + Conpot, the original setup) — heavier, but kept as
  an alternative; see [Running on the VM](#running-on-the-vm) below.

Both produce the exact same JSON output and feed the same host-side
pipeline — you don't need both, and the dashboard doesn't know or care which
one produced the data it's showing.

---

## Quickstart (Docker path)

### 1. Prerequisites

- **Docker Desktop** (with WSL2 backend) — [docker.com](https://www.docker.com/products/docker-desktop/)
- **PostgreSQL** — running locally, with a `cave_ot` database
- **Python 3.11+**

### 2. Clone and install Python dependencies

```bash
git clone https://github.com/mueedmak/CAVE-OT.git
cd CAVE-OT
pip install -r requirements.txt
```

### 3. Train the CVE-matching model (one-time, ~5-10 minutes)

The trained model (`model/*.pkl`) is gitignored — too large for git, and it's
just derived data. Regenerate it:

```bash
python Model_Training/model_trainer.py
```

(Needs the OT/general CVE datasets — see [`PROJECT_STRUCTURE.md`](PROJECT_STRUCTURE.md)
if these aren't already present under `Datasets/`.)

### 4. Set up the database

```bash
psql -U postgres -c "CREATE DATABASE cave_ot;"
psql -U postgres -d cave_ot -f Database/db_schema.sql
psql -U postgres -d cave_ot -f Database/db_schema_policy.sql
```

(Default credentials assumed throughout the codebase: user `postgres`,
password `admin`, host `localhost`, port `5432` — adjust `DB_CONFIG` in
`Dashboard/app.py` / `Database/sync_db.py` / `attack_path.py` if yours differ.)

### 5. Start the simulated plant

```bash
cd docker
docker compose up -d --build
```

Watch it running: `docker logs -f caveot-engine`

### 6. Start the host-side pipeline

In two separate terminals, from the repo root:

```bash
python file_watcher.py
```
```bash
python Dashboard/app.py
```

### 7. Open the dashboard

**http://localhost:5000**

Within ~15-40 seconds of step 5, you should see live assets, CVEs, alerts,
and attack paths.

Full Docker architecture, design rationale, and troubleshooting:
[`docker/README.md`](docker/README.md).

---

## Running on the VM

The original setup used an Ubuntu Server VM running Conpot honeypots instead
of Docker containers. If you have the VM disk image (shared separately —
~15GB, not distributed via git):

1. Boot the VM, open a terminal as the `caveot` user
2. `cd /home/caveot/cave_ot_test && sudo python3 cave_monitor.py`
3. On the host, point `file_watcher.py`'s `WATCH_DIR` and
   `Database/sync_db.py`'s `_SHARED` at your VMware shared folder path
   instead of `docker/shared/`
4. Steps 6-7 above are identical either way

---

## Features

| Module | What it does | Status |
|---|---|---|
| **Passive discovery** (`smart_discover.py`) | Identifies devices from captured traffic (port + protocol), no active scanning — safe for fragile OT devices | Live |
| **CVE matching** (`cve_discovery.py`) | TF-IDF cosine similarity against a 4.8k-entry OT-specific CVE corpus | Live |
| **Risk scoring** (in `cave_monitor.py`) | CVSS-Environmental formula, OT-weighted CIA (availability > integrity > confidentiality), boosted by EPSS/KEV/live IDS alerts | Live |
| **Attack path analysis** (`attack_path.py`) | Dijkstra shortest-path lateral-movement modelling from IT entry points to high-criticality OT targets, risk-weighted | Live |
| **Policy compliance** (`Policy_Compliance/`) | RandomForest classifier against NIST SP 800-82r3 / NERC CIP-007-6 / CISA DiD rules, with plain-English explanations | Live (ML-only — see `TODO.md` for the planned deterministic-rules gate) |
| **LLM remediation advisor** | RAG-based, human-in-the-loop remediation suggestions | Not yet built — see [`CAVE-OT_Iteration_and_Roadmap.md`](CAVE-OT_Iteration_and_Roadmap.md) |

## Risk scoring formula

CVSS v3.1 Environmental Scoring + NIST SP 800-82 OT weighting:

```
temporal      = cvss × exploit_maturity(epss) × remediation(kev)
cia           = (c_impact × 0.20) + (i_impact × 0.30) + (a_impact × 0.50)
environmental = min(temporal × cia × asset_criticality × 10, 10.0)
if kev == 1: environmental × 1.10   (capped at 10.0)
suricata_factor = min((alert_count × severity_weight) / 30, 1.0) × 1.5
final = min(environmental + suricata_factor, 10.0)
```

Availability is weighted highest (0.50) — in OT, a bug that takes a pump
offline is a physical-safety problem, unlike a typical IT confidentiality
breach.

**Risk tiers:** 🔴 CRITICAL ≥8.0 · 🟠 HIGH 6.0-7.9 · 🟡 MEDIUM 4.0-5.9 · 🟢 LOW <4.0

## CVE matching model

Two-stage TF-IDF training:
1. **General model** (206k CVEs) — broad patterns across IT and OT
2. **OT fine-tuned model** (4.8k CVEs) — specialized vocabulary for
   ICS/SCADA vendor/product terms, used at runtime by `cve_discovery.py`

Cosine similarity against the query string (vendor + product + firmware),
filtered by firmware version range where available.

---

## What's in this repo (and what isn't)

Source code only. Large/regenerable artifacts are gitignored — see
[`PROJECT_STRUCTURE.md`](PROJECT_STRUCTURE.md) for the full manifest.

| Excluded | How to get it |
|---|---|
| `model/*.pkl` (TF-IDF models) | `python Model_Training/model_trainer.py` |
| `Policy_Compliance/models/*.pkl` | `python Policy_Compliance/policy_model_trainer.py` |
| `Datasets/`, NVD zips, EPSS/KEV | Download from NVD/FIRST/CISA, then `python Data_Processing/data_processor.py` |
| VM disk image (~15GB) | Shared separately — or just use Docker instead, see Quickstart above |
| `docker/shared/` (generated runtime output) | Created automatically when the pipeline runs |

## Known gaps / planned work

See [`TODO.md`](TODO.md) — currently tracking: graceful handling of
unrecognized devices during discovery, making policy compliance a
deterministic rules-gate instead of pure ML classification, and further
file-layout cleanup.

## Academic references

- TF-IDF: Salton & Buckley (1988)
- CVSS v3.1: FIRST.org
- OT CIA weighting: NIST SP 800-82
- Asset criticality: IEC 62443
