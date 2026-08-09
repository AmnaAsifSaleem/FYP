# CAVE-OT — Project File Manifest

Context-Aware Vulnerability Engine for OT/ICS. This document classifies **every**
file so the team stops confusing which version is the real one.

**Legend**
- 🟥 **CORE** — the project will not run without it.
- 🟧 **SUPPORT** — needed for a full deployment (DB/dashboard/policy), but not the live scoring loop.
- 🟨 **PREP** — one-time offline work (data cleaning / model training). Regenerable.
- 🧪 **TEST/EVAL** — validates the system, produces report metrics. Not required to run.
- 📤 **GENERATED** — runtime output / sample data. Not source.
- 🗃️ **DATASET** — raw/processed data. Only needed to retrain.
- ⚠️ **DEPRECATED** — superseded/duplicate version. Safe to archive.
- 📝 **DOCS/MISC** — notes, config, scaffolding.

---

## The live system in one line
VM (`cave_monitor.py`) drives simulated plant traffic → `smart_discover.py` finds
assets → `cve_discovery.py` maps CVEs via TF-IDF model → `score_cve()` risk-scores
with OT CIA weighting + Suricata alerts → JSON synced over hgfs shared folder →
host PostgreSQL → Flask dashboard.

---

## 🟥 CORE — VM runtime (`/home/caveot/cave_ot_test`, mirrored in `A:\VM\CAVE-OT\shared folder`)
| File | Role |
|---|---|
| `cave_monitor.py` | Master orchestrator + live TUI. Runs the whole loop. |
| `smart_discover.py` | Passive asset discovery → `assets.json`. |
| `cve_discovery.py` | TF-IDF device→CVE mapping → `vulnerability_scan_results.json`. |
| `risk_scorer_v2.py` | OT risk-scoring logic (also inlined in cave_monitor). |
| `*_traffic.py` (modbus/`s7_traffic`, `dnp3_traffic`, `bacnet_traffic`, `hmi_traffic`, `backup_hmi_traffic`, `turbidity_traffic`, `uv_traffic`, `flowmeter_traffic`, `booster_traffic`, `reservoir_traffic`, `waterquality_traffic`) | Generate protocol traffic to Conpot honeypots = the simulated plant. |
| `suricata.yaml` + `ot-rules.rules` | IDS config + custom OT rules = the live alert feed. |
| `alert_ingester.py` | Feeds Suricata alerts into the scoring context. |
| `run_cave_ot.sh` / `run_cave_ot_tui.sh` | Launch scripts. |

## 🟥 CORE — Trained model artifacts (`model/`)
| File | Role |
|---|---|
| `ot_vectorizer.pkl`, `ot_matrix.pkl`, `ot_cve_database.pkl` | OT fine-tuned TF-IDF model. `cve_discovery.py` requires `ot_vectorizer.pkl`. |
| `general_vectorizer.pkl`, `general_matrix.pkl`, `cve_database.pkl` | General 206k-CVE model + CIA impact lookup used by `score_cve()`. |

> These 6 `.pkl` files are the trained "brain." Losing them = full retrain from NVD.

---

## 🟧 SUPPORT — Host database
| File | Role | Status |
|---|---|---|
| `Database/db_schema.sql` | Core PostgreSQL schema (assets, vulns, risk_scores). | 🟧 |
| `Database/db_schema_policy.sql` | Policy tables. | 🟧 |
| `Database/db_ingestor.py` | Loads VM JSON → PostgreSQL. Primary bridge. | 🟧 |
| `Database/db_manager.py` | DB connection layer used by dashboard. | 🟧 |
| `Database/sync_db.py` | Sync helper. | 🟧 |
| `Database/db_setup.py`, `create_db.py`, `db_policy_setup.py` | Overlapping setup scripts. | ⚠️ pick one |
| `Database/db_query.py`, `verify_tables.py` | DB inspection helpers. | 🧪 |

## 🟧 SUPPORT — Dashboard (`Dashboard/`)
| File | Role | Status |
|---|---|---|
| `app.py` | Flask web server. The SOC dashboard. | 🟧 CORE-for-UI |
| `policy_api.py` | Policy/compliance endpoints. | 🟧 |
| `templates/*.html` (base, index, assets, vulnerabilities, alerts, policy, pipeline) | UI pages. | 🟧 |
| `static/` (bootstrap, chart.min.js, fonts) | Front-end assets. | 🟧 |
| `patch_css.py` | One-off CSS fixer. | ⚠️ |

## 🟧 SUPPORT — Policy compliance (`Policy_Compliance/`)
| File | Role | Status |
|---|---|---|
| `models/policy_compliance_model.pkl` + `scaler.pkl` + `label_encoders.pkl` | Trained policy classifier + preprocessing. | 🟧 CORE-for-policy |
| `policy_predictor.py` | Loads model, runs predictions. | 🟧 |
| `policy_integrator.py`, `policy_preprocessor.py` | Wiring + preprocessing. | 🟧 |
| `policy_model_trainer.py` | Trains the policy model. | 🟨 PREP |
| `policy_predictor_updated.py`, `policy_model_trainer_improved.py`, `models/*_improved.*`, `*_backup.*` | Iterations/backups. | ⚠️ DEPRECATED |
| `analyze_dataset.py`, `plots/` | Analysis output. | 🧪 |

---

## 🟨 PREP — Offline data & training
| File | Role |
|---|---|
| `Data_Processing/data_processor.py` | Builds `processed_cves.csv` + `ot_cves.csv` from NVD/EPSS/KEV. |
| `Data_Processing/datacleaner.py`, `ot_cleaner.py` | One-time CSV cleaning. |
| `Model_Training/model_trainer.py` | Trains the 6 TF-IDF `.pkl` artifacts. |
| `Model_Training/model_trainer_proper.py`, `train_and_evaluate.py`, `proper_train_test_split.py` | Training experiments. ⚠️ pick one. |

---

## 🧪 TEST / EVAL (report metrics, not runtime)
- `Testing/` (all: `run_tests.py`, `unit_tests/`, `integration_tests/`, `test_all.bat`/`.sh`, `test_data/`, `reports/`)
- `Model_Evaluation/` (all: `comprehensive_evaluator.py`, `proper_evaluator.py`/`_fixed.py`, `detailed_metrics_calculator.py`, `model_evaluator.py`, `check_setup.py`, `test_pipeline.py`)
- Root: `test_api.py`, `test_policy.py`, `test_dashboard.html`, `verify_nfrs.py`, `verify_project.py`, `check_database.py`, `check_database_fixed.py`

---

## 📤 GENERATED — runtime output / sample data (not source)
- `Assets/` (all: `assets.json`, `risk_scored_results.json`, `vulnerability_scan_results.json`, `suricata_context.json`, `model_input.json`, `policy_results.json`, `scorer_output.txt`, `test_input.json`, `check_output.py`)
- VM/shared: `assets.json`, `suricata_context.json`, `vulnerability_scan_results.json`, `risk_scored_results.json`, `model_input.json`, `session_start.json`, `output.txt`, `test_all.pcap`
- Utility converters: `convert_to_scan_results.py`, `create_model_input.py`, `file_watcher.py`

---

## 🗃️ DATASET — only needed to retrain
- `Datasets/` (all: `processed_cves.csv`, `training_ready*.csv`, `ot_*.csv`, `policy_dataset.csv`, `cisa_data.json`, `epss_scores-current.csv.gz`, train/test splits)
- Root: `epss_scores-2026-03-11.csv`
- `NVD_Data/` (raw NVD zips)

---

## ⚠️ DEPRECATED — superseded/duplicate versions (safe to archive)
| File | Superseded by |
|---|---|
| `CVE_Pipeline/risk_scorer.py` | `risk_scorer_v2.py` |
| `CVE_Pipeline/cve_mapper.py`, `discover.py` | VM `cve_discovery.py` / `smart_discover.py` |
| `CVE_Pipeline/query_all_cves.py`, `query_multiple_assets.py` | ad-hoc query scripts |
| VM: `discover.py`, `discover_old.py`, `newdiscover.py` | `smart_discover.py` |
| VM: `final_tui.py`, `finalfinal_tui.py`, `new_tui.py`, `tui_pipeline.py` | `cave_monitor.py` (TUI) |
| VM: `traffic.py`, `live_comms.py`, `coordinator.py` | the individual `*_traffic.py` + `cave_monitor.py` |
| VM: `fix_tui_suricata.sh`, `write_rules.sh` | one-off fix scripts |

---

## 📝 DOCS / MISC
- `README.md` — ML pipeline overview.
- `PROJECT_STRUCTURE.md` — this file.
- `requirements.txt` — dep install (not a runtime module).
- `run_pipeline.bat` — Windows launcher.
- `New Text Document.txt` — a copy of `data_processor.py` (redundant).
- VM: `New Text Document (2/3/4).txt`, `u are req to use investigativetechq.txt` — notes.
- `.claude/`, `.vs/`, `.vscode/` — editor config.
- Empty/aux dirs: `Model Traning`, `New folder`, `Reports`, `Assets`.

---

## Known gaps vs. project document
- **LLM + RAG remediation advisor** (Module 2): NOT implemented.
- **Attack-path analysis** (NetworkX): partial/not in live path.
- **RF/XGBoost classifier**: project doc (Module 2 FR3) promises it; live path actually
  uses the deterministic CVSS-Environmental formula + TF-IDF. Reconcile in the report.
