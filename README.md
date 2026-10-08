# CAVE-OT

Context-Aware Vulnerability Engine for a simulated OT/ICS water-treatment plant.

## Current behavior

The engine captures simulated traffic, records observed endpoints, retrieves candidate CVEs, applies conservative product/firmware applicability checks, calculates a custom contextual risk score, and generates potential paths under configured topology assumptions. Complete monitoring cycles are atomically published to `docker/shared/snapshot.json`; the host validates and ingests each cycle into PostgreSQL, evaluates deterministic plant policies, and displays results through Flask.

- Device vendor/product/firmware supplied by the testbed inventory are explicitly marked configured and unverified. Unknown TCP service endpoints are retained.
- Text similarity is candidate retrieval, not vulnerability confirmation. Confirmed applicability requires verified identity and preserved simple vulnerable CPE/version constraints. Complex configurations and legacy flattened bounds need review.
- Policy results include pass, fail, unknown, and not applicable per rule. Patch age, encryption, and lifecycle data are never fabricated. An explicit plant rule prohibits OT protocols such as Modbus in the IT zone; ML cannot override that failure. Decisions are APPROVE, RESTRICT, REMEDIATE, and NEEDS_REVIEW; restrictions are analyst recommendations, not device enforcement.
- The review queue prioritizes failures on critical assets, then other failures, missing evidence, and passing assets, with direct links to remediation.
- The RandomForest is an optional historical advisory experiment. It is not required to run policy checks.
- Contextual risk is a custom prioritization score, version `cave-ot-2`, not official CVSS Environmental scoring. CVSS severity is retained separately; unknown CIA evidence stays null.
- IsolationForest evaluates against the previous accepted baseline; normal samples have zero anomaly suspicion. Unconfirmed anomalies do not boost live risk.
- Remediation requires confirmed CVE applicability, an external Groq key, retrieved local CVE context, deterministic safety checks, and human review. The server rejects blocked approvals and rechecks current evidence. Recommendations do not configure devices.
- Testbed services use simplified fixed protocol replies. Port 443 currently serves a plaintext HTTP simulation and is not evidence of TLS. Paths assume configured bidirectional reachability and do not prove exploitability.

## Run on the Windows host

Requires Python 3.11+, local PostgreSQL, and a working Linux container engine. This checkout selects the already-installed Docker Engine in WSL Ubuntu through `docker/backend.json`; Docker Desktop data is preserved. Set backend to `native` to return to Docker Desktop once its Windows socket issue is repaired. The WSL backend maintains a hidden project-owned session while monitoring runs, preventing WSL idle shutdown; `python docker_backend.py compose down` releases it.

```powershell
python -m pip install -r requirements.txt
# First-time database initialization:
psql -U postgres -c "CREATE DATABASE cave_ot;"
psql -U postgres -d cave_ot -f Database/db_schema.sql
psql -U postgres -d cave_ot -f Database/db_schema_policy.sql
psql -U postgres -d cave_ot -f Database/db_schema_remediation.sql
python Database/migrate_audit_fixes.py
python docker_backend.py compose up -d --build
python file_watcher.py
python Dashboard/app.py
```

Open http://127.0.0.1:5000. Stored results remain readable when scanning is stopped. Dashboard startup applies the versioned migration and starts the watcher. Do not run a second watcher if the dashboard already started one.

Connection variables: `CAVE_OT_DB_HOST`, `CAVE_OT_DB_PORT`, `CAVE_OT_DB_NAME`, `CAVE_OT_DB_USER`, `CAVE_OT_DB_PASSWORD`. The default database user is postgres; set `CAVE_OT_DB_PASSWORD` in your environment before connecting. `CAVE_OT_RUNTIME_DIR` overrides the host shared folder. `CAVE_OT_ENGINE_DIR` overrides engine runtime paths for VM/replay use; `CAVE_OT_DOCKER=1` selects container paths. The dashboard binds to loopback without debug mode by default.

## Training and provenance

`Model_Training/model_trainer.py` fits a general TF-IDF index and an OT index with shared vocabulary. Vendor/product weighting repeats separate tokens. Existing corpora can be recovered with `python Model_Training/rebuild_from_corpus.py`; original models are backed up and recovered CSVs receive provenance metadata. This does not reconstruct missing CPE constraints or policy labels. No new accuracy claim is made without independent labeled applicability evaluation.

`Data_Processing/data_processor.py` preserves vulnerable CPE entries, inclusive/exclusive bounds, and a conservative flag for simple configurations. Preserve these fields through cleaning and training. More complex AND/negated applicability is reported for review.

## Verify

```powershell
python -m pytest tests -q -p no:cacheprovider
$env:CAVE_OT_TEST_DB='1'
python -m pytest tests -q -p no:cacheprovider
```

Database integration tests create and remove disposable schemas and never modify production records. Regression coverage includes invalid scores, firmware boundaries, missing evidence, deterministic policy/API/database flow, violation/alert idempotency, snapshot corruption, remediation contracts, and blocked approvals. Live Docker/Suricata tests require a functioning host engine; a stopped engine is not a successful live test.

The audit repair migration preserves pre-repair rows in `audit_repair_archive`, repairs orphaned compliance references and duplicated rule seeds, restores the foreign key, removes artificial port-zero padding, and marks old similarity associations unverified.

## Analyst policy review

System recommendations and analyst decisions are separate. The policy page shows rule counts, records named decisions and rationale, and requests revalidation when policy evidence changes. Typed reviewer names are not authenticated accounts. See [Reports/POLICY_REVIEW_EXPLAINED.md](Reports/POLICY_REVIEW_EXPLAINED.md).

Normal migration creates the ledger; explicit setup: `python Database/migrate_policy_reviews.py`.
