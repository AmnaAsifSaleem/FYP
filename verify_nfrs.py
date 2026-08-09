import json, sys
sys.path.insert(0, 'CVE_Pipeline')
from risk_scorer_v2 import score_cve, cia_fallback

results = []

# NFR 1: Determinism
test_cve = {'cve_id': 'CVE-2022-30938', 'cvss': 7.5, 'epss': 0.018, 'kev': 0}
cia_lookup = {'CVE-2022-30938': (0.0, 0.0, 0.56)}
scores = [score_cve(test_cve, 0.95, cia_lookup, 0, 3)[0] for _ in range(100)]
unique = set(scores)
results.append(("Determinism: same input 100x = 0 variance", len(unique) == 1, f"unique scores: {unique}"))

# NFR 2: CIA fallback availability >= 0.56 for CVSS >= 7.0
cases = [7.0, 7.5, 8.0, 9.0, 9.9, 10.0]
fallback_pass = all(cia_fallback(cvss)[2] >= 0.56 for cvss in cases)
results.append(("CIA fallback a_impact >= 0.56 for CVSS >= 7.0", fallback_pass, f"tested: {cases}"))

# NFR 3: Similarity threshold enforced in code
with open('CVE_Pipeline/cve_mapper.py') as f:
    mapper = f.read()
has_ot_thresh = "threshold = 0.10" in mapper
has_it_thresh = "threshold = 0.15" in mapper
has_filter    = "candidates['similarity'] >= threshold" in mapper
results.append(("OT threshold 0.10 defined", has_ot_thresh, ""))
results.append(("IT threshold 0.15 defined", has_it_thresh, ""))
results.append(("Threshold filter applied before returning CVEs", has_filter, ""))

# NFR 4: Upsert idempotency
with open('Database/db_manager.py') as f:
    dbm = f.read()
asset_upsert = "ON CONFLICT (ip, port) DO UPDATE" in dbm
vuln_upsert  = "ON CONFLICT (asset_id, cve_id) DO UPDATE" in dbm
results.append(("Idempotent asset upsert (ON CONFLICT)", asset_upsert, ""))
results.append(("Idempotent vulnerability upsert (ON CONFLICT)", vuln_upsert, ""))

# NFR 5: Shared folder sync fails silently
with open('cave_monitor.py', encoding='utf-8', errors='ignore') as f:
    monitor = f.read()
silent_sync = "if not os.path.isdir(SHARED_DIR)" in monitor
results.append(("sync_to_shared fails silently when folder missing", silent_sync, ""))

# NFR 6: File watcher polling fallback within 5s
with open('file_watcher.py') as f:
    watcher = f.read()
has_fallback   = "except ImportError" in watcher and "watch_polling" in watcher
poll_interval  = "time.sleep(2)" in watcher
debounce_5s    = "DEBOUNCE_SECONDS = 5" in watcher
results.append(("Watcher falls back to polling on ImportError", has_fallback, ""))
results.append(("Polling interval 2s (detects change within 5s)", poll_interval, ""))
results.append(("Debounce <= 5s between syncs", debounce_5s, ""))

# NFR 7: All risk scores in [0.0, 10.0] in actual output
with open('Assets/risk_scored_results.json') as f:
    data = json.load(f)
total_cves = 0
out_of_range = []
for device in data['devices']:
    for cve in device['cves']:
        rs = cve['risk_score']
        if not (0.0 <= rs <= 10.0):
            out_of_range.append((cve['cve_id'], rs))
        total_cves += 1
results.append((f"All {total_cves} risk scores in [0.0, 10.0]", len(out_of_range) == 0, f"violations: {out_of_range}"))

# NFR 8: TUI refresh >= 1Hz
tui_1hz = "time.sleep(1)" in monitor
results.append(("TUI refresh rate >= 1Hz (sleep=1s)", tui_1hz, ""))

# NFR 9: Per-device fault isolation in monitor
except_count = monitor.count("except Exception as e")
results.append((f"Per-device fault isolation (except blocks: {except_count})", except_count >= 3, ""))

# NFR 10: Pipeline scripts accept custom input path
with open('CVE_Pipeline/risk_scorer_v2.py') as f:
    scorer = f.read()
scorer_argv = "sys.argv[1]" in scorer
mapper_argv = "sys.argv[1]" in mapper
results.append(("risk_scorer_v2.py accepts custom input path", scorer_argv, ""))
results.append(("cve_mapper.py accepts custom input path", mapper_argv, ""))

# NFR 11: Policy rules reference source standards
with open('Database/db_schema_policy.sql') as f:
    schema = f.read()
has_nist = "NIST SP 800-82r3" in schema
has_nerc = "NERC CIP" in schema
has_cisa = "CISA" in schema
results.append(("Policy rules reference NIST SP 800-82r3", has_nist, ""))
results.append(("Policy rules reference NERC CIP", has_nerc, ""))
results.append(("Policy rules reference CISA", has_cisa, ""))

# NFR 12: Confidence score returned by predictor
with open('Policy_Compliance/policy_predictor.py') as f:
    predictor = f.read()
has_confidence = "'confidence'" in predictor
has_score      = "'compliance_score'" in predictor
results.append(("Predictor returns confidence field", has_confidence, ""))
results.append(("Predictor returns compliance_score field", has_score, ""))

# NFR 13: Dashboard independent of pipeline (no pipeline imports)
with open('Dashboard/app.py') as f:
    app = f.read()
no_pipeline_dep = "cve_mapper" not in app and "risk_scorer" not in app
results.append(("Dashboard has no hard dependency on pipeline scripts", no_pipeline_dep, ""))

# ── Print results ─────────────────────────────────────────────────────────────
print()
print("=" * 72)
print("  CAVE-OT NFR VERIFICATION RESULTS")
print("=" * 72)
passed = 0
failed = 0
for label, ok, note in results:
    status = "PASS" if ok else "FAIL"
    marker = "[+]" if ok else "[X]"
    print(f"  {marker} {status}  {label}")
    if note:
        print(f"         {note}")
    if ok:
        passed += 1
    else:
        failed += 1

print()
print(f"  Total: {passed + failed}  |  Passed: {passed}  |  Failed: {failed}")
print("=" * 72)
