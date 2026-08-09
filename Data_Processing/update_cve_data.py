"""
update_cve_data.py
===================
Automates what used to be a fully manual chain: hand-download NVD zips +
EPSS + CISA KEV, then run data_processor.py -> ot_cleaner.py ->
datacleaner.py -> Model_Training/model_trainer.py in order.

This script fetches only what changed since the last successful run (via
the NVD REST API 2.0's lastModStartDate/lastModEndDate filter, not a full
historical re-download), merges it into the existing dataset, and reuses
every one of the 4 existing pipeline scripts' own functions unmodified for
parsing/cleaning/training — nothing here duplicates their logic.

Run:
    python Data_Processing/update_cve_data.py             # real run
    python Data_Processing/update_cve_data.py --dry-run   # fetch + report only
    python Data_Processing/update_cve_data.py --since 2026-01-01

Optional env var: NVD_API_KEY (raises the NVD rate limit from 5 to 50
requests/30s — get one free at https://nvd.nist.gov/developers/request-an-api-key)
"""

import os
import sys
import json
import time
import shutil
import argparse
import subprocess
import requests
import pandas as pd
from datetime import datetime, timedelta, timezone

# Windows consoles/redirected-output streams default to cp1252, which can't
# encode the unicode arrows/checkmarks the reused pipeline scripts print
# (e.g. ot_cleaner.py's "-> Next step"). Same fix Dashboard/app.py already
# applies, needed here since this script imports and calls those scripts'
# functions in-process, so their prints go through this process's stdout.
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

def _utcnow():
    """Naive UTC datetime (matches since_dt, which is parsed from plain
    'YYYY-MM-DD' strings with no tzinfo) — datetime.utcnow() is deprecated."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, "Data_Processing"))
sys.path.insert(0, os.path.join(REPO_ROOT, "Model_Training"))

from pipeline_paths import DATASET_FOLDER, MODEL_FOLDER
import data_processor
import ot_cleaner
import datacleaner
import model_trainer

# ── Config ───────────────────────────────────────────────────────────────────
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL    = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_URL     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

STATE_FILE = os.path.join(DATASET_FOLDER, "pipeline_state.json")
DOCKER_DIR = os.path.join(REPO_ROOT, "docker")

# Model last trained 2026-05-06 from a manual bulk download of unknown exact
# cutoff — this default is a deliberate safety buffer *before* that date.
# Overlap is free (dedup on cve_id absorbs re-fetched rows); a gap silently
# loses CVEs, so err early rather than exact.
DEFAULT_SINCE = "2026-04-01"

PKL_FILES = [
    "general_vectorizer.pkl", "general_matrix.pkl", "cve_database.pkl",
    "ot_vectorizer.pkl", "ot_matrix.pkl", "ot_cve_database.pkl",
]

SANITY_DROP_TOLERANCE = 0.05  # abort if row count drops more than 5%
# ─────────────────────────────────────────────────────────────────────────────


def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state):
    os.makedirs(DATASET_FOLDER, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def _fmt(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def _get_with_retries(params, headers, attempts=4):
    """NVD's public (unauthenticated) tier is occasionally slow/flaky —
    for an unattended weekly job, a transient timeout shouldn't fail the
    whole run. Retries with growing backoff before giving up for real."""
    last_exc = None
    for attempt in range(1, attempts + 1):
        try:
            resp = requests.get(NVD_API_URL, params=params, headers=headers,
                                 timeout=(10, 90))
            resp.raise_for_status()
            return resp.json()
        except (requests.exceptions.RequestException, ValueError) as e:
            last_exc = e
            if attempt < attempts:
                backoff = 5 * attempt
                print(f"    [retry {attempt}/{attempts}] {e} — retrying in {backoff}s...")
                time.sleep(backoff)
    raise last_exc


def _fetch_nvd_window(start_iso, end_iso, api_key, sleep_s):
    """One <=120-day window, paginated."""
    items = []
    start_index = 0
    # Smaller pages than NVD's 2000 max — a huge page (all CVEs modified
    # globally, not just OT, across a multi-month window) risks a read
    # timeout even with a generous timeout; more, smaller requests are
    # more reliable than fewer, larger ones for an unattended job.
    results_per_page = 500
    headers = {"apiKey": api_key} if api_key else {}
    while True:
        params = {
            "lastModStartDate": start_iso,
            "lastModEndDate": end_iso,
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }
        data = _get_with_retries(params, headers)
        vulns = data.get("vulnerabilities", [])
        items.extend(vulns)
        total = data.get("totalResults", 0)
        start_index += results_per_page
        print(f"    ...{min(start_index, total)}/{total}")
        if start_index >= total:
            break
        time.sleep(sleep_s)
    return items


def fetch_nvd_deltas(since_dt, until_dt, api_key):
    """NVD caps lastModStartDate/EndDate ranges at 120 days per request —
    chunk into <=119-day windows so a long-overdue run still works."""
    sleep_s = 0.7 if api_key else 6.5
    all_items = []
    cur = since_dt
    while cur < until_dt:
        nxt = min(cur + timedelta(days=119), until_dt)
        print(f"  Fetching NVD window {_fmt(cur)} -> {_fmt(nxt)} ...")
        items = _fetch_nvd_window(_fmt(cur), _fmt(nxt), api_key, sleep_s)
        print(f"    {len(items)} raw results")
        all_items.extend(items)
        cur = nxt
        if cur < until_dt:
            time.sleep(sleep_s)
    return all_items


def _download(url, dest):
    resp = requests.get(url, timeout=60, allow_redirects=True)
    resp.raise_for_status()
    with open(dest, "wb") as f:
        f.write(resp.content)
    print(f"  Downloaded {os.path.basename(dest)} ({len(resp.content):,} bytes)")


def refresh_epss_kev():
    print("\nRefreshing EPSS + CISA KEV (full snapshots, not incremental)...")
    os.makedirs(DATASET_FOLDER, exist_ok=True)
    _download(EPSS_URL, os.path.join(DATASET_FOLDER, data_processor.EPSS_FILE))
    _download(KEV_URL, os.path.join(DATASET_FOLDER, data_processor.KEV_FILE))
    epss_dict = data_processor.parse_epss(DATASET_FOLDER)
    kev_ids   = data_processor.parse_kev(DATASET_FOLDER)
    return epss_dict, kev_ids


def _row_count(path):
    if not os.path.exists(path):
        return 0
    return len(pd.read_csv(path))


def load_baseline():
    """processed_cves.csv is the ideal baseline (pre-clean, nothing lost).
    On this repo it doesn't exist yet — only the already-cleaned
    training_ready.csv does (from the original manual run) — so fall back
    to that. Both share the exact same 15-column schema."""
    primary  = os.path.join(DATASET_FOLDER, "processed_cves.csv")
    fallback = os.path.join(DATASET_FOLDER, "training_ready.csv")
    if os.path.exists(primary):
        print(f"  Baseline: {primary}")
        return pd.read_csv(primary)
    if os.path.exists(fallback):
        print(f"  processed_cves.csv not found — using training_ready.csv as baseline")
        return pd.read_csv(fallback)
    print("  No existing dataset found — starting from empty baseline")
    return pd.DataFrame(columns=[
        "cve_id", "vendor", "product", "version_start", "version_end",
        "cvss", "epss", "kev", "c_impact", "i_impact", "a_impact",
        "attack_vector", "complexity", "is_ot", "description",
    ])


def backup_model():
    if not any(os.path.exists(os.path.join(MODEL_FOLDER, f)) for f in PKL_FILES):
        return
    backup_dir = os.path.join(MODEL_FOLDER, ".backup")
    os.makedirs(backup_dir, exist_ok=True)
    for fname in PKL_FILES:
        src = os.path.join(MODEL_FOLDER, fname)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(backup_dir, fname))
    print(f"  Backed up previous model -> {backup_dir}")


def _docker_daemon_ready():
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
        return result.returncode == 0
    except Exception:
        return False


def _find_docker_desktop_exe():
    for path in (
        os.path.expandvars(r"%ProgramFiles%\Docker\Docker\Docker Desktop.exe"),
        os.path.expandvars(r"%LocalAppData%\Docker\Docker Desktop.exe"),
        r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
    ):
        if os.path.isfile(path):
            return path
    return None


def redeploy_docker():
    """Rebuild + restart the engine so the freshly-trained model actually
    goes live, launching Docker Desktop first if it isn't already running
    (same pattern as the dashboard's "Start passive scan" button)."""
    print("\n[7/7] Redeploying Docker...")
    if not _docker_daemon_ready():
        exe = _find_docker_desktop_exe()
        if exe:
            print("  Docker Desktop not running — launching it...")
            try:
                subprocess.Popen([exe], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                print(f"  [!] Could not launch Docker Desktop: {e}")
        else:
            print("  [!] Docker Desktop not found — skipping redeploy.")
            return
        print("  Waiting for Docker daemon...")
        deadline = time.time() + 150
        while time.time() < deadline:
            if _docker_daemon_ready():
                break
            time.sleep(3)
        else:
            print("  [!] Docker daemon never came up (150s) — skipping redeploy. "
                  "Run 'docker compose up -d --build' manually once it's up.")
            return

    result = subprocess.run(["docker", "compose", "up", "-d", "--build"], cwd=DOCKER_DIR)
    if result.returncode == 0:
        print("  Docker redeployed — new model is live.")
    else:
        print("  [!] Docker redeploy failed (see output above) — "
              "run 'docker compose up -d --build' manually.")


def run(since_override=None, dry_run=False):
    print("=" * 60)
    print("  CAVE-OT CVE MODEL UPDATE")
    print("=" * 60)
    print(f"  Dataset folder: {DATASET_FOLDER}")
    print(f"  Model folder:   {MODEL_FOLDER}")

    state = load_state()
    if since_override:
        since_dt = datetime.strptime(since_override, "%Y-%m-%d")
    elif state.get("last_nvd_lastmod_end"):
        since_dt = datetime.strptime(state["last_nvd_lastmod_end"][:19], "%Y-%m-%dT%H:%M:%S")
    else:
        since_dt = datetime.strptime(DEFAULT_SINCE, "%Y-%m-%d")
    until_dt = _utcnow() - timedelta(minutes=5)

    print(f"\n  Fetch window: {_fmt(since_dt)}  ->  {_fmt(until_dt)}")
    if since_dt >= until_dt:
        print("  Nothing to do (since >= now). Exiting.")
        return

    api_key = os.environ.get("NVD_API_KEY")
    print(f"  NVD_API_KEY: {'set (higher rate limit)' if api_key else 'not set (public rate limit)'}")

    print("\n[1/7] Fetching NVD deltas...")
    raw_items = fetch_nvd_deltas(since_dt, until_dt, api_key)
    new_rows = [r for r in (data_processor.parse_nvd_item(item) for item in raw_items) if r]
    print(f"  {len(raw_items)} raw NVD items -> {len(new_rows)} valid rows (had a CVSS score)")

    if dry_run:
        print("\n[dry-run] Stopping before any writes.")
        return

    print("\n[2/7] Loading baseline + merging...")
    old_df = load_baseline()
    before_general = len(old_df)
    before_training_general = _row_count(os.path.join(DATASET_FOLDER, "training_ready.csv"))
    before_training_ot       = _row_count(os.path.join(DATASET_FOLDER, "ot_training_ready.csv"))

    new_df = pd.DataFrame(new_rows) if new_rows else pd.DataFrame(columns=old_df.columns)
    combined = pd.concat([old_df, new_df], ignore_index=True)
    combined = combined.drop_duplicates(subset="cve_id", keep="last")
    print(f"  Combined: {before_general} old + {len(new_df)} new -> {len(combined)} unique CVEs")

    epss_dict, kev_ids = refresh_epss_kev()
    combined["epss"] = combined["cve_id"].map(epss_dict).fillna(0.0)
    combined["kev"]  = combined["cve_id"].apply(lambda c: 1 if c in kev_ids else 0)

    print("\n[3/7] Re-running existing cleaning pipeline (unmodified) on the merged set...")
    data_processor.clean_and_save(combined, DATASET_FOLDER)
    ot_cleaner.clean(DATASET_FOLDER)
    datacleaner.main()

    after_training_general = _row_count(os.path.join(DATASET_FOLDER, "training_ready.csv"))
    after_training_ot       = _row_count(os.path.join(DATASET_FOLDER, "ot_training_ready.csv"))

    print("\n[4/7] Sanity check...")
    if before_training_general > 0 and after_training_general < before_training_general * (1 - SANITY_DROP_TOLERANCE):
        print(f"  [ABORT] general training set dropped {before_training_general} -> {after_training_general} "
              f"(>{SANITY_DROP_TOLERANCE:.0%}). Not retraining. State NOT advanced.")
        return
    if before_training_ot > 0 and after_training_ot < before_training_ot * (1 - SANITY_DROP_TOLERANCE):
        print(f"  [ABORT] OT training set dropped {before_training_ot} -> {after_training_ot} "
              f"(>{SANITY_DROP_TOLERANCE:.0%}). Not retraining. State NOT advanced.")
        return
    print(f"  general: {before_training_general} -> {after_training_general}   "
          f"OT: {before_training_ot} -> {after_training_ot}   OK")

    print("\n[5/7] Retraining model...")
    backup_model()
    model_trainer.main()

    print("\n[6/7] Advancing state...")
    save_state({
        "last_success_utc": _utcnow().isoformat(),
        "last_nvd_lastmod_end": _fmt(until_dt),
        "general_rows": after_training_general,
        "ot_rows": after_training_ot,
    })

    redeploy_docker()

    print("\n" + "=" * 60)
    print("  DONE")
    print("=" * 60)
    print(f"  New model files are in {MODEL_FOLDER}")


def main():
    parser = argparse.ArgumentParser(description="Fetch new/changed CVEs and retrain the CAVE-OT model.")
    parser.add_argument("--dry-run", action="store_true", help="Fetch and report only, no writes.")
    parser.add_argument("--since", metavar="YYYY-MM-DD", help="Override the fetch window start.")
    args = parser.parse_args()
    run(since_override=args.since, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
