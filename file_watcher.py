"""
CAVE-OT File Watcher
====================
Watches the Assets folder for changes to JSON files produced by the Ubuntu VM pipeline.
When any file changes, automatically runs sync_db.py to update PostgreSQL.

Run permanently on Windows:
    python file_watcher.py

Requires: pip install watchdog
"""

import time
import os
import sys
import subprocess
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────────────────

# Docker testbed's bind-mounted shared folder (docker/shared/, relative to
# this file's own location so it works regardless of where the repo is
# cloned). If you're running the VM instead of Docker, point this at your
# VMware shared folder path instead.
WATCH_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docker", "shared")

# Files that trigger a DB sync when changed
TRIGGER_FILES = {
    "assets.json",
    "vulnerability_scan_results.json",
    "risk_scored_results.json",
    "suricata_context.json",
    "attack_paths.json",
}

SESSION_FILE = "session_start.json"  # written by cave_monitor on startup → triggers DB wipe

# Minimum seconds between syncs (debounce — avoid hammering DB on rapid writes)
DEBOUNCE_SECONDS = 5

SYNC_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Database", "sync_db.py")

# ── Watcher ───────────────────────────────────────────────────────────────────

def log(msg, color=""):
    ts = datetime.now().strftime("%H:%M:%S")
    colors = {"green": "\033[92m", "yellow": "\033[93m", "red": "\033[91m", "": ""}
    reset  = "\033[0m" if color else ""
    print(f"[{ts}] {colors.get(color,'')}{msg}{reset}", flush=True)


def run_sync(wipe=False, reset=False):
    flag = '--wipe' if wipe else ('--reset' if reset else '')
    log(f"Running sync_db.py {flag}...", "yellow")
    cmd = [sys.executable, SYNC_SCRIPT]
    if wipe:
        cmd.append("--wipe")
    elif reset:
        cmd.append("--reset")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            if "Assets synced" in line or "CVEs synced" in line or "Done" in line or "skipping" in line:
                log(f"  {line.strip()}", "green")
        log("DB sync complete", "green")
    else:
        log(f"sync_db.py failed (rc={result.returncode})", "red")
        if result.stderr:
            for line in result.stderr.splitlines()[:5]:
                log(f"  {line}", "red")


def watch_polling():
    """
    Simple polling watcher — no external dependencies.
    Checks file mtimes every 3 seconds.
    """
    log(f"Watching: {WATCH_DIR}")
    log(f"Triggers: {', '.join(sorted(TRIGGER_FILES))}")
    log("Press Ctrl+C to stop\n")

    last_mtimes = {}
    last_sync   = 0

    # sync on startup without wiping — DB keeps data between watcher restarts
    # wipe only happens when VM sends session_start.json
    log("Initial sync on startup...", "yellow")
    run_sync()
    last_sync = time.time()

    while True:
        try:
            changed = False
            for fname in TRIGGER_FILES:
                fpath = os.path.join(WATCH_DIR, fname)
                if not os.path.exists(fpath):
                    continue
                mtime = os.path.getmtime(fpath)
                if last_mtimes.get(fname) != mtime:
                    if fname in last_mtimes:
                        log(f"Changed: {fname}", "yellow")
                        changed = True
                    last_mtimes[fname] = mtime

            # check for session_start.json — VM restarted, wipe DB
            session_path = os.path.join(WATCH_DIR, SESSION_FILE)
            if os.path.exists(session_path):
                smtime = os.path.getmtime(session_path)
                if last_mtimes.get(SESSION_FILE) != smtime:
                    if SESSION_FILE in last_mtimes:
                        log("VM session started — resetting asset statuses...", "yellow")
                        run_sync(reset=True)
                        last_sync = time.time()
                        changed = False
                    last_mtimes[SESSION_FILE] = smtime

            if changed:
                now = time.time()
                if now - last_sync >= DEBOUNCE_SECONDS:
                    run_sync()
                    last_sync = now
                else:
                    remaining = int(DEBOUNCE_SECONDS - (now - last_sync))
                    log(f"Debouncing — next sync in {remaining}s")

        except KeyboardInterrupt:
            log("\nStopped.", "yellow")
            break
        except Exception as e:
            log(f"Watcher error: {e}", "red")

        time.sleep(2)


def watch_watchdog():
    """
    Watchdog-based watcher — more efficient, event-driven.
    Used if watchdog package is installed.
    """
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler

    last_sync = [time.time()]

    class Handler(FileSystemEventHandler):
        def on_modified(self, event):
            if event.is_directory:
                return
            fname = os.path.basename(event.src_path)
            if fname not in TRIGGER_FILES:
                return
            now = time.time()
            if now - last_sync[0] >= DEBOUNCE_SECONDS:
                log(f"Changed: {fname}", "yellow")
                run_sync()
                last_sync[0] = now
            else:
                remaining = int(DEBOUNCE_SECONDS - (now - last_sync[0]))
                log(f"Changed: {fname} — debouncing ({remaining}s)")

        on_created = on_modified

    log(f"Watching: {WATCH_DIR}  [watchdog mode]")
    log(f"Triggers: {', '.join(sorted(TRIGGER_FILES))}")
    log("Press Ctrl+C to stop\n")

    log("Initial sync on startup...", "yellow")
    run_sync()

    observer = Observer()
    observer.schedule(Handler(), WATCH_DIR, recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        log("\nStopped.", "yellow")
    observer.join()


if __name__ == "__main__":
    # use watchdog if available, fall back to polling
    try:
        import watchdog
        watch_watchdog()
    except ImportError:
        log("watchdog not installed — using polling mode (pip install watchdog for better performance)")
        watch_polling()
