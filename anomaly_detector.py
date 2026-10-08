"""
CAVE-OT Anomaly Detector
========================
CVE matching (cve_discovery.py) can only ever find *known, named*
vulnerabilities — it's a lookup against a fixed CVE corpus. This script is
the other half: it learns each device's normal traffic pattern over time
(packet volume, talker count, average packet size) and flags a cycle where
a device's behavior looks statistically unusual, even when nothing matches
a CVE. Feeds into cave_monitor.py's risk formula as anomaly_score.

Runs automatically after smart_discover.py generates assets.json.
"""

import json
import os
import numpy as np
from sklearn.ensemble import IsolationForest

# ── Config ───────────────────────────────────────────────────────────────────
from pipeline_paths import ENGINE_FOLDER
from snapshot_io import atomic_json
CAVE_DIR     = ENGINE_FOLDER
ASSETS_FILE  = os.path.join(CAVE_DIR, "assets.json")
HISTORY_FILE = os.path.join(CAVE_DIR, "anomaly_history.json")
OUTPUT_FILE  = os.path.join(CAVE_DIR, "anomaly_results.json")

WINDOW_SIZE = 30   # cycles of history kept per device (~5 min at 10s/cycle)
MIN_SAMPLES = 8    # cycles needed before a baseline is trusted (~80s warm-up)

# IsolationForest's contamination setting forces it to always call ~10% of
# ANY window "outliers", even when nothing is actually wrong — with only a
# handful of samples and small, jittery counts, that alone was enough to
# flip the ANOMALOUS badge on/off almost every cycle for no real reason.
# Requiring the model to flag a device on CONSECUTIVE cycles before the
# badge actually lights up is what kills that flicker — one noisy blip no
# longer counts, only a sustained pattern does.
CONTAMINATION     = 0.10
STREAK_TO_CONFIRM = 2

FEATURE_LABELS = ["packet volume", "unique talkers", "avg packet size"]
# ─────────────────────────────────────────────────────────────────────────────


def load_assets():
    if not os.path.exists(ASSETS_FILE):
        return []
    with open(ASSETS_FILE, "r") as f:
        return json.load(f)


def load_state():
    if not os.path.exists(HISTORY_FILE):
        return {"windows": {}, "streaks": {}}
    try:
        with open(HISTORY_FILE, "r") as f:
            state = json.load(f)
        state.setdefault("windows", {})
        state.setdefault("streaks", {})
        return state
    except Exception:
        return {"windows": {}, "streaks": {}}


def save_state(state):
    with open(HISTORY_FILE, "w") as f:
        json.dump(state, f)


def feature_vector(asset):
    return [
        float(asset.get("packet_count", 0)),
        float(len(asset.get("talkers", []))),
        float(asset.get("avg_packet_size", 0.0)),
    ]


def describe_reason(vector, mean):
    diffs = [abs(vector[i] - mean[i]) / (mean[i] + 1e-6) for i in range(len(vector))]
    worst = diffs.index(max(diffs))
    baseline = mean[worst]
    if baseline <= 0:
        return f"unusual {FEATURE_LABELS[worst]}"
    ratio = vector[worst] / baseline
    return f"{FEATURE_LABELS[worst]} {ratio:.1f}x normal"


def run():
    assets  = load_assets()
    state   = load_state()
    windows = state["windows"]
    streaks = state["streaks"]
    results = []

    for asset in assets:
        key    = f"{asset.get('ip')}:{asset.get('port')}"
        vector = feature_vector(asset)

        window = windows.get(key, [])


        base = {
            "ip": asset.get("ip"), "port": asset.get("port"),
            "device_type": asset.get("device_type"),
            "samples_seen": len(window),
        }

        if len(window) < MIN_SAMPLES:
            window.append(vector)
            windows[key] = window[-WINDOW_SIZE:]
            streaks[key] = 0
            results.append({
                **base, "anomaly_score": 0.0, "is_anomalous": False,
                "reason": "learning baseline",
            })
            continue

        X = np.array(window)
        model = IsolationForest(n_estimators=50, contamination=CONTAMINATION, random_state=42)
        model.fit(X)

        raw_score  = float(model.decision_function([vector])[0])  # higher = more normal
        is_outlier = bool(model.predict([vector])[0] == -1)
        # A constant baseline gives IsolationForest no split boundaries: even
        # a large new spike may score as normal. Use a bounded deviation guard
        # against the prior baseline, independent of the current sample.
        mean = X.mean(axis=0)
        scale = np.maximum(X.std(axis=0), np.maximum(np.abs(mean)*.25, 1.0))
        deviation = float(np.max(np.abs(np.asarray(vector)-mean)/scale))
        is_outlier = is_outlier or deviation > 4.0
        # decision_function is roughly centered on 0 (~-0.5..0.5); map that
        # onto a 0-1 "suspicion" score for display/scoring purposes.
        suspicion = max(0.0, min(1.0, max(-raw_score*4.0,(deviation-4.0)/8.0))) if is_outlier else 0.0

        streaks[key] = streaks.get(key, 0) + 1 if is_outlier else 0
        confirmed = streaks[key] >= STREAK_TO_CONFIRM

        if not is_outlier:
            windows[key] = (window + [vector])[-WINDOW_SIZE:]
        mean = X.mean(axis=0)
        if is_outlier:
            reason = describe_reason(vector, mean)
            if not confirmed:
                reason += f" (confirming, {streaks[key]}/{STREAK_TO_CONFIRM})"
        else:
            reason = "normal"

        results.append({
            **base,
            "anomaly_score": round(suspicion, 3),
            "is_anomalous":  confirmed,
            "reason":        reason,
        })

    save_state({"windows": windows, "streaks": streaks})
    atomic_json(OUTPUT_FILE, results)

    print(f"[+] anomaly_results.json saved -> {len(results)} devices")
    for r in results:
        flag = "ANOMALOUS" if r["is_anomalous"] else "normal"
        print(f"  {r['device_type']:<24} score={r['anomaly_score']:.2f}  {flag}  ({r['reason']})")


if __name__ == "__main__":
    run()
