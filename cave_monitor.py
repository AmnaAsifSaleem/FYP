import socket, struct, subprocess, threading
import time, random, os, re, json, sys, shutil
from datetime import datetime

SHARED_DIR = os.environ.get("CAVE_OT_SHARED_DIR","/mnt/hgfs/shared folder")

def sync_to_shared(*filenames):
    if not os.path.isdir(SHARED_DIR):
        return
    for fname in filenames:
        src = os.path.join(CAVE_DIR, fname)
        dst = os.path.join(SHARED_DIR, fname)
        if os.path.exists(src):
            try:
                shutil.copy2(src, dst)
            except Exception as e:
                print(f"[sync] Failed to copy {fname}: {e}", flush=True)

try:
    import joblib
    _JOBLIB_OK = True
except ImportError:
    _JOBLIB_OK = False

_RISK_TIERS   = [(9.0,"CRITICAL"),(7.0,"HIGH"),(4.0,"MEDIUM"),(0.0,"LOW")]
_SEV_WEIGHT   = {1:1.00, 2:0.60, 3:0.30}
_MODEL_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model")

def build_cia_lookup():
    lookup = {}
    if not _JOBLIB_OK:
        return lookup
    for fname in ("cve_database.pkl", "ot_cve_database.pkl"):
        path = os.path.join(_MODEL_FOLDER, fname)
        if not os.path.exists(path):
            continue
        try:
            db = joblib.load(path)
            for _, row in db.iterrows():
                lookup[row["cve_id"]] = (float(row["c_impact"]), float(row["i_impact"]), float(row["a_impact"]))
        except Exception as e:
            print(f"[CIA LOOKUP] Failed to load {fname}: {e}", flush=True)
    return lookup



from contextual_risk import score_cve, score_details, get_risk_tier, VERSION
from ids_context import risk_context

R   = '\033[0;31m'
G   = '\033[0;32m'
Y   = '\033[1;33m'
B   = '\033[0;34m'
C   = '\033[0;36m'
M   = '\033[0;35m'
W   = '\033[1;37m'
DIM = '\033[2m'
NC  = '\033[0m'
BOLD= '\033[1m'

from pipeline_paths import ENGINE_FOLDER
CAVE_DIR = ENGINE_FOLDER
WIDTH    = 78

DEVICES = {
    "Dosing_Pump_PLC":        {"port": 502,   "proto": "modbus", "zone": "OT", "delay": 0,  "container": "conpot"},
    "Filtration_PLC":         {"port": 10201, "proto": "s7",     "zone": "OT", "delay": 0,  "container": "conpot"},
    "Ventilation_Controller": {"port": 47808, "proto": "bacnet", "zone": "OT", "delay": 0,  "container": "conpot"},
    "Water_Level_RTU":        {"port": 20000, "proto": "dnp3",   "zone": "OT", "delay": 0,  "container": "conpot"},
    "WaterQuality_Sensor":    {"port": 5020,  "proto": "modbus", "zone": "OT", "delay": 0,  "container": "conpot"},
    "SCADA_Server":           {"port": 6230,  "proto": "tcp",    "zone": "IT", "delay": 0,  "container": "conpot"},
    "HMI_Interface":          {"port": 80,    "proto": "http",   "zone": "IT", "delay": 0,  "container": "conpot"},
    "Turbidity_Sensor_PLC":   {"port": 5031,  "proto": "modbus", "zone": "OT", "delay": 0,  "container": "conpot_turbidity"},
    "UV_Disinfection_PLC":    {"port": 5032,  "proto": "modbus", "zone": "OT", "delay": 0,  "container": "conpot_uv"},
    "Flow_Meter_RTU":         {"port": 20001, "proto": "dnp3",   "zone": "OT", "delay": 0,  "container": "conpot_flowmeter"},
    "Backup_HMI_Interface":   {"port": 8080,  "proto": "http",   "zone": "IT", "delay": 0,  "container": "conpot_backup_hmi"},
    "Historian":              {"port": 443,   "proto": "http",   "zone": "IT", "delay": 0,  "container": "conpot_historian"},
    "Engineering_WS":         {"port": 2222,  "proto": "tcp",    "zone": "IT", "delay": 0,  "container": "conpot_engineering_ws"},
    "Reservoir_Level_PLC":    {"port": 10203, "proto": "s7",     "zone": "OT", "delay": 7,  "container": "conpot_reservior"},
    "Booster_Pump_PLC":       {"port": 10204, "proto": "s7",     "zone": "OT", "delay": 10, "container": "conpot_booster"},
}
DEVICE_NAMES = list(DEVICES.keys())

MODBUS = struct.pack(">HHHBBHH", 0x0001, 0x0000, 0x0006, 0x01, 0x03, 0x0000, 0x000A)
S7     = bytes([0x03,0x00,0x00,0x16,0x11,0xe0,0x00,0x00,0x00,0x01,0x00,0xc0,0x01,0x0a,0xc1,0x02,0x01,0x00,0xc2,0x02,0x01,0x02])
DNP3   = bytes([0x05,0x64,0x14,0x44,0x01,0x00,0x03,0x00,0xe9,0x21,0xc0,0x01,0x01,0x3c,0x02,0x06,0x3c,0x01,0x06])
HTTP   = b"GET /status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
BACNET = bytes([0x81,0x0b,0x00,0x0c,0x01,0x20,0xff,0xff,0x00,0xff,0x10,0x08])

status            = {n: "WAITING" for n in DEVICE_NAMES}
comms_log         = []
alerts_log        = []
events_log        = []
cve_log           = []
cycle_num         = 0
start_time        = time.time()
lock              = threading.Lock()
_cia_lookup       = {}

# ── Discovery lock — use a proper lock instead of a bool flag ────────────────
# This prevents the race where pcap_loop and start_delayed both try to
# run discovery simultaneously and one silently drops out.
_discovery_lock = threading.Lock()

sensor_vals = {
    "water_level":   75.0,
    "turbidity":     2.5,
    "chlorine":      1.2,
    "ph":            7.2,
    "flow_rate":     850.0,
    "reservoir_pct": 68.0,
    "pressure":      3.2,
}

# ── Network helpers ──────────────────────────────────────────────────────────

def send_pkt(name):
    d = DEVICES[name]
    try:
        if d["proto"] == "bacnet":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.sendto(BACNET, ("127.0.0.1", d["port"]))
            s.close()
        else:
            pkt = {"modbus": MODBUS, "s7": S7, "dnp3": DNP3,
                   "http": HTTP, "tcp": MODBUS}[d["proto"]]
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(("127.0.0.1", d["port"]))
            s.send(pkt)
            try: s.recv(256)
            except: pass
            s.close()
        return True
    except:
        return False


def log_comm(src, dst, msg, ok):
    ts  = datetime.now().strftime("%H:%M:%S")
    col = G if ok else R
    sym = ">>>" if ok else "---"
    entry = f"{DIM}{ts}{NC} {col}{sym}{NC} {src[:18]:<18}->{dst[:18]:<18} {DIM}{msg[:14]}{NC}"
    with lock:
        comms_log.append(entry)
        if len(comms_log) > 6:
            comms_log.pop(0)


def log_event(msg, color=Y):
    ts = datetime.now().strftime("%H:%M:%S")
    with lock:
        events_log.append(f"{DIM}{ts}{NC} {color}{msg[:65]}{NC}")
        if len(events_log) > 4:
            events_log.pop(0)


# ── Sensor simulation ────────────────────────────────────────────────────────

def update_sensors():
    sensor_vals["water_level"]   = max(10,  min(100, sensor_vals["water_level"]   + random.uniform(-1.5, 1.5)))
    sensor_vals["turbidity"]     = max(0.1, min(10,  sensor_vals["turbidity"]     + random.uniform(-0.2, 0.2)))
    sensor_vals["chlorine"]      = max(0.1, min(5,   sensor_vals["chlorine"]      + random.uniform(-0.1, 0.1)))
    sensor_vals["ph"]            = max(6.0, min(9.0, sensor_vals["ph"]            + random.uniform(-0.05, 0.05)))
    sensor_vals["flow_rate"]     = max(100, min(1500,sensor_vals["flow_rate"]     + random.uniform(-20, 20)))
    sensor_vals["reservoir_pct"] = max(10,  min(100, sensor_vals["reservoir_pct"] + random.uniform(-1, 1)))
    sensor_vals["pressure"]      = max(0.5, min(10,  sensor_vals["pressure"]      + random.uniform(-0.1, 0.1)))


# ── Comm cycle ───────────────────────────────────────────────────────────────

def comm_cycle():
    global cycle_num
    while True:
        cycle_num += 1
        update_sensors()
        sv = sensor_vals
        comms = [
            ("Water_Level_RTU",       "SCADA_Server",          f"level={sv['water_level']:.1f}%"),
            ("Turbidity_Sensor_PLC",  "UV_Disinfection_PLC",   f"NTU={sv['turbidity']:.2f}"),
            ("WaterQuality_Sensor",   "Dosing_Pump_PLC",       f"Cl={sv['chlorine']:.2f}mg/L"),
            ("Flow_Meter_RTU",        "Filtration_PLC",        f"flow={sv['flow_rate']:.0f}L/m"),
            ("Reservoir_Level_PLC",   "Booster_Pump_PLC",      f"res={sv['reservoir_pct']:.1f}%"),
            ("Ventilation_Controller","SCADA_Server",           "vent=OK"),
            ("SCADA_Server",          "HMI_Interface",          "dashboard"),
            ("SCADA_Server",          "Backup_HMI_Interface",   "dashboard"),
            ("Filtration_PLC",        "WaterQuality_Sensor",    "req quality"),
            ("Dosing_Pump_PLC",       "Water_Level_RTU",        "confirm level"),
            ("UV_Disinfection_PLC",   "Turbidity_Sensor_PLC",   "confirm NTU"),
            ("Booster_Pump_PLC",      "Flow_Meter_RTU",         "confirm flow"),
            ("Historian",             "SCADA_Server",            "data archive"),
            ("Engineering_WS",        "SCADA_Server",            "eng access"),
            ("SCADA_Server",          "Historian",               "log data"),
            ("SCADA_Server",          "Engineering_WS",          "status push"),
        ]
        for src, dst, msg in comms:
            if status[src] == "ONLINE" and status[dst] == "ONLINE":
                ok = send_pkt(dst)
                log_comm(src, dst, msg, ok)
            else:
                log_comm(src, dst, msg, False)
            time.sleep(0.2)
        time.sleep(4)


# ── Suricata alert reader ────────────────────────────────────────────────────

def read_alerts():
    seen        = set()
    known_ports = set(d["port"] for d in DEVICES.values())
    while True:
        try:
            with open("/var/log/suricata/fast.log") as f:
                lines = f.readlines()
            new_alerts = []
            for line in lines:
                if line in seen:
                    continue
                seen.add(line)
                m_msg  = re.search(r'\[\*\*\] \[.*?\] (.+?) \[\*\*\]', line)
                m_port = re.search(r'-> [\d\.]+:(\d+)', line)
                if not m_msg or not m_port:
                    continue
                msg  = m_msg.group(1).strip()
                port = int(m_port.group(1))
                col  = R if ("Attack" in msg or "Rapid" in msg or "Brute" in msg) else Y
                new_alerts.append(f"{col}{msg[:68]}{NC}")
                if port not in known_ports:
                    known_ports.add(port)
                    log_event(f"NEW ASSET on port {port} — discovery triggered", R)
                    threading.Thread(target=run_discovery, daemon=True).start()
            with lock:
                alerts_log.extend(new_alerts)
                if len(alerts_log) > 5:
                    alerts_log[:] = alerts_log[-5:]
        except Exception as e:
            pass
        time.sleep(2)

# ── PCAP capture helper ──────────────────────────────────────────────────────

def capture_pcap(warm_up_ports=None):
    """
    Capture 200 packets on loopback.
    If warm_up_ports is given, send traffic to those ports BEFORE starting
    tcpdump so they are guaranteed to appear in the capture.
    Also sends traffic to all currently-ONLINE devices during the capture.
    """
    pcap_file = f"{CAVE_DIR}/test_all.pcap"

    # Pre-warm: send to any ports that need to be visible (delayed assets)
    if warm_up_ports:
        log_event(f"Pre-warming ports {warm_up_ports} before capture...", C)
        for port in warm_up_ports:
            for name, d in DEVICES.items():
                if d["port"] == port:
                    for _ in range(5):
                        send_pkt(name)
                        time.sleep(0.1)

    log_event("tcpdump capturing 200 packets...", DIM)
    proc = subprocess.Popen(
        ["sudo", "tcpdump", "-i", "lo", "-w", pcap_file, "-c", "200"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    # Keep sending traffic to all online devices while tcpdump is running
    # so the pcap always has a full picture
    deadline = time.time() + 30  # safety timeout
    while proc.poll() is None and time.time() < deadline:
        for name in DEVICE_NAMES:
            if status[name] == "ONLINE":
                send_pkt(name)
        time.sleep(0.5)

    if proc.poll() is None:
        import signal
        proc.send_signal(signal.SIGINT)
        try:proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill();proc.wait(timeout=5)
    if not os.path.exists(pcap_file) or os.path.getsize(pcap_file)<=24:
        log_event('Capture produced no packets; preserving last valid snapshot',R)
        return False
    log_event("Capture done", G)
    return True


# ── Risk scoring ─────────────────────────────────────────────────────────────

TIER_COLOR = {"CRITICAL": R, "HIGH": Y, "MEDIUM": C, "LOW": G}

def _load_port_lookup(filename):
    """Load a shared/*.json list-of-devices file into a dict keyed by port."""
    path = os.path.join(CAVE_DIR, filename)
    lookup = {}
    try:
        with open(path) as f:
            for entry in json.load(f):
                lookup[(entry.get("ip"),entry.get("port"))] = entry
    except Exception:
        pass
    return lookup


def _score_and_display(results_file):
    global _cia_lookup
    try:
        with open(results_file) as f:
            data = json.load(f)
    except Exception as e:
        log_event(f"Risk score read error: {e}", R)
        return

    # assets.json (what vulnerability_scan_results.json's "device" objects
    # come from) never carries alert_count/alert_severity/anomaly_score
    # itself — those live in suricata_context.json / anomaly_results.json,
    # keyed by port. Load and join them here rather than reading them off
    # `device` directly (device.get("alert_count", 0) was always 0 before
    # this fix, since that key was never actually present).
    suricata_lookup = _load_port_lookup("suricata_context.json")
    anomaly_lookup   = _load_port_lookup("anomaly_results.json")

    scored_output = {"devices": []}

    for entry in data.get("devices", []):
        try:
            device      = entry.get("device", {})
            cves_raw    = entry.get("cves", [])
            vendor      = device.get("vendor", "?")
            product     = device.get("product", "?")
            criticality = device.get("criticality", 0.30)
            device_type = device.get("device_type", "Generic")
            ip          = device.get("ip", "?")
            port        = device.get("port")

            suri          = suricata_lookup.get((ip,port), {})
            context       = risk_context(suri.get('alert_events',[]))
            alert_count   = context['risk_alert_count']
            alert_sev     = context['risk_alert_severity']

            anomaly         = anomaly_lookup.get((ip,port), {})
            anomaly_score   = anomaly.get("anomaly_score", 0.0) if anomaly.get("is_anomalous") else 0.0
            is_anomalous    = anomaly.get("is_anomalous", False)
            anomaly_reason  = anomaly.get("reason", "")

            scored_cves = []
            for cve in cves_raw:
                details=score_details(cve,criticality,_cia_lookup,alert_count,alert_sev,anomaly_score,
                    weighted_alert_count=context['risk_alert_weighted_count'],
                    security_requirements=device.get('cvss_requirements'))
                scored_cves.append({
                    **cve,
                    **details,
                    "ids_window_seconds":context['alert_window_seconds'],
                })

            scored_cves.sort(key=lambda x: (x["priority_total"], x["epss"]), reverse=True)

            top_risk  = scored_cves[0]["risk_score"] if scored_cves else 0.0
            top_tier  = scored_cves[0]["risk_tier"]  if scored_cves else "LOW"
            top_epss  = scored_cves[0]["epss"]        if scored_cves else 0.0
            top_cve   = scored_cves[0]["cve_id"]      if scored_cves else "—"
            kev_count = sum(1 for c in scored_cves if c.get("kev") == 1)
            tcol      = TIER_COLOR.get(top_tier, DIM)
            kev_str   = f"{R}KEV:{kev_count}{NC}" if kev_count > 0 else f"{DIM}KEV:0{NC}"
            name_str  = f"{vendor} {product}"

            line = (
                f" {tcol}{name_str[:26]:<26}{NC} "
                f"{DIM}{ip:<15}{NC} "
                f"Risk:{tcol}{top_risk:>4.1f}{NC} "
                f"{tcol}{top_tier:<8}{NC} "
                f"EPSS:{DIM}{top_epss:.4f}{NC} "
                f"#{top_cve:<18} "
                f"CVEs:{len(scored_cves):>3}  {kev_str}"
            )

            with lock:
                replaced = False
                for idx, (key, _) in enumerate(cve_log):
                    if key == name_str:
                        cve_log[idx] = (name_str, line)
                        replaced = True
                        break
                if not replaced:
                    cve_log.append((name_str, line))
                if len(cve_log) > 15:
                    cve_log[:] = cve_log[-15:]

            log_event(f"Scored {device_type}: {top_risk} {top_tier}", tcol)

            scored_output["devices"].append({
                "ip": ip, "port": port, "device_type": device_type,
                "vendor": vendor, "product": product,
                "criticality": criticality,
                "score_version": VERSION,
                "cia_db_hits":  sum(1 for c in scored_cves if c["cia_source"] == "db"),
                "cia_unknown": sum(1 for c in scored_cves if c["cia_source"] == "unknown"),
                "anomaly_score": anomaly_score, "is_anomalous": is_anomalous,
                "anomaly_reason": anomaly_reason,
                "cves": scored_cves,
            })

        except Exception as e:
            log_event(f"Scoring error: {e}", R)
            return False

    out_path = os.path.join(CAVE_DIR, "risk_scored_results.json")
    try:
        from snapshot_io import atomic_json
        atomic_json(out_path,scored_output)
        sync_to_shared("risk_scored_results.json")
        log_event(f"risk_scored_results.json saved ({len(scored_output['devices'])} devices)", G)
        return True
    except Exception as e:
        log_event(f"Failed to save risk results: {e}", R)
        return False

# ── Discovery pipeline ───────────────────────────────────────────────────────

def run_discovery(warm_up_ports=None):
    """
    Full discovery cycle: capture pcap → smart_discover → CVE scan → risk score.

    warm_up_ports: list of ports to pre-warm before capture (delayed assets).
                   When set, this call takes priority and will WAIT for the
                   current discovery to finish rather than silently dropping out.
    """
    # If a delayed asset triggered this, wait for any in-progress discovery
    # to finish first, then run our own.  Regular pcap_loop calls skip if busy.
    if warm_up_ports:
        acquired = _discovery_lock.acquire(blocking=True, timeout=60)
    else:
        acquired = _discovery_lock.acquire(blocking=False)

    if not acquired:
        log_event("Discovery busy — skipping this cycle", DIM)
        return

    try:
        if capture_pcap(warm_up_ports=warm_up_ports) is False:return

        log_event("Running smart_discover.py...", C)
        os.chdir(CAVE_DIR)
        r = subprocess.run(
            [sys.executable, f"{CAVE_DIR}/smart_discover.py"],
            capture_output=True, text=True
        )
        if r.returncode != 0:
            log_event(f"smart_discover failed (rc={r.returncode})", R)
            return
            print(f"[smart_discover stderr]\n{r.stderr}", flush=True)
        else:
            log_event("assets.json + suricata_context.json updated", G)
        sync_to_shared("assets.json", "suricata_context.json")

        log_event("Running anomaly_detector.py...", C)
        r_anom = subprocess.run(
            ["python3", f"{CAVE_DIR}/anomaly_detector.py"],
            capture_output=True, text=True
        )
        if r_anom.returncode != 0:
            log_event(f"anomaly_detector failed (rc={r_anom.returncode})", R)
            return
            print(f"[anomaly_detector stderr]\n{r_anom.stderr}", flush=True)
        else:
            log_event("anomaly_results.json updated", G)
        sync_to_shared("anomaly_results.json")

        # Optional legacy risk scorer
        if os.path.exists(f"{CAVE_DIR}/risk_scorer.py") and \
           os.path.exists(f"{CAVE_DIR}/risk_model.pkl"):
            log_event("Running risk_scorer.py...", C)
            subprocess.run(["python3", f"{CAVE_DIR}/risk_scorer.py"],
                           capture_output=True, text=True)

        # CVE scan + risk scoring
        model_ready  = os.path.exists(f"{CAVE_DIR}/model/ot_vectorizer.pkl")
        assets_ready = os.path.exists(f"{CAVE_DIR}/assets.json")
        if model_ready and assets_ready:
            log_event("Running CVE scan...", C)
            result = subprocess.run(
                ["python3", f"{CAVE_DIR}/cve_discovery.py"],
                capture_output=True, text=True
            )
            results_file = f"{CAVE_DIR}/vulnerability_scan_results.json"
            if result.returncode == 0 and os.path.exists(results_file):
                log_event("CVE scan done — scoring risks...", G)
                sync_to_shared("vulnerability_scan_results.json")
                if not _score_and_display(results_file):return

                # Step 4: Attack path analysis — final step of discovery pipeline
                risk_path = os.path.join(CAVE_DIR, "risk_scored_results.json")
                if os.path.exists(risk_path):
                    try:
                        from attack_path import run_attack_path_analysis
                        run_attack_path_analysis()
                        from snapshot_io import publish_cycle
                        publish_cycle(CAVE_DIR, SHARED_DIR)
                    except Exception as e:
                        log_event(f"Attack path error: {e}", R)
            else:
                log_event(f"CVE scan failed (rc={result.returncode})", R)
                print(f"[cve_discovery stderr]\n{result.stderr}", flush=True)
        elif not model_ready:
            log_event("CVE scan skipped — model/ files needed", Y)

    finally:
        _discovery_lock.release()


# ── PCAP loop (periodic background discovery) ────────────────────────────────

def pcap_loop():
    time.sleep(15)  # let containers start first
    while True:
        run_discovery()   # non-blocking acquire — skips if delayed asset is mid-discovery
        time.sleep(10)


# ── TUI ──────────────────────────────────────────────────────────────────────

def pbar(val, maxval, width=12, color=G):
    filled = min(int(width * val / maxval), width) if maxval > 0 else 0
    return color + "█" * filled + DIM + "░" * (width - filled) + NC


def div(label="", char="─"):
    if label:
        side = (WIDTH - len(label) - 2) // 2
        print(f" {DIM}{char*side}{NC} {W}{label}{NC} {DIM}{char*side}{NC}")
    else:
        print(f" {DIM}{char*WIDTH}{NC}")


def render():
    os.system("clear")
    elapsed      = int(time.time() - start_time)
    online_count = sum(1 for n in DEVICE_NAMES if status[n] == "ONLINE")
    total        = len(DEVICE_NAMES)
    h = elapsed // 3600
    m = (elapsed % 3600) // 60
    s = elapsed % 60
    sc = G if online_count == total else (Y if online_count > 0 else R)

    print(f"{BOLD}{B}╔{'═'*WIDTH}╗{NC}")
    title = "CAVE-OT  ::  Water Treatment Plant  ::  Live Monitor"
    pad   = WIDTH - len(title)
    print(f"{BOLD}{B}║{NC}  {W}{title}{NC}{' '*(pad-2)}{BOLD}{B}║{NC}")
    info  = f"Cycle:{cycle_num}  Uptime:{h:02d}:{m:02d}:{s:02d}  Assets:{sc}{online_count}/{total}{NC}  [24/7]"
    print(f"{BOLD}{B}║{NC}  {info:<{WIDTH+10}}{BOLD}{B}║{NC}")
    print(f"{BOLD}{B}╚{'═'*WIDTH}╝{NC}")

    div("ASSETS")
    names     = DEVICE_NAMES
    mid       = (len(names) + 1) // 2
    left_col  = names[:mid]
    right_col = names[mid:]
    for i in range(mid):
        def fmt_asset(name):
            d    = DEVICES[name]
            st   = status[name]
            col  = G if st == "ONLINE" else (Y if st == "STARTING" else DIM)
            sym  = "●" if st == "ONLINE" else ("◑" if st == "STARTING" else "○")
            zone = "IT" if d["zone"] == "IT" else "OT"
            zcol = B if zone == "IT" else M
            dly  = f"▲+{d['delay']}s" if d["delay"] > 0 and st != "ONLINE" else ""
            return f" {col}{sym}{NC} {zcol}[{zone}]{NC} {col}{name[:22]:<22}{NC} {Y}{dly:<6}{NC}"
        left  = fmt_asset(left_col[i])
        right = fmt_asset(right_col[i]) if i < len(right_col) else ""
        print(f"{left}  {right}")

    div("SENSOR READINGS")
    sv = sensor_vals
    sensors = [
        ("Water Level", sv['water_level'],   100,  "%",    sv['water_level'] < 20),
        ("Turbidity",   sv['turbidity'],     10,   "NTU",  sv['turbidity'] > 4),
        ("Chlorine",    sv['chlorine'],      5,    "mg/L", sv['chlorine'] < 0.8),
        ("pH",          sv['ph'] - 6,        3,    f"pH {sv['ph']:.2f}", False),
        ("Flow Rate",   sv['flow_rate'],     1500, "L/m",  sv['flow_rate'] > 1200),
        ("Reservoir",   sv['reservoir_pct'], 100,  "%",    sv['reservoir_pct'] < 30),
        ("Pressure",    sv['pressure'],      10,   "bar",  sv['pressure'] > 7),
    ]
    mid2 = (len(sensors) + 1) // 2
    for i in range(mid2):
        def fmt_sensor(s):
            sname, val, mx, unit, warn = s
            bc  = R if warn else G
            bar = pbar(val, mx, 12, bc)
            vstr = f"{val:.1f}"
            return f" {C}{sname:<12}{NC}{bar} {W}{vstr:>6} {unit:<5}{NC}"
        left  = fmt_sensor(sensors[i])
        right = fmt_sensor(sensors[i + mid2]) if i + mid2 < len(sensors) else ""
        print(f"{left}   {right}")

    div("LIVE COMMUNICATIONS")
    with lock:
        logs = list(comms_log)
    if logs:
        for e in logs: print(f" {e}")
    else:
        print(f" {DIM} Initializing...{NC}")

    div("SURICATA IDS ALERTS")
    with lock:
        alts = list(alerts_log)
    if alts:
        for a in alts: print(f" {a}")
    else:
        print(f" {DIM} Listening on loopback...{NC}")

    div("CVE RISK RESULTS  [risk_score | tier | top EPSS | top CVE]")
    with lock:
        cves = list(cve_log)
    if cves:
        print(f" {DIM}{'Device':<26}  {'IP':<15} {'Risk':>4}  {'Tier':<8}  {'EPSS':<10} {'Top CVE':<20} CVEs  KEV{NC}")
        for _, line in cves:
            print(line)
    else:
        model_path = f"{CAVE_DIR}/model/ot_vectorizer.pkl"
        if not os.path.exists(model_path):
            print(f" {Y} Waiting for model files in {CAVE_DIR}/model/{NC}")
        else:
            print(f" {DIM} Waiting for first discovery cycle...{NC}")

    div("SYSTEM EVENTS")
    with lock:
        evs = list(events_log)
    if evs:
        for e in evs: print(f" {e}")
    else:
        print(f" {DIM} Pipeline running...{NC}")

    div()
    print(f" {DIM}Running 24/7  |  Ctrl+C to exit{NC}")


def tui_loop():
    while True:
        render()
        time.sleep(1)

# ── Container startup ────────────────────────────────────────────────────────

def start_containers():
    immediate = []
    delayed   = []
    done      = set()
    for name, d in DEVICES.items():
        c = d["container"]
        if c in done:
            continue
        done.add(c)
        if d["delay"] == 0:
            immediate.append((name, c))
        else:
            delayed.append((name, c, d["delay"]))

    # CAVE_OT_DOCKER=1 (set in docker-compose.yml) means this is the Compose
    # testbed, where a single multi-port `honeypot` listener binds every
    # device port at container start — there's no per-device container to
    # start. Unset (the VM's actual deployment) means real per-device Conpot
    # containers exist and must be started individually, exactly as before.
    # Either way the delay/status-transition simulation below runs unchanged
    # (it drives real dashboard/demo behaviour) — only the container-start
    # call itself is conditional.
    docker_testbed = os.environ.get("CAVE_OT_DOCKER") == "1"

    log_event("Starting immediate containers...", Y)
    if not docker_testbed:
        for name, c in immediate:
            subprocess.run(["sudo", "docker", "start", c], capture_output=True)
    time.sleep(4)
    for name, d in DEVICES.items():
        if d["delay"] == 0:
            with lock:
                status[name] = "ONLINE"
    log_event("Immediate assets online", G)

    def start_delayed(name, c, delay):
        with lock:
            status[name] = "STARTING"
        log_event(f"{name} coming online in {delay}s...", Y)
        time.sleep(delay)
        if not docker_testbed:
            subprocess.run(["sudo", "docker", "start", c], capture_output=True)
        time.sleep(3)
        with lock:
            status[name] = "ONLINE"
        log_event(f"{name} ONLINE — running discovery with fresh capture", G)
        # Pass warm_up_ports so this discovery WAITS for any in-progress one
        # and then captures a pcap that includes this asset's traffic
        port = DEVICES[name]["port"]
        threading.Thread(
            target=run_discovery,
            kwargs={"warm_up_ports": [port]},
            daemon=True
        ).start()

    for name, c, delay in delayed:
        threading.Thread(target=start_delayed, args=(name, c, delay), daemon=True).start()


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("[INIT] Loading CIA lookup from local database...")
    _cia_lookup = build_cia_lookup()
    print(f"[INIT] CIA lookup ready — {len(_cia_lookup):,} CVEs")

    os.makedirs("/var/log/suricata", exist_ok=True)
    open("/var/log/suricata/fast.log", "w").close()
    for f in ["assets.json", "suricata_context.json", "final_risk.json",
              "test_all.pcap", "vulnerability_scan_results.json",
              "risk_scored_results.json"]:
        try: os.remove(f"{CAVE_DIR}/{f}")
        except: pass

    # Signal Windows file_watcher that a new session is starting
    try:
        _session_file = os.path.join(SHARED_DIR, "session_start.json")
        with open(_session_file, "w") as _f:
            json.dump({"started_at": str(datetime.now())}, _f)
    except Exception as _e:
        print(f"[INIT] Could not write session_start.json: {_e}", flush=True)

    threading.Thread(target=tui_loop, daemon=True).start()

    log_event("Starting Suricata (pcap mode)...", Y)
    subprocess.run(["sudo", "pkill", "-f", "suricata"], capture_output=True)
    subprocess.run(["sudo", "rm", "-f", "/var/run/suricata.pid"])
    time.sleep(2)
    ids_start = subprocess.run(
        ["sudo", "suricata", "-c", "/etc/suricata/suricata.yaml",
         "-S", "/var/lib/suricata/rules/ot-rules.rules", "-k", "none", "--pcap=lo", "-D", "--pidfile", "/var/run/suricata.pid"],
        capture_output=True, text=True, timeout=20
    )
    if ids_start.returncode:
        print("Suricata startup failed: "+ids_start.stderr,flush=True)
        sys.exit(1)
    time.sleep(4)
    log_event("Suricata live on loopback", G)

    threading.Thread(target=start_containers, daemon=True).start()
    time.sleep(8)
    threading.Thread(target=comm_cycle,  daemon=True).start()
    threading.Thread(target=read_alerts, daemon=True).start()
    time.sleep(3)
    threading.Thread(target=pcap_loop,   daemon=True).start()

    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print(f"\n{Y}Shutting down...{NC}")
        subprocess.run(["sudo", "pkill", "-f", "suricata"], capture_output=True)
        subprocess.run(["sudo", "pkill", "-f", "tcpdump"],  capture_output=True)
        print(f"{G}Done. Check {CAVE_DIR}/risk_scored_results.json{NC}\n")
