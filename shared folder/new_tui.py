import socket, struct, subprocess, threading
import time, random, os, re, json
from datetime import datetime

R  = '\033[0;31m'
G  = '\033[0;32m'
Y  = '\033[1;33m'
B  = '\033[0;34m'
C  = '\033[0;36m'
M  = '\033[0;35m'
W  = '\033[1;37m'
DIM= '\033[2m'
NC = '\033[0m'
BOLD='\033[1m'

CAVE_DIR = "/home/caveot/cave_ot_test"

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
    "Reservoir_Level_PLC":    {"port": 10203, "proto": "s7",     "zone": "OT", "delay": 15, "container": "conpot_reservior"},
    "Booster_Pump_PLC":       {"port": 10204, "proto": "s7",     "zone": "OT", "delay": 25, "container": "conpot_booster"},
}

DEVICE_NAMES = list(DEVICES.keys())

MODBUS = struct.pack(">HHHBBHH",0x0001,0x0000,0x0006,0x01,0x03,0x0000,0x000A)
S7     = bytes([0x03,0x00,0x00,0x16,0x11,0xe0,0x00,0x00,0x00,0x01,
                0x00,0xc0,0x01,0x0a,0xc1,0x02,0x01,0x00,0xc2,0x02,0x01,0x02])
DNP3   = bytes([0x05,0x64,0x14,0x44,0x01,0x00,0x03,0x00,0xe9,0x21,
                0xc0,0x01,0x01,0x3c,0x02,0x06,0x3c,0x01,0x06])
HTTP   = b"GET /status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
BACNET = bytes([0x81,0x0b,0x00,0x0c,0x01,0x20,0xff,0xff,0x00,0xff,0x10,0x08])

# ── Shared State ─────────────────────────────────────
status     = {n: "WAITING"  for n in DEVICE_NAMES}
comms_log  = []
alerts_log = []
events_log = []
cycle_num  = 0
start_time = time.time()
lock       = threading.Lock()
discovery_running = False

sensor_vals = {
    "water_level":   75.0,
    "turbidity":     2.5,
    "chlorine":      1.2,
    "ph":            7.2,
    "flow_rate":     850.0,
    "reservoir_pct": 68.0,
    "pressure":      3.2,
}

# ── Send Packet ──────────────────────────────────────
def send_pkt(name):
    d = DEVICES[name]
    try:
        if d["proto"] == "bacnet":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.sendto(BACNET, ("127.0.0.1", d["port"]))
            s.close()
        else:
            pkt = {"modbus":MODBUS,"s7":S7,"dnp3":DNP3,
                   "http":HTTP,"tcp":MODBUS}[d["proto"]]
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

# ── Log Comm Event ───────────────────────────────────
def log_comm(src, dst, msg, ok):
    ts  = datetime.now().strftime("%H:%M:%S")
    col = G if ok else DIM+R
    sym = ">>>" if ok else "---"
    entry = f"{DIM}{ts}{NC} {col}{sym}{NC} {C}{src[:20]:<20}{NC}->{M}{dst[:20]:<20}{NC} {DIM}{msg}{NC}"
    with lock:
        comms_log.append(entry)
        if len(comms_log) > 8:
            comms_log.pop(0)

# ── Log System Event ─────────────────────────────────
def log_event(msg, color=Y):
    ts = datetime.now().strftime("%H:%M:%S")
    with lock:
        events_log.append(f"{DIM}{ts}{NC} {color}{msg}{NC}")
        if len(events_log) > 5:
            events_log.pop(0)

# ── Update Sensors ───────────────────────────────────
def update_sensors():
    sensor_vals["water_level"]   = max(10,  min(100, sensor_vals["water_level"]   + random.uniform(-1.5,1.5)))
    sensor_vals["turbidity"]     = max(0.1, min(10,  sensor_vals["turbidity"]     + random.uniform(-0.2,0.2)))
    sensor_vals["chlorine"]      = max(0.1, min(5,   sensor_vals["chlorine"]      + random.uniform(-0.1,0.1)))
    sensor_vals["ph"]            = max(6.0, min(9.0, sensor_vals["ph"]            + random.uniform(-0.05,0.05)))
    sensor_vals["flow_rate"]     = max(100, min(1500,sensor_vals["flow_rate"]     + random.uniform(-20,20)))
    sensor_vals["reservoir_pct"] = max(10,  min(100, sensor_vals["reservoir_pct"] + random.uniform(-1,1)))
    sensor_vals["pressure"]      = max(0.5, min(10,  sensor_vals["pressure"]      + random.uniform(-0.1,0.1)))

# ── Comm Cycle Thread ────────────────────────────────
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
        ]

        for src, dst, msg in comms:
            if status[src] == "ONLINE" and status[dst] == "ONLINE":
                ok = send_pkt(src)
                log_comm(src, dst, msg, ok)
            else:
                log_comm(src, dst, msg, False)
            time.sleep(0.2)

        time.sleep(4)

# ── Suricata Alert Reader ────────────────────────────
def read_alerts():
    seen = set()
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

                new_alerts.append(f"{col}{msg[:65]}{NC}")

                # Check if this is a new unknown port — new asset detected
                if port not in known_ports:
                    known_ports.add(port)
                    log_event(f"NEW ASSET DETECTED on port {port} — triggering discovery", R)
                    threading.Thread(target=run_discovery, daemon=True).start()

                # Check if delayed asset just came online via its port
                for name, d in DEVICES.items():
                    if d["port"] == port and status[name] != "ONLINE":
                        with lock:
                            status[name] = "ONLINE"
                        log_event(f"DELAYED ASSET ONLINE: {name} (port {port})", G)
                        threading.Thread(target=run_discovery, daemon=True).start()

            with lock:
                alerts_log.extend(new_alerts)
                if len(alerts_log) > 6:
                    alerts_log[:] = alerts_log[-6:]

        except:
            pass
        time.sleep(2)

# ── Auto Discovery + Risk Scoring ───────────────────
def run_discovery():
    global discovery_running
    if discovery_running:
        return
    discovery_running = True
    log_event("Running smart_discover.py...", C)
    os.chdir(CAVE_DIR)
    subprocess.run(["sudo","python3","smart_discover.py"],
                   capture_output=True)
    log_event("assets.json updated", G)

    # Run risk scorer if model exists
    if os.path.exists(f"{CAVE_DIR}/risk_scorer.py") and \
       os.path.exists(f"{CAVE_DIR}/risk_model.pkl"):
        log_event("Running risk_scorer.py...", C)
        subprocess.run(["python3","risk_scorer.py"],
                       capture_output=True)
        log_event("final_risk.json updated", G)

    discovery_running = False

# ── Progress Bar ─────────────────────────────────────
def pbar(val, maxval, width=14, color=G):
    filled = min(int(width * val / maxval), width) if maxval > 0 else 0
    return color + "█"*filled + DIM + "░"*(width-filled) + NC

# ── TUI Render ───────────────────────────────────────
def render():
    os.system("clear")
    elapsed     = int(time.time() - start_time)
    online_count= sum(1 for n in DEVICE_NAMES if status[n]=="ONLINE")
    total       = len(DEVICE_NAMES)
    h = elapsed//3600
    m = (elapsed%3600)//60
    s = elapsed%60

    status_col = G if online_count==total else (Y if online_count>0 else R)

    print(f"{BOLD}{B}╔══════════════════════════════════════════════════════════════════════════╗{NC}")
    print(f"{BOLD}{B}║{NC}  {W}CAVE-OT{NC} :: Water Treatment Plant :: {C}Live Autonomous Monitor{NC}            {BOLD}{B}║{NC}")
    print(f"{BOLD}{B}║{NC}  {DIM}Cycle:{NC}{W}{cycle_num:<5}{NC} {DIM}Uptime:{NC}{W}{h:02d}:{m:02d}:{s:02d}{NC}  {DIM}Assets:{NC}{status_col}{online_count}/{total}{NC}  {DIM}[24/7 Running — No Stop Needed]{NC}  {BOLD}{B}║{NC}")
    print(f"{BOLD}{B}╚══════════════════════════════════════════════════════════════════════════╝{NC}")

    # Asset grid + sensors side by side
    print(f"\n{BOLD}{W} ASSETS{NC}                                        {BOLD}{W}LIVE SENSOR READINGS{NC}")
    print(f" {'─'*42}        {'─'*30}")

    sv = sensor_vals
    sensor_lines = [
        f" {C}Water Level {NC} {pbar(sv['water_level'],100)}  {W}{sv['water_level']:5.1f}%{NC}",
        f" {C}Turbidity   {NC} {pbar(sv['turbidity'],10,14,Y if sv['turbidity']>4 else G)}  {W}{sv['turbidity']:5.2f} NTU{NC}",
        f" {C}Chlorine    {NC} {pbar(sv['chlorine'],5,14,R if sv['chlorine']<0.8 else G)}  {W}{sv['chlorine']:5.2f} mg/L{NC}",
        f" {C}pH          {NC} {pbar(sv['ph']-6,3)}  {W}{sv['ph']:5.2f}{NC}",
        f" {C}Flow Rate   {NC} {pbar(sv['flow_rate'],1500,14,R if sv['flow_rate']>1200 else G)}  {W}{sv['flow_rate']:5.0f} L/m{NC}",
        f" {C}Reservoir   {NC} {pbar(sv['reservoir_pct'],100,14,R if sv['reservoir_pct']<30 else G)}  {W}{sv['reservoir_pct']:5.1f}%{NC}",
        f" {C}Pressure    {NC} {pbar(sv['pressure'],10)}  {W}{sv['pressure']:5.2f} bar{NC}",
    ]

    for i, name in enumerate(DEVICE_NAMES):
        d   = DEVICES[name]
        st  = status[name]
        col = G if st=="ONLINE" else (Y if st=="STARTING" else (R if st=="OFFLINE" else DIM))
        sym = "●" if st=="ONLINE" else ("◑" if st=="STARTING" else "○")
        zone= f"{B}IT{NC}" if d["zone"]=="IT" else f"{M}OT{NC}"
        dly = f" {Y}▲DELAYED +{d['delay']}s{NC}" if d["delay"]>0 and st!="ONLINE" else ""
        left= f" {col}{sym}{NC} [{zone}] {col}{name[:26]:<26}{NC}{dly}"

        if i < len(sensor_lines):
            print(f"{left:<50}{sensor_lines[i]}")
        else:
            print(left)

    # Comms
    print(f"\n{BOLD}{W} LIVE COMMUNICATIONS{NC}  {DIM}(real-time asset-to-asset){NC}")
    print(f" {'─'*72}")
    with lock:
        logs = list(comms_log)
    if logs:
        for e in logs:
            print(f" {e}")
    else:
        print(f" {DIM} Initializing...{NC}")

    # Alerts
    print(f"\n{BOLD}{W} SURICATA IDS{NC}  {DIM}(live passive monitoring — loopback interface){NC}")
    print(f" {'─'*72}")
    with lock:
        alts = list(alerts_log)
    if alts:
        for a in alts[-6:]:
            print(f" {a}")
    else:
        print(f" {DIM} Suricata listening on lo interface...{NC}")

    # Events
    print(f"\n{BOLD}{W} SYSTEM EVENTS{NC}  {DIM}(auto-discovery, new assets, risk scoring){NC}")
    print(f" {'─'*72}")
    with lock:
        evs = list(events_log)
    if evs:
        for e in evs:
            print(f" {e}")
    else:
        print(f" {DIM} Pipeline running...{NC}")

    print(f"\n {DIM}Running 24/7 — Ctrl+C only to exit completely{NC}")

# ── TUI Thread ───────────────────────────────────────
def tui_loop():
    while True:
        render()
        time.sleep(1)

# ── Container Starter With Delay ─────────────────────
def start_containers():
    # Group containers
    immediate = []
    delayed   = []

    done_containers = set()
    for name, d in DEVICES.items():
        c = d["container"]
        if c in done_containers:
            continue
        done_containers.add(c)
        if d["delay"] == 0:
            immediate.append((name, c))
        else:
            delayed.append((name, c, d["delay"]))

    # Start immediate
    log_event("Starting immediate containers...", Y)
    for name, c in immediate:
        subprocess.run(["sudo","docker","start", c], capture_output=True)

    time.sleep(4)

    # Mark immediate as online
    for name, d in DEVICES.items():
        if d["delay"] == 0:
            with lock:
                status[name] = "ONLINE"
    log_event("Immediate assets online", G)
    run_discovery()

    # Handle delayed containers in background
    def start_delayed(name, c, delay):
        with lock:
            status[name] = "STARTING"
        log_event(f"{name} starting in {delay}s...", Y)
        time.sleep(delay)
        subprocess.run(["sudo","docker","start", c], capture_output=True)
        time.sleep(3)
        with lock:
            status[name] = "ONLINE"
        log_event(f"{name} now ONLINE — Suricata will detect", G)

    for name, c, delay in delayed:
        threading.Thread(target=start_delayed, args=(name,c,delay), daemon=True).start()

# ── Main ─────────────────────────────────────────────
if __name__ == "__main__":

    # Clean logs
    os.makedirs("/var/log/suricata", exist_ok=True)
    open("/var/log/suricata/fast.log", "w").close()

    # Start TUI
    threading.Thread(target=tui_loop, daemon=True).start()

    # Start Suricata live on loopback
    log_event("Starting Suricata on loopback interface...", Y)
    subprocess.Popen(
        ["sudo","suricata","-i","lo",
         "-l","/var/log/suricata/",
         "-c","/etc/suricata/suricata.yaml"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(3)
    log_event("Suricata live — monitoring loopback", G)

    # Start containers
    threading.Thread(target=start_containers, daemon=True).start()

      # Start tcpdump capture in background
    log_event("Starting packet capture on loopback...", Y)
    tcpdump_proc = subprocess.Popen(
        ["sudo", "tcpdump", "-i", "lo", "-w",
         f"{CAVE_DIR}/test_all.pcap", "-c", "250"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    log_event("tcpdump capturing 250 packets...", G)

    # Start comms
    time.sleep(5)
    threading.Thread(target=comm_cycle, daemon=True).start()

       # After capture finishes, run discovery
    def post_capture():
        tcpdump_proc.wait()  # blocks until 250 packets captured
        log_event("Capture complete — running discovery...", Y)
        time.sleep(2)
        run_discovery()
        log_event("assets.json + suricata_context.json updated", G)

    # Start alert reader
    threading.Thread(target=read_alerts, daemon=True).start()

    # Keep alive forever
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print(f"\n{Y}[*] Shutting down...{NC}")
        subprocess.run(["sudo","pkill","-f","suricata"], capture_output=True)
        print(f"{G}[+] assets.json and final_risk.json saved.{NC}\n")