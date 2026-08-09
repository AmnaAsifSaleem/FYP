import socket
import struct
import subprocess
import threading
import time
import random
import sys
import os
import re
import json
from datetime import datetime

# ── Colors ───────────────────────────────────────────
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

# ── Device Map ───────────────────────────────────────
DEVICES = {
    "Dosing_Pump_PLC":        {"port": 502,   "proto": "modbus", "zone": "OT", "delay": 0},
    "Filtration_PLC":         {"port": 10201, "proto": "s7",     "zone": "OT", "delay": 0},
    "Ventilation_Controller": {"port": 47808, "proto": "bacnet", "zone": "OT", "delay": 0},
    "Water_Level_RTU":        {"port": 20000, "proto": "dnp3",   "zone": "OT", "delay": 0},
    "WaterQuality_Sensor":    {"port": 5020,  "proto": "modbus", "zone": "OT", "delay": 0},
    "SCADA_Server":           {"port": 6230,  "proto": "tcp",    "zone": "IT", "delay": 0},
    "HMI_Interface":          {"port": 80,    "proto": "http",   "zone": "IT", "delay": 0},
    "Turbidity_Sensor_PLC":   {"port": 5031,  "proto": "modbus", "zone": "OT", "delay": 0},
    "UV_Disinfection_PLC":    {"port": 5032,  "proto": "modbus", "zone": "OT", "delay": 0},
    "Reservoir_Level_PLC":    {"port": 10203, "proto": "s7",     "zone": "OT", "delay": 7},   # DELAYED 7s
    "Booster_Pump_PLC":       {"port": 10204, "proto": "s7",     "zone": "OT", "delay": 12},  # DELAYED 12s
    "Flow_Meter_RTU":         {"port": 20001, "proto": "dnp3",   "zone": "OT", "delay": 0},
    "Backup_HMI_Interface":   {"port": 8080,  "proto": "http",   "zone": "IT", "delay": 0},
}

DEVICE_NAMES = list(DEVICES.keys())

# ── Packets ──────────────────────────────────────────
MODBUS = struct.pack(">HHHBBHH", 0x0001,0x0000,0x0006,0x01,0x03,0x0000,0x000A)
S7     = bytes([0x03,0x00,0x00,0x16,0x11,0xe0,0x00,0x00,0x00,0x01,
                0x00,0xc0,0x01,0x0a,0xc1,0x02,0x01,0x00,0xc2,0x02,0x01,0x02])
DNP3   = bytes([0x05,0x64,0x14,0x44,0x01,0x00,0x03,0x00,0xe9,0x21,
                0xc0,0x01,0x01,0x3c,0x02,0x06,0x3c,0x01,0x06])
HTTP   = b"GET /status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
BACNET = bytes([0x81,0x0b,0x00,0x0c,0x01,0x20,0xff,0xff,0x00,0xff,0x10,0x08])

# ── Shared State ─────────────────────────────────────
status      = {n: "WAITING" for n in DEVICE_NAMES}
online      = {n: False     for n in DEVICE_NAMES}
comms_log   = []          # last 8 comm events
alerts_log  = []          # suricata alerts
cycle_num   = 0
start_time  = time.time()
lock        = threading.Lock()

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
            pkt = {"modbus":MODBUS,"s7":S7,"dnp3":DNP3,"http":HTTP,"tcp":MODBUS}[d["proto"]]
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

# ── Comm Log Helper ──────────────────────────────────
def log_comm(src, dst, msg, ok):
    ts  = datetime.now().strftime("%H:%M:%S")
    col = G if ok else R
    sym = ">>>" if ok else "---"
    entry = f"{DIM}{ts}{NC} {col}{sym}{NC} {C}{src[:22]:<22}{NC} -> {M}{dst[:22]:<22}{NC} {DIM}{msg}{NC}"
    with lock:
        comms_log.append(entry)
        if len(comms_log) > 8:
            comms_log.pop(0)

# ── Update Sensor Values ─────────────────────────────
def update_sensors():
    sensor_vals["water_level"]   = max(10,  min(100, sensor_vals["water_level"]   + random.uniform(-1.5,1.5)))
    sensor_vals["turbidity"]     = max(0.1, min(10,  sensor_vals["turbidity"]     + random.uniform(-0.2,0.2)))
    sensor_vals["chlorine"]      = max(0.1, min(5,   sensor_vals["chlorine"]      + random.uniform(-0.1,0.1)))
    sensor_vals["ph"]            = max(6.0, min(9.0, sensor_vals["ph"]            + random.uniform(-0.05,0.05)))
    sensor_vals["flow_rate"]     = max(100, min(1500,sensor_vals["flow_rate"]     + random.uniform(-20,20)))
    sensor_vals["reservoir_pct"] = max(10,  min(100, sensor_vals["reservoir_pct"] + random.uniform(-1,1)))
    sensor_vals["pressure"]      = max(0.5, min(10,  sensor_vals["pressure"]      + random.uniform(-0.1,0.1)))

# ── One Comm Cycle ───────────────────────────────────
def comm_cycle():
    global cycle_num
    while True:
        cycle_num += 1
        update_sensors()
        sv = sensor_vals

        comms = [
            ("Water_Level_RTU",       "SCADA_Server",          f"level={sv['water_level']:.1f}%"),
            ("Turbidity_Sensor_PLC",  "UV_Disinfection_PLC",   f"NTU={sv['turbidity']:.2f}"),
            ("WaterQuality_Sensor",   "Dosing_Pump_PLC",       f"Cl={sv['chlorine']:.2f} pH={sv['ph']:.2f}"),
            ("Flow_Meter_RTU",        "Filtration_PLC",        f"flow={sv['flow_rate']:.0f}L/m"),
            ("Reservoir_Level_PLC",   "Booster_Pump_PLC",      f"res={sv['reservoir_pct']:.1f}%"),
            ("Ventilation_Controller","SCADA_Server",           "ventilation=OK"),
            ("SCADA_Server",          "HMI_Interface",          "dashboard update"),
            ("SCADA_Server",          "Backup_HMI_Interface",   "dashboard update"),
            ("Filtration_PLC",        "WaterQuality_Sensor",    "request quality check"),
            ("Dosing_Pump_PLC",       "Water_Level_RTU",        "confirm level"),
            ("UV_Disinfection_PLC",   "Turbidity_Sensor_PLC",   "confirm turbidity"),
            ("Booster_Pump_PLC",      "Flow_Meter_RTU",         "confirm flow"),
        ]

        for src, dst, msg in comms:
            if status[src] == "ONLINE" and status[dst] == "ONLINE":
                ok = send_pkt(src) and send_pkt(dst)
                with lock:
                    online[src] = ok
                    online[dst] = ok
                log_comm(src, dst, msg, ok)
            else:
                log_comm(src, dst, msg, False)
            time.sleep(0.3)

        time.sleep(3)

# ── Read Suricata Alerts ─────────────────────────────
def read_alerts():
    while True:
        try:
            with open("/var/log/suricata/fast.log") as f:
                lines = f.readlines()
            with lock:
                alerts_log.clear()
                for line in lines[-6:]:
                    m = re.search(r'\[\*\*\] \[.*?\] (.+?) \[\*\*\]', line)
                    if m:
                        msg = m.group(1).strip()
                        col = R if ("Attack" in msg or "Rapid" in msg or "Brute" in msg) else Y
                        alerts_log.append(f"{col}{msg[:60]}{NC}")
        except:
            pass
        time.sleep(3)

# ── Progress Bar ─────────────────────────────────────
def pbar(val, maxval, width=20, color=G):
    filled = int(width * val / maxval) if maxval > 0 else 0
    filled = min(filled, width)
    bar = color + "█" * filled + DIM + "░" * (width - filled) + NC
    return bar

# ── TUI Render ───────────────────────────────────────
def render():
    os.system("clear")
    elapsed = int(time.time() - start_time)
    online_count = sum(1 for n in DEVICE_NAMES if status[n] == "ONLINE")
    total = len(DEVICE_NAMES)

    # Header
    print(f"{BOLD}{B}╔══════════════════════════════════════════════════════════════════════════╗{NC}")
    print(f"{BOLD}{B}║{NC}  {W}CAVE-OT{NC} :: Water Treatment Plant :: {C}Live Monitor{NC}                        {BOLD}{B}║{NC}")
    print(f"{BOLD}{B}║{NC}  {DIM}Cycle:{NC} {W}{cycle_num:<4}{NC}  {DIM}Uptime:{NC} {W}{elapsed}s{NC:<6}  {DIM}Assets Online:{NC} {G if online_count==total else Y}{online_count}/{total}{NC}                 {BOLD}{B}║{NC}")
    print(f"{BOLD}{B}╚══════════════════════════════════════════════════════════════════════════╝{NC}")

    # Asset Status Panel
    print(f"\n{BOLD}{W} ASSET STATUS{NC}  {DIM}(OT Zone){NC}                           {BOLD}{W}SENSOR READINGS{NC}")
    print(f" {'─'*38}          {'─'*28}")

    ot_devices = [(n,d) for n,d in DEVICES.items() if d["zone"]=="OT"]
    it_devices = [(n,d) for n,d in DEVICES.items() if d["zone"]=="IT"]

    sv = sensor_vals
    sensor_lines = [
        f" {C}Water Level  {NC}{pbar(sv['water_level'],100,15)} {W}{sv['water_level']:5.1f}%{NC}",
        f" {C}Turbidity    {NC}{pbar(sv['turbidity'],10,15,Y if sv['turbidity']>4 else G)} {W}{sv['turbidity']:5.2f} NTU{NC}",
        f" {C}Chlorine     {NC}{pbar(sv['chlorine'],5,15,R if sv['chlorine']<0.8 else G)} {W}{sv['chlorine']:5.2f} mg/L{NC}",
        f" {C}pH           {NC}{pbar(sv['ph']-6,3,15)} {W}{sv['ph']:5.2f}{NC}",
        f" {C}Flow Rate    {NC}{pbar(sv['flow_rate'],1500,15,R if sv['flow_rate']>1200 else G)} {W}{sv['flow_rate']:5.0f} L/m{NC}",
        f" {C}Reservoir    {NC}{pbar(sv['reservoir_pct'],100,15,R if sv['reservoir_pct']<30 else G)} {W}{sv['reservoir_pct']:5.1f}%{NC}",
        f" {C}Pressure     {NC}{pbar(sv['pressure'],10,15)} {W}{sv['pressure']:5.2f} bar{NC}",
    ]

    all_devs = ot_devices + it_devices
    for i, (name, d) in enumerate(all_devs):
        st   = status[name]
        col  = G if st=="ONLINE" else (Y if st=="STARTING" else (DIM if st=="WAITING" else R))
        sym  = "●" if st=="ONLINE" else ("◑" if st=="STARTING" else "○")
        dly  = f"{R}[DELAYED +{d['delay']}s]{NC}" if d["delay"] > 0 and st != "ONLINE" else ""
        zone = f"{B}[IT]{NC}" if d["zone"]=="IT" else f"{M}[OT]{NC}"
        left = f" {col}{sym}{NC} {zone} {name[:28]:<28} {dly}"

        if i < len(sensor_lines):
            print(f"{left:<52}{sensor_lines[i]}")
        else:
            print(left)

    # Communication Log
    print(f"\n{BOLD}{W} LIVE COMMUNICATIONS{NC}  {DIM}(last 8 events){NC}")
    print(f" {'─'*70}")
    with lock:
        logs = list(comms_log)
    if logs:
        for entry in logs:
            print(f" {entry}")
    else:
        print(f" {DIM} Waiting for communication...{NC}")

    # Suricata Alerts
    print(f"\n{BOLD}{W} SURICATA IDS ALERTS{NC}  {DIM}(passive monitoring){NC}")
    print(f" {'─'*70}")
    with lock:
        alts = list(alerts_log)
    if alts:
        for a in alts:
            print(f" {a}")
    else:
        print(f" {DIM} No alerts yet — waiting for Suricata...{NC}")

    print(f"\n {DIM}Press Ctrl+C to stop pipeline{NC}")

# ── TUI Refresh Loop ─────────────────────────────────
def tui_loop():
    while True:
        render()
        time.sleep(1)

# ── Start Containers With Delay ──────────────────────
def start_containers():
    containers = [
        ("conpot",            None,  None),
        ("conpot_turbidity",  5031,  502),
        ("conpot_uv",         5032,  502),
        ("conpot_reservior",  10203, 10201),
        ("conpot_booster",    10204, 10201),
        ("conpot_flowmeter",  20001, 20000),
        ("conpot_backup_hmi", 8080,  80),
    ]

    # map container name to device names
    container_device_map = {
        "conpot":            ["Dosing_Pump_PLC","Filtration_PLC","Ventilation_Controller",
                              "Water_Level_RTU","WaterQuality_Sensor","SCADA_Server","HMI_Interface"],
        "conpot_turbidity":  ["Turbidity_Sensor_PLC"],
        "conpot_uv":         ["UV_Disinfection_PLC"],
        "conpot_reservior":  ["Reservoir_Level_PLC"],
        "conpot_booster":    ["Booster_Pump_PLC"],
        "conpot_flowmeter":  ["Flow_Meter_RTU"],
        "conpot_backup_hmi": ["Backup_HMI_Interface"],
    }

    # stop all first
    for name, _, _ in containers:
        subprocess.run(["sudo","docker","stop",name], capture_output=True)

    time.sleep(2)

    for name, hport, cport in containers:
        devs = container_device_map[name]

        # get delay from first device in this container
        delay = DEVICES[devs[0]]["delay"]

        if delay > 0:
            # mark as STARTING
            with lock:
                for d in devs:
                    status[d] = "STARTING"
            time.sleep(delay)

        # start container
        with lock:
            for d in devs:
                status[d] = "STARTING"

        if hport is None:
            subprocess.run(["sudo","docker","start","conpot"], capture_output=True)
        else:
            subprocess.run(["sudo","docker","start", name], capture_output=True)

        time.sleep(3)

        with lock:
            for d in devs:
                status[d] = "ONLINE"

# ── Main ─────────────────────────────────────────────
if __name__ == "__main__":

    # TUI thread
    t_tui = threading.Thread(target=tui_loop, daemon=True)
    t_tui.start()

    # Start containers with delays
    t_containers = threading.Thread(target=start_containers, daemon=False)
    t_containers.start()
    t_containers.join()

    # Start comm cycle
    t_comms = threading.Thread(target=comm_cycle, daemon=True)
    t_comms.start()

    # Start alert reader
    t_alerts = threading.Thread(target=read_alerts, daemon=True)
    t_alerts.start()

    # Start tcpdump
    tcpdump = subprocess.Popen(
        ["sudo","tcpdump","-i","lo","-w",
         "/home/caveot/cave_ot_test/test_all.pcap","-c","500"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n\n{Y}[*] Stopping...{NC}")
        tcpdump.terminate()
        time.sleep(2)

        # Run Suricata
        print(f"{Y}[*] Running Suricata on captured traffic...{NC}")
        subprocess.run([
            "sudo","suricata","-r",
            "/home/caveot/cave_ot_test/test_all.pcap",
            "-l","/var/log/suricata/",
            "-c","/etc/suricata/suricata.yaml"
        ])

        # Run discovery
        print(f"{Y}[*] Running asset discovery...{NC}")
        os.chdir("/home/caveot/cave_ot_test")
        subprocess.run(["sudo","python3","smart_discover.py"])

        print(f"\n{G}[+] Done. assets.json and suricata_context.json ready.{NC}")
        print(f"{G}[+] Feed assets.json into your model.{NC}\n")