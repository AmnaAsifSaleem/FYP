import socket
import struct
import time
import random
import threading

# ── Device Map ───────────────────────────────────────
DEVICES = {
    "Water_Level_RTU":        {"ip": "127.0.0.1", "port": 20000, "proto": "dnp3"},
    "WaterQuality_Sensor":    {"ip": "127.0.0.1", "port": 5020,  "proto": "modbus"},
    "Dosing_Pump_PLC":        {"ip": "127.0.0.1", "port": 502,   "proto": "modbus"},
    "Filtration_PLC":         {"ip": "127.0.0.1", "port": 10201, "proto": "s7"},
    "Ventilation_Controller": {"ip": "127.0.0.1", "port": 47808, "proto": "bacnet"},
    "SCADA_Server":           {"ip": "127.0.0.1", "port": 6230,  "proto": "tcp"},
    "HMI_Interface":          {"ip": "127.0.0.1", "port": 80,    "proto": "http"},
    "Turbidity_Sensor_PLC":   {"ip": "127.0.0.1", "port": 5031,  "proto": "modbus"},
    "UV_Disinfection_PLC":    {"ip": "127.0.0.1", "port": 5032,  "proto": "modbus"},
    "Reservoir_Level_PLC":    {"ip": "127.0.0.1", "port": 10203, "proto": "s7"},
    "Booster_Pump_PLC":       {"ip": "127.0.0.1", "port": 10204, "proto": "s7"},
    "Flow_Meter_RTU":         {"ip": "127.0.0.1", "port": 20001, "proto": "dnp3"},
    "Backup_HMI_Interface":   {"ip": "127.0.0.1", "port": 8080,  "proto": "http"},
}

# ── Packets ──────────────────────────────────────────
MODBUS = struct.pack(">HHHBBHH", 0x0001, 0x0000, 0x0006, 0x01, 0x03, 0x0000, 0x000A)
S7     = bytes([0x03,0x00,0x00,0x16,0x11,0xe0,0x00,0x00,0x00,0x01,0x00,
                0xc0,0x01,0x0a,0xc1,0x02,0x01,0x00,0xc2,0x02,0x01,0x02])
DNP3   = bytes([0x05,0x64,0x14,0x44,0x01,0x00,0x03,0x00,0xe9,0x21,
                0xc0,0x01,0x01,0x3c,0x02,0x06,0x3c,0x01,0x06])
HTTP   = b"GET /status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
BACNET = bytes([0x81,0x0b,0x00,0x0c,0x01,0x20,0xff,0xff,0x00,0xff,0x10,0x08])

# ── Simulated Sensor Values ──────────────────────────
state = {
    "water_level":   75.0,   # percent
    "turbidity":     2.5,    # NTU
    "chlorine":      1.2,    # mg/L
    "ph":            7.2,
    "flow_rate":     850.0,  # L/min
    "reservoir_pct": 68.0,   # percent
    "pressure":      3.2,    # bar
}

# ── Send To One Device ───────────────────────────────
def send(name, reason="poll"):
    d = DEVICES[name]
    proto = d["proto"]
    try:
        if proto == "bacnet":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(BACNET, (d["ip"], d["port"]))
            sock.close()
        else:
            pkt = {"modbus": MODBUS, "s7": S7, "dnp3": DNP3,
                   "http": HTTP, "tcp": MODBUS}[proto]
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((d["ip"], d["port"]))
            sock.send(pkt)
            try: sock.recv(256)
            except: pass
            sock.close()
        return True
    except:
        return False

# ── Update Sensor Values With Slight Random Drift ───
def update_state():
    state["water_level"]   = max(10, min(100, state["water_level"]   + random.uniform(-1.5, 1.5)))
    state["turbidity"]     = max(0,  min(10,  state["turbidity"]     + random.uniform(-0.2, 0.2)))
    state["chlorine"]      = max(0,  min(5,   state["chlorine"]      + random.uniform(-0.1, 0.1)))
    state["ph"]            = max(6,  min(9,   state["ph"]            + random.uniform(-0.05, 0.05)))
    state["flow_rate"]     = max(0,  min(1500,state["flow_rate"]     + random.uniform(-20, 20)))
    state["reservoir_pct"] = max(10, min(100, state["reservoir_pct"] + random.uniform(-1, 1)))
    state["pressure"]      = max(0,  min(10,  state["pressure"]      + random.uniform(-0.1, 0.1)))

# ── Communication Logic Per Cycle ───────────────────
def run_cycle(cycle):
    update_state()
    s = state

    print(f"\n{'='*55}")
    print(f"  CYCLE {cycle} | Water Treatment Plant Live Comms")
    print(f"{'='*55}")
    print(f"  Level:{s['water_level']:.1f}%  Turbidity:{s['turbidity']:.2f}NTU  "
          f"Cl:{s['chlorine']:.2f}mg/L  pH:{s['ph']:.2f}")
    print(f"  Flow:{s['flow_rate']:.0f}L/m  Reservoir:{s['reservoir_pct']:.1f}%  "
          f"Pressure:{s['pressure']:.2f}bar")
    print(f"{'-'*55}")

    # 1. Water Level RTU → reads level → reports to SCADA
    ok = send("Water_Level_RTU", "read level")
    print(f"  Water_Level_RTU       -> SCADA_Server         "
          f"[level={s['water_level']:.1f}%] {'OK' if ok else 'FAIL'}")
    send("SCADA_Server")

    # 2. Turbidity Sensor → reads NTU → commands UV if high
    ok = send("Turbidity_Sensor_PLC", "read turbidity")
    action = "INCREASE UV POWER" if s["turbidity"] > 4.0 else "normal"
    print(f"  Turbidity_Sensor_PLC  -> UV_Disinfection_PLC  "
          f"[NTU={s['turbidity']:.2f}] {action} {'OK' if ok else 'FAIL'}")
    send("UV_Disinfection_PLC")

    # 3. Water Quality → reads pH/chlorine → commands dosing pump
    ok = send("WaterQuality_Sensor", "read quality")
    action = "INCREASE DOSE" if s["chlorine"] < 0.8 else "normal"
    print(f"  WaterQuality_Sensor   -> Dosing_Pump_PLC      "
          f"[Cl={s['chlorine']:.2f}mg/L pH={s['ph']:.2f}] {action} {'OK' if ok else 'FAIL'}")
    send("Dosing_Pump_PLC")

    # 4. Flow Meter → reads flow → reports to Filtration PLC
    ok = send("Flow_Meter_RTU", "read flow")
    action = "REDUCE FLOW" if s["flow_rate"] > 1200 else "normal"
    print(f"  Flow_Meter_RTU        -> Filtration_PLC       "
          f"[flow={s['flow_rate']:.0f}L/m] {action} {'OK' if ok else 'FAIL'}")
    send("Filtration_PLC")

    # 5. Reservoir Level → commands Booster Pump
    ok = send("Reservoir_Level_PLC", "read reservoir")
    action = "BOOST PRESSURE" if s["reservoir_pct"] < 30 else "normal"
    print(f"  Reservoir_Level_PLC   -> Booster_Pump_PLC     "
          f"[reservoir={s['reservoir_pct']:.1f}%] {action} {'OK' if ok else 'FAIL'}")
    send("Booster_Pump_PLC")

    # 6. Ventilation monitors chemical storage
    ok = send("Ventilation_Controller", "read ventilation")
    print(f"  Ventilation_Controller -> SCADA_Server        "
          f"[passive monitor] {'OK' if ok else 'FAIL'}")

    # 7. SCADA reports to both HMIs
    ok1 = send("HMI_Interface",       "update dashboard")
    ok2 = send("Backup_HMI_Interface","update dashboard")
    print(f"  SCADA_Server          -> HMI_Interface        "
          f"[dashboard update] {'OK' if ok1 else 'FAIL'}")
    print(f"  SCADA_Server          -> Backup_HMI_Interface "
          f"[dashboard update] {'OK' if ok2 else 'FAIL'}")

    online = sum([
        send("Water_Level_RTU"),   send("Turbidity_Sensor_PLC"),
        send("WaterQuality_Sensor"),send("Dosing_Pump_PLC"),
        send("Filtration_PLC"),    send("UV_Disinfection_PLC"),
        send("Ventilation_Controller"), send("SCADA_Server"),
        send("HMI_Interface"),     send("Reservoir_Level_PLC"),
        send("Booster_Pump_PLC"),  send("Flow_Meter_RTU"),
        send("Backup_HMI_Interface")
    ])
    print(f"\n  Assets online: {online}/13")

# ── Main Loop ────────────────────────────────────────
if __name__ == "__main__":
    print("[*] CAVE-OT Live Communication Starting...")
    print("[*] All 13 assets communicating continuously")
    print("[*] Press Ctrl+C to stop\n")

    cycle = 1
    while True:
        try:
            run_cycle(cycle)
            cycle += 1
            time.sleep(5)   # poll every 5 seconds
        except KeyboardInterrupt:
            print("\n[*] Stopped.")
            break