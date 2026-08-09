import socket
import struct
import time

DEVICES = [
    {"name": "Water_Level_RTU",       "ip": "127.0.0.1", "port": 20000, "proto": "dnp3"},
    {"name": "WaterQuality_Sensor",   "ip": "127.0.0.1", "port": 5020,  "proto": "modbus"},
    {"name": "Dosing_Pump_PLC",       "ip": "127.0.0.1", "port": 502,   "proto": "modbus"},
    {"name": "Filtration_PLC",        "ip": "127.0.0.1", "port": 10201, "proto": "s7"},
    {"name": "Ventilation_Controller","ip": "127.0.0.1", "port": 47808, "proto": "bacnet"},
    {"name": "SCADA_Server",          "ip": "127.0.0.1", "port": 6230,  "proto": "tcp"},
    {"name": "HMI_Interface",         "ip": "127.0.0.1", "port": 80,    "proto": "http"},
    {"name": "Turbidity_Sensor_PLC",  "ip": "127.0.0.1", "port": 5031,  "proto": "modbus"},
    {"name": "UV_Disinfection_PLC",   "ip": "127.0.0.1", "port": 5032,  "proto": "modbus"},
    {"name": "Reservoir_Level_PLC",   "ip": "127.0.0.1", "port": 10203, "proto": "s7"},
    {"name": "Booster_Pump_PLC",      "ip": "127.0.0.1", "port": 10204, "proto": "s7"},
    {"name": "Flow_Meter_RTU",        "ip": "127.0.0.1", "port": 20001, "proto": "dnp3"},
    {"name": "Backup_HMI_Interface",  "ip": "127.0.0.1", "port": 8080,  "proto": "http"},
]

MODBUS = struct.pack(">HHHBBHH", 0x0001, 0x0000, 0x0006, 0x01, 0x03, 0x0000, 0x000A)
S7     = bytes([0x03,0x00,0x00,0x16,0x11,0xe0,0x00,0x00,0x00,0x01,0x00,
                0xc0,0x01,0x0a,0xc1,0x02,0x01,0x00,0xc2,0x02,0x01,0x02])
DNP3   = bytes([0x05,0x64,0x14,0x44,0x01,0x00,0x03,0x00,0xe9,0x21,
                0xc0,0x01,0x01,0x3c,0x02,0x06,0x3c,0x01,0x06])
HTTP   = b"GET /status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
BACNET = bytes([0x81,0x0b,0x00,0x0c,0x01,0x20,0xff,0xff,0x00,0xff,0x10,0x08])

def poll(device):
    proto = device["proto"]
    try:
        if proto == "bacnet":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(BACNET, (device["ip"], device["port"]))
            sock.close()
        else:
            pkt = {"modbus": MODBUS, "s7": S7, "dnp3": DNP3,
                   "http": HTTP, "tcp": MODBUS}[proto]
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((device["ip"], device["port"]))
            sock.send(pkt)
            try: sock.recv(256)
            except: pass
            sock.close()
        print(f"  [OK]     {device['name']} port {device['port']}")
        return True
    except Exception as e:
        print(f"  [OFFLINE] {device['name']} port {device['port']}")
        return False

print("[*] SCADA Coordinator starting (8 cycles)...")
for cycle in range(1, 9):
    print(f"\n[Cycle {cycle}] Polling all {len(DEVICES)} devices...")
    online = sum(poll(d) for d in DEVICES)
    print(f"  {online}/{len(DEVICES)} devices online")
    time.sleep(3)
print("[*] Coordinator done.")