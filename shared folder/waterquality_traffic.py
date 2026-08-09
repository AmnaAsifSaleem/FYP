import socket
import struct
import time

def send_modbus_request():
    # Read holding registers for water quality
    # Registers: chlorine level, pH, turbidity
    packet = struct.pack('>HHHBBHH',
        0x0001,  # transaction id
        0x0000,  # protocol id
        0x0006,  # length
        0x01,    # unit id
        0x03,    # function code: read holding registers
        0x0064,  # start address (register 100 = chlorine)
        0x0003   # quantity (3 registers)
    )
    return packet

print("[*] Sending Modbus traffic (water quality sensor)...")

for i in range(20):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(('127.0.0.1', 5020))
        sock.send(send_modbus_request())
        try:
            response = sock.recv(256)
            print(f"WaterQuality Read {i+1}: OK - {len(response)} bytes")
        except:
            print(f"WaterQuality Read {i+1}: Sent OK - no response")
        sock.close()
    except Exception as e:
        print(f"WaterQuality Read {i+1}: Error - {e}")
    time.sleep(1)

print("[*] Water Quality Done.")