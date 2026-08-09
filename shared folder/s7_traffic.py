import socket
import struct
import time

def send_s7_request(ip, port):
    # COTP + S7 connection request
    # Standard S7 identification packet
    s7_packet = bytes([
        0x03, 0x00, 0x00, 0x16,
        0x11, 0xE0, 0x00, 0x00,
        0x00, 0x01, 0x00,
        0xC0, 0x01, 0x0A,
        0xC1, 0x02, 0x01, 0x00,
        0xC2, 0x02, 0x01, 0x02
    ])
    return s7_packet

print("[*] Sending S7 traffic to Conpot...")

for i in range(20):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(('127.0.0.1', 10201))
        sock.send(send_s7_request('127.0.0.1', 10201))
        response = sock.recv(256)
        sock.close()
        print(f"S7 Read {i+1}: OK - {len(response)} bytes")
    except Exception as e:
        print(f"S7 Read {i+1}: Error - {e}")
    time.sleep(1)

print("[*] S7 Done.")