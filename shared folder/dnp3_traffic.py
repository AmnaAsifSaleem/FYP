import socket
import time

def send_dnp3_request():
    # DNP3 Data Link Layer frame
    # Read Class 0 data (water level sensors)
    dnp3_packet = bytes([
        0x05, 0x64,  # Start bytes
        0x14,        # Length
        0x44,        # Control
        0x01, 0x00,  # Destination (RTU address 1)
        0x03, 0x00,  # Source (master address 3)
        0xE9, 0x21,  # CRC
        0xC0, 0x01,  # Transport + Application
        0x01,        # Function code: Read
        0x3C, 0x02,  # Object: Class 1 data
        0x06,        # Qualifier
        0x3C, 0x03,  # Object: Class 2 data
        0x06,        # Qualifier
        0x3C, 0x01,  # Object: Class 0 data
        0x06,        # Qualifier
    ])
    return dnp3_packet

print("[*] Sending DNP3 traffic (water level sensors)...")

for i in range(20):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(('127.0.0.1', 20000))
        sock.send(send_dnp3_request())
        try:
            response = sock.recv(256)
            print(f"DNP3 Read {i+1}: OK - {len(response)} bytes")
        except:
            print(f"DNP3 Read {i+1}: Sent OK - no response")
        sock.close()
    except Exception as e:
        print(f"DNP3 Read {i+1}: Error - {e}")
    time.sleep(1)

print("[*] DNP3 Done.")