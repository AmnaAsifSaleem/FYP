import socket
DNP3 = bytes([0x05,0x64,0x14,0x44,0x01,0x00,0x03,0x00,0xe9,0x21,
              0xc0,0x01,0x01,0x3c,0x02,0x06,0x3c,0x01,0x06])
for i in range(5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(('127.0.0.1', 20001))
        sock.send(DNP3)
        sock.close()
        print(f"FlowMeter {i+1}: Sent")
    except Exception as e:
        print(f"FlowMeter {i+1}: {e}")