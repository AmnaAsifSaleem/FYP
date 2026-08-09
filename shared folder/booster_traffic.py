import socket
S7 = bytes([0x03,0x00,0x00,0x16,0x11,0xe0,0x00,0x00,0x00,0x01,0x00,
            0xc0,0x01,0x0a,0xc1,0x02,0x01,0x00,0xc2,0x02,0x01,0x02])
for i in range(5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(('127.0.0.1', 10203))
        sock.send(S7)
        try: sock.recv(256)
        except: pass
        sock.close()
        print(f"Reservoir {i+1}: OK")
    except Exception as e:
        print(f"Reservoir {i+1}: {e}")