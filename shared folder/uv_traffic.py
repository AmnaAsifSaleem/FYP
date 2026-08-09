import socket, struct
for i in range(5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(('127.0.0.1', 5032))
        sock.send(struct.pack('>HHHBBHH', 0x0001,0x0000,0x0006,0x01,0x03,0x0000,0x000A))
        sock.recv(256)
        sock.close()
        print(f"UV {i+1}: OK")
    except Exception as e:
        print(f"UV {i+1}: {e}")