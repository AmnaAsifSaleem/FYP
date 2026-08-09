import socket
REQ = b"GET /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
for i in range(5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(('127.0.0.1', 8080))
        sock.send(REQ)
        sock.close()
        print(f"BackupHMI {i+1}: Sent")
    except Exception as e:
        print(f"BackupHMI {i+1}: {e}")