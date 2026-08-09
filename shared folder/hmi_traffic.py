import socket
import time

def send_http_request():
    request = (
        "GET /index.html HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "User-Agent: WASA-SCADA/1.0\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    return request.encode()

print("[*] Sending HTTP traffic (HMI web interface)...")

for i in range(20):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(('127.0.0.1', 80))
        sock.send(send_http_request())
        try:
            response = sock.recv(1024)
            print(f"HMI Read {i+1}: OK - {len(response)} bytes")
        except:
            print(f"HMI Read {i+1}: Sent OK - no response")
        sock.close()
    except Exception as e:
        print(f"HMI Read {i+1}: Error - {e}")
    time.sleep(1)

print("[*] HMI Done.")