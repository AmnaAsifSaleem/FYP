import socket
import time

def send_bacnet_whois(ip, port):
    # BACnet Who-Is request
    # Standard device discovery packet
    bacnet_whois = bytes([
        0x81, 0x0b, 0x00, 0x0c,
        0x01, 0x20, 0xff, 0xff,
        0x00, 0xff, 0x10, 0x08
    ])
    return bacnet_whois

print("[*] Sending BACnet traffic to Conpot...")

for i in range(20):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        packet = send_bacnet_whois('127.0.0.1', 47808)
        sock.sendto(packet, ('127.0.0.1', 47808))
        
        try:
            response, addr = sock.recvfrom(1024)
            print(f"BACnet Read {i+1}: OK - {len(response)} bytes")
        except:
            print(f"BACnet Read {i+1}: Sent OK - no response")
        
        sock.close()
    except Exception as e:
        print(f"BACnet Read {i+1}: Error - {e}")
    time.sleep(1)

print("[*] BACnet Done.")