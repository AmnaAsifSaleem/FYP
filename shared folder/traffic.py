import socket
import struct
import time

def send_modbus_request(ip, port):
    # Build raw Modbus TCP packet manually
    # No pymodbus needed
    transaction_id = 0x0001
    protocol_id    = 0x0000
    length         = 0x0006
    unit_id        = 0x01
    function_code  = 0x03  # Read Holding Registers
    start_address  = 0x0000
    quantity       = 0x000A

    packet = struct.pack('>HHHBBHH',
        transaction_id,
        protocol_id,
        length,
        unit_id,
        function_code,
        start_address,
        quantity
    )
    return packet

print("[*] Connecting to Conpot PLC...")

for i in range(20):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(('127.0.0.1', 502))

        request = send_modbus_request('127.0.0.1', 502)
        sock.send(request)

        response = sock.recv(256)
        sock.close()

        print(f"Read {i+1}: OK - Response bytes: {len(response)}")

    except Exception as e:
        print(f"Read {i+1}: Error - {e}")

    time.sleep(1)

print("[*] Done.")