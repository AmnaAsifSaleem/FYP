"""Controlled read/write signatures against the Docker-only canned endpoint."""
import socket,struct,time,json
from pathlib import Path
LOG=Path('/var/log/suricata/fast.log')
def count():
    return sum('WASA Modbus Dosing Pump Write Attempt' in line for line in LOG.read_text().splitlines())
def send(function):
    packet=struct.pack('>HHHBBHH',4242,0,6,1,function,0,1)
    with socket.create_connection(('127.0.0.1',502),timeout=3) as client:
        client.sendall(packet);client.recv(256)
before=count();send(3);time.sleep(2);after_read=count();send(6)
deadline=time.monotonic()+15
after_write=count()
while after_write<=after_read and time.monotonic()<deadline:
    time.sleep(1);after_write=count()
result={'read_created_write_alert':after_read>before,'write_alert_detected':after_write>after_read,'target':'Container-local canned Modbus endpoint','counts':[before,after_read,after_write]}
print(json.dumps(result,indent=2))
if result['read_created_write_alert'] or not result['write_alert_detected']:raise SystemExit(1)
