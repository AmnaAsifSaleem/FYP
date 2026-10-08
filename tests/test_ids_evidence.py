import sys
from pathlib import Path
from unittest.mock import MagicMock
ROOT=Path(__file__).resolve().parents[1]
for path in (ROOT,ROOT/'Database'):sys.path.insert(0,str(path))

def test_fast_log_priority_and_destination_are_preserved(tmp_path):
 from smart_discover import read_suricata_alerts
 log=tmp_path/'fast.log'
 log.write_text('10/07/2026-00:00:00.000000 [**] [1:9000001:1] Ordinary connection Attack wording [**] [Priority: 3] {TCP} 192.0.2.2:51000 -> 192.0.2.1:502\n')
 event=read_suricata_alerts(str(log))[0]
 assert event['severity']==3 and event['src_ip']=='192.0.2.2' and event['dest_ip']=='192.0.2.1'

def test_signature_does_not_inherit_another_signatures_attack_priority():
 from sync_db import upsert_alerts
 cur=MagicMock()
 payload={'ip':'192.0.2.1','port':502,'service':'Modbus','alert_severity':1,'is_attacked':True,
          'alert_messages':['Normal connection','Rapid connection attack'],
          'alert_events':[{'message':'Normal connection','severity':3,'src_ip':'192.0.2.2','dest_ip':'192.0.2.1'},
                          {'message':'Rapid connection attack','severity':1,'src_ip':'192.0.2.3','dest_ip':'192.0.2.1'}]}
 assert upsert_alerts(cur,1,payload)==2
 values=[call.args[1] for call in cur.execute.call_args_list]
 assert values[0]['sev']==3 and values[0]['attack'] is False
 assert values[1]['sev']==1 and values[1]['attack'] is True
 assert values[0]['src_ip']=='192.0.2.2' and values[1]['src_ip']=='192.0.2.3'

def test_plaintext_transport_comes_from_payload_not_port():
 from smart_discover import observed_transport
 from scapy.all import IP,TCP,Raw
 assert observed_transport(IP()/TCP(dport=443)/Raw(b'HTTP/1.1 200 OK\r\n'),'HTTPS')==(False,'HTTP')
 assert observed_transport(IP()/TCP(dport=502)/Raw(b'arbitrary bytes'),'Modbus')==(None,None)
 assert observed_transport(IP()/TCP(dport=502)/Raw(b'\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01'),'Modbus')==(False,'Modbus')
