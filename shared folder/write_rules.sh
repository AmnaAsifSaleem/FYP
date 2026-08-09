#!/bin/bash
sudo python3 << 'PYEOF'
rules = [
'alert tcp any any -> any 502 (msg:"WASA Modbus Dosing Pump Connection"; flow:to_server,established; sid:9000001; rev:1;)',
'alert tcp any any -> any 502 (msg:"WASA Modbus Write Attempt"; flow:to_server,established; content:"|00 00 00 00 00 06|"; depth:6; sid:9000002; rev:1;)',
'alert tcp any any -> any 502 (msg:"WASA Modbus Rapid Connection Attack"; flow:to_server; threshold:type both,track by_src,count 15,seconds 3; sid:9000003; rev:1;)',
'alert tcp any any -> any 10201 (msg:"WASA S7 Filtration PLC Connection"; flow:to_server,established; sid:9000004; rev:1;)',
'alert tcp any any -> any 10201 (msg:"WASA S7 Rapid Connection Attack"; flow:to_server; threshold:type both,track by_src,count 15,seconds 3; sid:9000005; rev:1;)',
'alert udp any any -> any 47808 (msg:"WASA BACnet Ventilation Packet"; sid:9000006; rev:1;)',
'alert tcp any any -> any 20000 (msg:"WASA DNP3 Water Level RTU Connection"; flow:to_server,established; sid:9000007; rev:1;)',
'alert tcp any any -> any 20000 (msg:"WASA DNP3 Rapid Attack"; flow:to_server; threshold:type both,track by_src,count 15,seconds 3; sid:9000008; rev:1;)',
'alert tcp any any -> any 5020 (msg:"WASA Modbus Water Quality Reading"; flow:to_server,established; sid:9000009; rev:1;)',
'alert tcp any any -> any 5020 (msg:"WASA Water Quality Rapid Attack"; flow:to_server; threshold:type both,track by_src,count 15,seconds 3; sid:9000010; rev:1;)',
'alert tcp any any -> any 6230 (msg:"WASA IPMI SCADA Server Access"; flow:to_server,established; sid:9000011; rev:1;)',
'alert tcp any any -> any 6230 (msg:"WASA IPMI Brute Force Attempt"; flow:to_server; threshold:type both,track by_src,count 5,seconds 10; sid:9000012; rev:1;)',
'alert tcp any any -> any 80 (msg:"WASA HMI Web Interface Access"; flow:to_server,established; sid:9000013; rev:1;)',
'alert tcp any any -> any 80 (msg:"WASA HMI Rapid Attack"; flow:to_server; threshold:type both,track by_src,count 30,seconds 3; sid:9000014; rev:1;)',
'alert tcp any any -> any 502 (msg:"WASA IT to OT Lateral Movement Modbus"; flow:to_server,established; sid:9000015; rev:1;)',
'alert tcp any any -> any 10201 (msg:"WASA IT to OT Lateral Movement S7"; flow:to_server,established; sid:9000016; rev:1;)',
'alert tcp any any -> any 20000 (msg:"WASA IT to OT Lateral Movement DNP3"; flow:to_server,established; sid:9000017; rev:1;)',
'alert tcp any any -> any 5031 (msg:"WASA Turbidity Sensor Reading"; flow:to_server,established; sid:9000018; rev:1;)',
'alert tcp any any -> any 5031 (msg:"WASA Turbidity Sensor Rapid Attack"; flow:to_server; threshold:type both,track by_src,count 15,seconds 3; sid:9000019; rev:1;)',
'alert tcp any any -> any 5032 (msg:"WASA UV Disinfection PLC Reading"; flow:to_server,established; sid:9000020; rev:1;)',
'alert tcp any any -> any 5032 (msg:"WASA UV Disinfection Rapid Attack"; flow:to_server; threshold:type both,track by_src,count 15,seconds 3; sid:9000021; rev:1;)',
'alert tcp any any -> any 10203 (msg:"WASA Reservoir Level PLC Connection"; flow:to_server,established; sid:9000022; rev:1;)',
'alert tcp any any -> any 10203 (msg:"WASA Reservoir Level Rapid Attack"; flow:to_server; threshold:type both,track by_src,count 15,seconds 3; sid:9000023; rev:1;)',
'alert tcp any any -> any 10204 (msg:"WASA Booster Pump Station Connection"; flow:to_server,established; sid:9000024; rev:1;)',
'alert tcp any any -> any 10204 (msg:"WASA Booster Pump Rapid Attack"; flow:to_server; threshold:type both,track by_src,count 15,seconds 3; sid:9000025; rev:1;)',
'alert tcp any any -> any 20001 (msg:"WASA Flow Meter RTU Connection"; flow:to_server,established; sid:9000026; rev:1;)',
'alert tcp any any -> any 20001 (msg:"WASA Flow Meter Rapid Attack"; flow:to_server; threshold:type both,track by_src,count 15,seconds 3; sid:9000027; rev:1;)',
'alert tcp any any -> any 8080 (msg:"WASA Backup HMI Interface Access"; flow:to_server,established; sid:9000028; rev:1;)',
'alert tcp any any -> any 8080 (msg:"WASA Backup HMI Rapid Attack"; flow:to_server; threshold:type both,track by_src,count 30,seconds 3; sid:9000029; rev:1;)',
]
with open('/var/lib/suricata/rules/ot-rules.rules','w') as f:
    f.write('\n'.join(rules))
print('Rules written successfully')
PYEOF
sudo suricata -T -c /etc/suricata/suricata.yaml