"""Known packet fixtures verify the write signature independently of capture."""
import tempfile,pathlib,struct,subprocess,json
from scapy.all import Ether,IP,TCP,Raw,wrpcap
packets=[]
for port,function in ((31001,3),(31002,6)):
 a={'src':'192.0.2.2','dst':'192.0.2.1'};b={'src':'192.0.2.1','dst':'192.0.2.2'}
 request=struct.pack('>HHHBBHH',4242,0,6,1,function,0,1)
 packets.extend([Ether()/IP(**a)/TCP(sport=port,dport=502,flags='S',seq=100),Ether()/IP(**b)/TCP(sport=502,dport=port,flags='SA',seq=200,ack=101),Ether()/IP(**a)/TCP(sport=port,dport=502,flags='A',seq=101,ack=201),Ether()/IP(**a)/TCP(sport=port,dport=502,flags='PA',seq=101,ack=201)/Raw(request),Ether()/IP(**b)/TCP(sport=502,dport=port,flags='A',seq=201,ack=113)])
folder=pathlib.Path(tempfile.mkdtemp(prefix='caveot-ids-probe-'));pcap=folder/'probe.pcap';logs=folder/'logs';logs.mkdir();wrpcap(str(pcap),packets)
p=subprocess.run(['suricata','-c','/etc/suricata/suricata.yaml','-S','/var/lib/suricata/rules/ot-rules.rules','-k','none','-r',str(pcap),'-l',str(logs),'--runmode','single'],capture_output=True,text=True,timeout=30)
alerts=(logs/'fast.log').read_text() if (logs/'fast.log').exists() else ''
print(json.dumps({'exit_code':p.returncode,'write_detected':'WASA Modbus Dosing Pump Write Attempt' in alerts,'alerts':alerts,'diagnostics':p.stderr},indent=2))
