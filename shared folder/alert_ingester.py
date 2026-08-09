import json
import re
from datetime import datetime

def parse_fast_log(log_file):
    alerts = []
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Parse fast.log format:
                # 03/11/2026-20:31:24 [**] [1:9000001:1] msg [**] ... IP:port -> IP:port
                
                # Extract message
                msg_match = re.search(r'\[\*\*\] \[.*?\] (.+?) \[\*\*\]', line)
                if not msg_match:
                    continue
                msg = msg_match.group(1).strip()
                
                # Extract ports
                port_match = re.search(r'-> [\d\.]+:(\d+)', line)
                if not port_match:
                    continue
                dest_port = int(port_match.group(1))
                
                # Extract source IP
                src_match = re.search(r'(\d+\.\d+\.\d+\.\d+):\d+ -> ', line)
                src_ip = src_match.group(1) if src_match else "unknown"
                
                # Determine severity based on message
                if "Attack" in msg or "Rapid" in msg:
                    severity = 1  # critical
                elif "Write" in msg:
                    severity = 2  # high
                else:
                    severity = 3  # medium

                alerts.append({
                    "message":   msg,
                    "dest_port": dest_port,
                    "src_ip":    src_ip,
                    "severity":  severity
                })
    
    except FileNotFoundError:
        print(f"[!] Log file not found: {log_file}")
    
    return alerts

def update_model_input(model_input_file, alerts):
    
    with open(model_input_file, 'r') as f:
        records = json.load(f)
    
    for record in records:
        port = record["port"]
        
        # Find alerts matching this asset port
        matching = [a for a in alerts if a["dest_port"] == port]
        
        if matching:
            record["alert_count"]    = len(matching)
            record["alert_severity"] = min(a["severity"] for a in matching)
            record["is_attacked"]    = 1 if any(
                a["severity"] == 1 for a in matching
            ) else 0
        else:
            record["alert_count"]    = 0
            record["alert_severity"] = 0
            record["is_attacked"]    = 0
    
    with open(model_input_file, 'w') as f:
        json.dump(records, f, indent=2)
    
    print(f"[+] Updated {len(records)} records with Suricata alerts")
    return records

def show_summary(records):
    print("\n" + "="*60)
    print("   SURICATA ALERT SUMMARY")
    print("="*60)
    
    for r in records:
        attacked = "🔴 UNDER ATTACK" if r["is_attacked"] else "🟢 Normal"
        print(f"\n  {r['service']} | {r['device_type']} | Port {r['port']}")
        print(f"  CVE: {r['cve_id']} | CVSS: {r['cvss']}")
        print(f"  Alerts: {r['alert_count']} | Severity: {r['alert_severity']} | {attacked}")
        print("-"*60)

if __name__ == "__main__":
    print("[*] Reading Suricata alerts...")
    alerts = parse_fast_log("/var/log/suricata/fast.log")
    print(f"[+] Found {len(alerts)} alerts")
    
    print("[*] Updating model_input.json...")
    records = update_model_input("model_input.json", alerts)
    
    show_summary(records)
    print("\n[+] model_input.json updated with Suricata context")
    print("[+] alert_count, alert_severity, is_attacked filled")
    print("[+] Ready for ML risk scoring")