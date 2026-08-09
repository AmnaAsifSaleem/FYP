#!/bin/bash
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
CAVE_DIR="/home/caveot/cave_ot_test"

echo -e "${GREEN}================================================${NC}"
echo "  CAVE-OT: Water Treatment Plant Pipeline"
echo -e "${GREEN}================================================${NC}"

# Step 1: Start main Conpot
echo -e "${YELLOW}[Step 1] Starting Conpot...${NC}"
sudo docker rm -f conpot 2>/dev/null
sudo docker run -d -p 502:502 -p 10201:10201 -p 47808:47808 -p 6230:6230 -p 20000:20000 -p 5020:5020 -p 80:80 --name conpot honeynet/conpot
sleep 5
echo -e "${GREEN}[+] Conpot running${NC}"

# Step 2: Clean old files
echo -e "${YELLOW}[Step 2] Cleaning...${NC}"
rm -f $CAVE_DIR/test_all.pcap
rm -f $CAVE_DIR/assets.json
rm -f $CAVE_DIR/suricata_context.json
rm -f /var/log/suricata/fast.log
echo -e "${GREEN}[+] Clean done${NC}"

# Step 3: Start tcpdump
echo -e "${YELLOW}[Step 3] Starting capture (500 packets)...${NC}"
sudo tcpdump -i lo -w $CAVE_DIR/test_all.pcap -c 500 &
TCPDUMP_PID=$!
sleep 2

# Step 4: Run coordinator
echo -e "${YELLOW}[Step 4] Running SCADA coordinator...${NC}"
python3 $CAVE_DIR/coordinator.py &

# Step 5: Run all traffic generators
echo -e "${YELLOW}[Step 5] Running traffic generators...${NC}"
python3 $CAVE_DIR/traffic.py &
python3 $CAVE_DIR/s7_traffic.py &
python3 $CAVE_DIR/bacnet_traffic.py &
python3 $CAVE_DIR/dnp3_traffic.py &
python3 $CAVE_DIR/waterquality_traffic.py &
python3 $CAVE_DIR/hmi_traffic.py &
python3 $CAVE_DIR/turbidity_traffic.py &
python3 $CAVE_DIR/uv_traffic.py &
python3 $CAVE_DIR/reservoir_traffic.py &
python3 $CAVE_DIR/booster_traffic.py &
python3 $CAVE_DIR/flowmeter_traffic.py &
python3 $CAVE_DIR/backup_hmi_traffic.py &

# Step 6: Wait for capture
echo -e "${YELLOW}[Step 6] Waiting for capture to finish...${NC}"
wait $TCPDUMP_PID
echo -e "${GREEN}[+] Capture complete${NC}"

# Step 7: Run Suricata
echo -e "${YELLOW}[Step 7] Running Suricata...${NC}"
sudo suricata -r $CAVE_DIR/test_all.pcap -l /var/log/suricata/ -c /etc/suricata/suricata.yaml
echo -e "${GREEN}[+] Suricata done${NC}"

# Step 8: Run discovery
echo -e "${YELLOW}[Step 8] Running smart discovery...${NC}"
cd $CAVE_DIR && sudo python3 smart_discover.py
echo -e "${GREEN}[+] Discovery complete${NC}"

echo -e "${GREEN}================================================"
echo "  PIPELINE COMPLETE"
echo "  assets.json          -> feed into model"
echo "  suricata_context.json -> alert context"
echo "================================================${NC}"