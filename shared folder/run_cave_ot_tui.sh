#!/bin/bash
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}================================================${NC}"
echo "  CAVE-OT TUI Pipeline Starting"
echo -e "${GREEN}================================================${NC}"

# Fix suricata log dir
sudo mkdir -p /var/log/suricata

# Clean old files
rm -f /home/caveot/cave_ot_test/test_all.pcap
rm -f /home/caveot/cave_ot_test/assets.json
rm -f /home/caveot/cave_ot_test/suricata_context.json
rm -f /var/log/suricata/fast.log

echo -e "${YELLOW}[*] Launching TUI pipeline...${NC}"
cd /home/caveot/cave_ot_test
sudo python3 tui_pipeline.py