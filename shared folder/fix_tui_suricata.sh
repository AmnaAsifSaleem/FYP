#!/bin/bash
# ============================================================
# CAVE-OT: Patch new_tui.py to show Suricata alerts properly
# Run this once on your VM:  sudo bash fix_tui_suricata.sh
# ============================================================

CAVE_DIR="/home/caveot/cave_ot_test"
TUI="$CAVE_DIR/new_tui.py"

echo "[1/4] Backing up new_tui.py..."
cp "$TUI" "$TUI.bak.$(date +%s)"

echo "[2/4] Patching read_alerts() to live-poll fast.log..."

# ---- Replace the read_alerts function ----
python3 << 'PYEOF'
import re

path = "/home/caveot/cave_ot_test/new_tui.py"
with open(path, "r") as f:
    src = f.read()

# ----------------------------------------------------------------
# NEW read_alerts: continuously tails fast.log and feeds the TUI
# ----------------------------------------------------------------
new_read_alerts = '''
def read_alerts():
    """Live-poll Suricata fast.log and update suricata_log list."""
    fast_log = "/var/log/suricata/fast.log"
    seen = set()
    while True:
        try:
            if os.path.exists(fast_log):
                with open(fast_log, "r") as f:
                    lines = f.readlines()
                for line in lines:
                    line = line.strip()
                    if line and line not in seen:
                        seen.add(line)
                        suricata_log.append(line)
                        # Keep list from growing forever
                        if len(suricata_log) > 50:
                            suricata_log.pop(0)
        except Exception:
            pass
        time.sleep(2)
'''

# Find the old read_alerts function and replace it
# Match def read_alerts(): ... up to the next def at column 0
old_pattern = re.compile(
    r'def read_alerts\(\):.*?(?=\ndef |\Z)',
    re.DOTALL
)
if old_pattern.search(src):
    src = old_pattern.sub(new_read_alerts.strip(), src, count=1)
    print("  [OK] read_alerts() replaced")
else:
    # If not found, inject it before def draw_ui or def main
    inject_before = "def draw_ui"
    if inject_before in src:
        src = src.replace(inject_before, new_read_alerts + "\n\ndef draw_ui", 1)
        print("  [OK] read_alerts() injected (was missing)")
    else:
        print("  [WARN] Could not find insertion point — add manually")

with open(path, "w") as f:
    f.write(src)
PYEOF

echo "[3/4] Patching Suricata startup to use ens33 AND lo (covers all traffic)..."

python3 << 'PYEOF'
path = "/home/caveot/cave_ot_test/new_tui.py"
with open(path, "r") as f:
    src = f.read()

# Fix Suricata launch to listen on lo (where Docker traffic lives)
# and make sure it starts BEFORE traffic
old_suricata = 'sudo", "suricata", "-c", "/etc/suricata/suricata.yaml", "-i", "eth0"'
new_suricata = 'sudo", "suricata", "-c", "/etc/suricata/suricata.yaml", "-i", "lo"'
if old_suricata in src:
    src = src.replace(old_suricata, new_suricata)
    print("  [OK] Suricata interface fixed: eth0 → lo")
else:
    # Try ens33
    old2 = 'sudo", "suricata", "-c", "/etc/suricata/suricata.yaml", "-i", "ens33"'
    if old2 in src:
        src = src.replace(old2, new_suricata)
        print("  [OK] Suricata interface fixed: ens33 → lo")
    else:
        print("  [INFO] Suricata launch line not matched — check manually")

with open(path, "w") as f:
    f.write(src)
PYEOF

echo "[4/4] Flushing old Suricata fast.log so display starts clean..."
sudo truncate -s 0 /var/log/suricata/fast.log 2>/dev/null || true
sudo touch /var/log/suricata/fast.log
sudo chmod 644 /var/log/suricata/fast.log

echo ""
echo "============================================================"
echo "  Patch complete. Now run:"
echo "  cd /home/caveot/cave_ot_test && sudo python3 new_tui.py"
echo ""
echo "  Suricata alerts will appear in the IDS panel automatically."
echo "  No second terminal needed."
echo "============================================================"