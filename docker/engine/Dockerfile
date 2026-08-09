# Build context is the REPO ROOT (see docker-compose.yml's `context: ..`),
# not this directory — so this Dockerfile can COPY the actual pipeline
# source files directly, rather than a separately-maintained duplicate.
# That's a deliberate choice: an earlier version of this migration kept a
# static copy of cave_monitor.py under docker/engine/app/, and it silently
# drifted from the repo's real copy within the same session. Building
# straight from the single canonical source makes that class of bug
# structurally impossible instead of just "remembered not to do."
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# System deps: suricata (IDS), tcpdump (pcap capture), python, libpcap for scapy
RUN apt-get update && apt-get install -y --no-install-recommends \
        suricata \
        tcpdump \
        iproute2 \
        libpcap0.8 \
        python3 \
        python3-pip \
        ca-certificates \
        sudo \
    && rm -rf /var/lib/apt/lists/*
# Container already runs as root, but cave_monitor.py's subprocess calls are
# prefixed with sudo throughout (matching the VM, where caveot was non-root).
# Installing sudo as a no-op-for-root shim means those calls keep working
# unmodified rather than needing every call site edited.

# Python deps for the pipeline (TF-IDF CVE matching, attack-path graph, discovery)
RUN pip3 install --no-cache-dir --break-system-packages \
        scapy \
        networkx \
        numpy \
        pandas \
        scikit-learn \
        joblib

# App code lives at the same path the VM used, so no in-code path changes needed
WORKDIR /home/caveot/cave_ot_test
COPY cave_monitor.py attack_path.py smart_discover.py cve_discovery.py anomaly_detector.py ./
COPY model/ ./model/

# Suricata expects its log dir
RUN mkdir -p /var/log/suricata

# cave_monitor.py invokes suricata with -c /etc/suricata/suricata.yaml (the
# STOCK apt-installed config). On the real VM, a human ran write_rules.sh
# once by hand to install ot-rules.rules into /var/lib/suricata/rules/ and
# edited /etc/suricata/suricata.yaml's rule-files list — that one-time manual
# step is replicated here at build time instead:
#   1. install ot-rules.rules where default-rule-path expects it
#   2. register it in rule-files (kept alongside the stock suricata.rules)
#   3. disable checksum validation for loopback capture — Docker's loopback
#      doesn't carry real checksums (the kernel skips them for local
#      delivery), so Suricata's "auto" detection silently rejected every
#      packet and produced zero alerts even though traffic matched real
#      rules (confirmed via a direct pcap-replay test with -k none). This
#      likely affects the VM too under some NIC/driver combinations — worth
#      spot-checking if its alert counts ever look suspiciously low.
COPY docker/engine/ot-rules.rules /tmp/ot-rules.rules
RUN mkdir -p /var/lib/suricata/rules \
    && cp /tmp/ot-rules.rules /var/lib/suricata/rules/ot-rules.rules \
    && sed -i 's/^  - suricata.rules$/  - suricata.rules\n  - ot-rules.rules/' /etc/suricata/suricata.yaml \
    && sed -i 's/^  checksum-checks: auto$/  checksum-checks: no/' /etc/suricata/suricata.yaml \
    && sed -i '/^pcap:$/a\  - interface: lo\n    checksum-checks: no' /etc/suricata/suricata.yaml

# CAVE_OT_DOCKER=1 tells cave_monitor.py's start_containers() there's no
# per-device container to `docker start` (see that function for the branch).
ENV CAVE_OT_DOCKER=1

CMD ["python3", "/home/caveot/cave_ot_test/cave_monitor.py"]
