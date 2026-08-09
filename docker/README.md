# CAVE-OT — Docker Testbed

This replaces the VMware VM as the environment that runs the simulated
water-treatment plant: device honeypots, Suricata IDS, and
`cave_monitor.py`'s live discovery → CVE-mapping → risk-scoring →
attack-path pipeline. Same pipeline code (literally the same files — see
below), same output files, same host-side ingestion — just two Docker
containers instead of a 14GB VM.

**Why this exists:** the VM worked, but it's a single large file sitting on
one person's machine. Sharing it with teammates meant physically copying a VM
around. This is `git clone` + `docker compose up` — every teammate runs an
identical environment instead of "here's my copy, hope it still boots."

---

## Architecture

```
┌─────────────────────────── docker compose ───────────────────────────┐
│                                                                        │
│  ┌─────────────────────────┐        ┌──────────────────────────┐    │
│  │   engine (Ubuntu 24.04)  │        │  honeypot (python:slim)   │    │
│  │                          │        │                            │    │
│  │  cave_monitor.py         │◄──────►│  listener.py               │    │
│  │  smart_discover.py       │  same  │  binds all 15 device ports │    │
│  │  cve_discovery.py        │  net   │  (502, 10201, 20000, ...)  │    │
│  │  attack_path.py          │  ns    │  answers with a canned,    │    │
│  │  Suricata (watches lo)   │        │  protocol-flavoured reply  │    │
│  │  tcpdump                 │        │                            │    │
│  └───────────┬──────────────┘        └────────────────────────────┘    │
│              │ network_mode: "service:engine"                          │
│              │ (honeypot joins engine's namespace — NOT its own)       │
│              │                                                          │
│              │ bind mount                                              │
│              ▼                                                          │
│         ./shared  ◄────────────────────────────────────────────────┐  │
└──────────────┼───────────────────────────────────────────────────┘  │
               │                                                         │
               ▼  (same JSON files the VM produced)                     │
┌─────────────────────── Windows host ──────────────────────────────────┘
│  file_watcher.py → Database/sync_db.py → PostgreSQL → Dashboard/app.py │
│  (unchanged from the VM setup — same ingestion path)                  │
└─────────────────────────────────────────────────────────────────────┘
```

### Single source of truth — no separately-maintained copy

`engine/Dockerfile` builds with the **repo root as its build context**
(`context: ..` in `docker-compose.yml`) and `COPY`s `cave_monitor.py`,
`attack_path.py`, `smart_discover.py`, `cve_discovery.py`, and `model/*.pkl`
**directly from the repo root** — the same files used for host-side testing,
not a duplicate living under `docker/`.

This is a deliberate reaction to a real bug hit during development: the
repo's `cave_monitor.py` and the VM's own copy had silently diverged (device
roster, concurrency handling) without anyone noticing until something broke.
An early version of this Docker setup repeated that exact mistake with a
static `docker/engine/app/` copy that drifted from the repo within the same
session it was created. Building straight from the canonical source makes
that whole class of bug structurally impossible instead of relying on
remembering to keep two copies in sync.

`cave_monitor.py` itself has one small environment-aware branch for this:
`start_containers()` checks `CAVE_OT_DOCKER` (set to `1` in the Dockerfile).
On the VM (unset), it runs real per-device `docker start` calls. In this
testbed, there's a single multi-port listener already up from container
start, so that branch is skipped — everything else (the delayed-asset timing
simulation, status transitions, discovery triggers) runs identically either
way.

### The one non-obvious design decision: `network_mode: "service:engine"`

The pipeline assumes every device lives at `127.0.0.1:<port>` —
`smart_discover.py` sniffs `lo`, Suricata watches `lo`, `cave_monitor.py`
talks to `127.0.0.1:502` etc. directly. Containers don't share a network
namespace by default — two containers get two different `localhost`s, and
none of the discovery/IDS code would see anything.

`network_mode: "service:engine"` on the `honeypot` service makes it share the
`engine` container's network namespace entirely. Both containers now see one
`127.0.0.1`, one `lo` interface, one set of ports — exactly like the VM.
Nothing in the pipeline's networking code needed to change.

### Why a custom `listener.py` instead of real Conpot

The VM used `honeynet/conpot`, but Conpot only serves its own default ports
(502, 102, 161, 80, 47808, 623). This plant's port scheme is custom
(10201, 5031, 5032, 20001, 2222, 10203, 10204, ...) and would need extensive
per-device Conpot templates to serve correctly. `honeypot/listener.py` is
~110 lines: it binds exactly the 15 ports this plant needs and replies with a
small protocol-flavoured blob per port. Discovery and Suricata both key off
the **destination port**, not deep protocol state — so faithful port
coverage matters far more than a fully accurate Modbus/S7 state machine.

---

## Quickstart

**Prerequisites:**
1. Docker Desktop installed and running (WSL2 backend). Check with `docker info` — if that hangs or errors, start Docker Desktop from the Start Menu and wait ~30-60s.
2. The trained OT CVE model must exist at `model/ot_vectorizer.pkl`,
   `model/ot_matrix.pkl`, `model/ot_cve_database.pkl` (repo root). These are
   gitignored (too large for git) — if you just cloned the repo, run
   `python Model_Training/model_trainer.py` first (see the main repo README).

**Run it:**
```
cd docker
docker compose up -d
```
Two containers start, `cave_monitor.py` launches automatically inside
`engine`, and within ~15-40 seconds the first discovery cycle completes.

**Watch it running:**
```
docker logs -f caveot-engine
```
Shows the same live TUI the VM had — asset table, sensor readings, Suricata
alerts, CVE risk scores.

**Check it's producing real output:**
```
dir shared
```
You should see `assets.json`, `risk_scored_results.json`,
`vulnerability_scan_results.json`, `suricata_context.json`, and
`attack_paths.json`, all refreshing every cycle. `shared/` is gitignored —
it's generated runtime output, same as it always was on the VM.

**Stop it:**
```
docker compose down
```
Nothing is lost — containers are disposable by design. `docker compose up -d`
next time rebuilds them fresh. The only thing that persists across runs is
whatever's in `./shared`.

---

## Connecting it to the dashboard (host side)

`file_watcher.py`'s `WATCH_DIR` and `Database/sync_db.py`'s `_SHARED` should
point at this folder's `shared/` directory (already set that way in this
repo — check both if you've moved the repo somewhere else).

Then, from the repo root:
```
python file_watcher.py
python Dashboard/app.py
```
Open `http://localhost:5000` — same dashboard, same pages, sourced from
Docker instead of the VM.

---

## What's genuinely different from the VM (and why)

| VM behaviour | Docker equivalent | Why |
|---|---|---|
| 13 separate Conpot containers, one per device group, `docker start <name>` per device | 1 honeypot container, all ports live from the start | No per-device container to start; `cave_monitor.py`'s delayed-asset *timing simulation* is preserved (status transitions, discovery triggers) via the `CAVE_OT_DOCKER` env check in `start_containers()` — see above |
| VMware hgfs shared folder | Docker bind mount at the identical guest path (`/mnt/hgfs/shared folder`) | Zero code changes to `sync_to_shared()` — it writes to the same path either way |
| Non-root `caveot` user, real `sudo` | Root by default, `sudo` installed as a shim | `cave_monitor.py`'s subprocess calls are `sudo`-prefixed throughout; installing `sudo` (a no-op for root) meant zero call-site edits |
| Human manually ran `write_rules.sh` once during VM setup to install `ot-rules.rules` and hand-edit `/etc/suricata/suricata.yaml` | Same steps, done at image build time (`engine/Dockerfile`) | Reproducible instead of a manual one-time setup step |

## Bugs found during this migration (not Docker-specific — latent in the original setup too)

1. **Suricata's checksum validation silently dropped all loopback traffic.**
   The kernel doesn't compute real checksums for local delivery, and
   Suricata's default `checksum-checks: auto` rejected every packet —
   meaning **zero IDS alerts fired**, even though traffic matched real rules.
   Confirmed via a direct pcap-replay test with `-k none`. Fixed by setting
   `checksum-checks: no` for both live capture and pcap-file replay. This
   likely affects the VM too depending on its NIC/driver setup — worth
   spot-checking if the VM's alert counts ever looked suspiciously low.

2. **`ot-rules.rules` has a paste artifact at the top** in the original
   VM/repo copy (`shared folder/ot-rules.rules`) — it literally starts with
   `sudo nano /var/lib/suricata/rules/ot-rules.rules` and a markdown code
   fence, as if someone pasted straight from a setup guide instead of just
   the rules. Suricata silently skips the malformed lines. The cleaned copy
   lives at `docker/engine/ot-rules.rules`; the original `shared folder/`
   copy hasn't been fixed (only worked around here).

---

## Troubleshooting

**`docker info` hangs or the daemon won't respond:** Docker Desktop has shown
intermittent instability during development (both a corrupted internal
socket file and a wedged daemon state). Escalating fixes, in order:
1. Quit and relaunch Docker Desktop
2. Kill all `*docker*`-named processes in Task Manager, then relaunch
3. `wsl --shutdown` (forces WSL2's VM to fully reset), then relaunch Docker Desktop
4. Reboot Windows — reliably fixed it every time this was tried

**Containers show `Exited (137)`:** SIGKILL — normal after a Docker Desktop
restart/crash or a full reboot. Just `docker compose up -d` again.

**Container name conflict** (`"/caveot-engine" is already in use`): an old
stack with the same container names still exists. `docker rm -f caveot-engine
caveot-honeypot` then `docker compose up -d`.

**Rebuilt the image but old behaviour persists:** force it —
```
docker compose up -d --force-recreate
```
If that's still not picking up changes, rebuild without cache:
```
docker compose build --no-cache engine
```

**`sudo: command not found` inside the container:** the image wasn't
rebuilt after a Dockerfile change — `docker compose build engine` then
`docker compose up -d --force-recreate`.

**Windows path errors when running `docker exec` commands with Unix paths
from Git Bash:** Git Bash auto-translates `/var/log/...`-style paths into
Windows paths. Prefix the command with `MSYS_NO_PATHCONV=1`.

---

## TODO / not done yet

- No restart policy — containers don't auto-restart if they crash. Fine for
  development; add `restart: unless-stopped` before treating this as
  "always-on."
- `shared folder/ot-rules.rules` (the original, human-maintained copy used by
  the VM) still has the paste-artifact bug described above — only the Docker
  copy (`docker/engine/ot-rules.rules`) has been cleaned up.
- `shared folder/` more broadly still has stale copies of `cave_monitor.py`,
  `smart_discover.py`, etc. that have already drifted from the repo-root
  versions this Docker build actually uses — see the main repo's `TODO.md`
  item about file/VM layout restructuring.
