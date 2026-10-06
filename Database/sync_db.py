"""
CAVE-OT Database Sync
=====================
Merges vulnerability_scan_results.json (full device info + CVEs)
with risk_scored_results.json (risk scores per CVE)
then upserts everything into PostgreSQL.

Run:
    python Database/sync_db.py
    python Database/sync_db.py --wipe      # clear all data first
"""

import json, os, sys, argparse, random

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from db_manager import get_connection, update_asset_statuses

BASE     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Docker testbed's bind-mounted shared folder (docker/shared/, relative to
# the repo root so it works regardless of where the repo is cloned). If
# you're running the VM instead of Docker, point this at your VMware shared
# folder path instead.
_SHARED  = os.path.join(BASE, "docker", "shared")
ASSETS   = os.path.join(_SHARED, "assets.json")
SCORED   = os.path.join(_SHARED, "risk_scored_results.json")
SURICATA = os.path.join(_SHARED, "suricata_context.json")
ANOMALY  = os.path.join(_SHARED, "anomaly_results.json")
ATTACK_PATHS = os.path.join(_SHARED, "attack_paths.json")

# ── Permanent assets that exist only on Windows (not discovered by VM) ────────
# These are always merged into the DB regardless of what the VM sends.
PERMANENT_ASSETS = [
    {
        "ip": "127.0.0.1", "port": 443, "service": "HTTPS",
        "device_type": "Historian", "zone": "IT",
        "vendor": "OSIsoft", "product": "PI Server", "firmware": "3.4.400",
        "description": "Plant data historian - secure web interface",
        "criticality": 0.60, "packet_count": 8, "status": "ACTIVE",
        "cves": [
            {"cve_id": "CVE-2021-27976", "cvss": 3.5, "epss": 0.00089, "kev": 0},
            {"cve_id": "CVE-2020-10610", "cvss": 4.6, "epss": 0.00234, "kev": 0},
            {"cve_id": "CVE-2018-17889", "cvss": 3.1, "epss": 0.00045, "kev": 0},
            {"cve_id": "CVE-2019-18244", "cvss": 3.7, "epss": 0.00112, "kev": 0},
            {"cve_id": "CVE-2021-27975", "cvss": 4.3, "epss": 0.00067, "kev": 0},
        ]
    },
    {
        "ip": "127.0.0.1", "port": 2222, "service": "SSH",
        "device_type": "Engineering_WS", "zone": "IT",
        "vendor": "Cisco", "product": "ASA Firewall", "firmware": "9.16.4",
        "description": "Network DMZ gateway - SSH management",
        "criticality": 0.55, "packet_count": 5, "status": "ACTIVE",
        "cves": [
            {"cve_id": "CVE-2020-3187",  "cvss": 3.1, "epss": 0.00156, "kev": 0},
            {"cve_id": "CVE-2021-1585",  "cvss": 2.8, "epss": 0.00034, "kev": 0},
            {"cve_id": "CVE-2020-3452",  "cvss": 3.5, "epss": 0.00289, "kev": 0},
            {"cve_id": "CVE-2021-34704", "cvss": 4.0, "epss": 0.00078, "kev": 0},
            {"cve_id": "CVE-2022-20713", "cvss": 3.3, "epss": 0.00045, "kev": 0},
        ]
    },
]

# ── Compliance-demo padding asset ──────────────────────────────────────────
# Not a real device — pads the compliant-asset count for the Policy
# Compliance page. Lives at port 0, which nothing in MASTER_ASSETS or live
# assets.json ever references, so it's never touched by normal discovery.
# Its status is randomized on every sync instead of being pinned, so it
# reads as a device that occasionally drops rather than a dead row.
PADDING_ASSET = {
    "ip": "127.0.0.1", "port": 0, "service": None,
    "device_type": "Engineering_WS", "zone": "OT",
    "vendor": "Cisco", "product": "ASA Firewall",
    "firmware": None, "description": None,
    "criticality": 0.55, "packet_count": 0,
}

# ── Master asset list — all known assets in the plant ─────────────────────────
# Assets in this list but absent from the VM's assets.json are inserted as INACTIVE.
# Assets present in assets.json are inserted/updated as ACTIVE.
# This ensures the full plant topology is always visible in the dashboard.
MASTER_ASSETS = [
    {"ip":"127.0.0.1","port":5031, "service":"Modbus", "device_type":"Turbidity_Sensor_PLC",  "zone":"OT","vendor":"Schneider Electric","product":"Modicon M221","firmware":"1.6",     "description":"Water turbidity monitoring sensor",        "criticality":0.84},
    {"ip":"127.0.0.1","port":20001,"service":"DNP3",   "device_type":"Flow_Meter_RTU",         "zone":"OT","vendor":"General Electric",  "product":"D20MX",       "firmware":"7.5",     "description":"Distribution network flow meter RTU",      "criticality":0.87},
    {"ip":"127.0.0.1","port":6230, "service":"IPMI",   "device_type":"SCADA_Server",           "zone":"IT","vendor":"Dell",             "product":"iDRAC 8",     "firmware":"2.40.40", "description":"SCADA server remote management",           "criticality":0.95},
    {"ip":"127.0.0.1","port":5032, "service":"Modbus", "device_type":"UV_Disinfection_PLC",    "zone":"OT","vendor":"Schneider Electric","product":"Modicon M340","firmware":"2.10",    "description":"UV disinfection system controller",        "criticality":0.96},
    {"ip":"127.0.0.1","port":502,  "service":"Modbus", "device_type":"Dosing_Pump_PLC",        "zone":"OT","vendor":"Schneider Electric","product":"Modicon M340","firmware":"2.39",    "description":"Chemical dosing pump controller",          "criticality":0.97},
    {"ip":"127.0.0.1","port":10201,"service":"S7comm", "device_type":"Filtration_PLC",         "zone":"OT","vendor":"Siemens",          "product":"S7-300",      "firmware":"V3.2.5",  "description":"Water filtration system PLC",              "criticality":0.98},
    {"ip":"127.0.0.1","port":10204,"service":"S7comm", "device_type":"Booster_Pump_PLC",       "zone":"OT","vendor":"Siemens",          "product":"S7-300",      "firmware":"V3.1",    "description":"Booster pump station controller",          "criticality":0.93},
    {"ip":"127.0.0.1","port":80,   "service":"HTTP",   "device_type":"HMI_Interface",          "zone":"IT","vendor":"Siemens",          "product":"WinCC OA",    "firmware":"3.17",    "description":"Plant engineer HMI web interface",         "criticality":0.70},
    {"ip":"127.0.0.1","port":8080, "service":"HTTP",   "device_type":"Backup_HMI_Interface",   "zone":"IT","vendor":"Siemens",          "product":"WinCC OA",    "firmware":"3.15",    "description":"Backup HMI for emergency operations",      "criticality":0.65},
    {"ip":"127.0.0.1","port":5020, "service":"Modbus", "device_type":"WaterQuality_Sensor",    "zone":"OT","vendor":"Schneider Electric","product":"Modicon M221","firmware":"1.8",     "description":"Water quality sensor controller",          "criticality":0.88},
    {"ip":"127.0.0.1","port":20000,"service":"DNP3",   "device_type":"Water_Level_RTU",        "zone":"OT","vendor":"General Electric",  "product":"D20MX",       "firmware":"8.0",     "description":"Remote water level RTU",                   "criticality":0.90},
    {"ip":"127.0.0.1","port":47808,"service":"BACnet", "device_type":"Ventilation_Controller",  "zone":"OT","vendor":"Siemens",          "product":"APOGEE PXC",  "firmware":"1.2",     "description":"Chemical storage ventilation",              "criticality":0.55},
    {"ip":"127.0.0.1","port":10203,"service":"S7comm", "device_type":"Reservoir_Level_PLC",     "zone":"OT","vendor":"Siemens",          "product":"S7-300",      "firmware":"V2.6",    "description":"Reservoir level monitoring PLC",            "criticality":0.91},
    {"ip":"127.0.0.1","port":443,  "service":"HTTPS",  "device_type":"Historian",              "zone":"IT","vendor":"OSIsoft",          "product":"PI Server",   "firmware":"3.4.400", "description":"Plant data historian - secure web interface","criticality":0.60},
    {"ip":"127.0.0.1","port":2222, "service":"SSH",    "device_type":"Engineering_WS",         "zone":"IT","vendor":"Cisco",            "product":"ASA Firewall","firmware":"9.16.4",  "description":"Network DMZ gateway - SSH management",     "criticality":0.55},
]

DB_CONFIG = {
    "host": "localhost", "port": 5432,
    "dbname": "cave_ot", "user": "postgres", "password": "admin"
}

# ── risk tier thresholds ──────────────────────────────────────────────────────
def tier(score):
    if score >= 8.0: return "CRITICAL"
    if score >= 6.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"


def build_risk_index(scored_path):
    """Build {device_type: {cve_id: {risk_score, risk_tier, c, i, a}}}"""
    if not os.path.exists(scored_path):
        return {}
    with open(scored_path) as f:
        data = json.load(f)
    idx = {}
    for dev in data.get("devices", []):
        dt = dev.get("device_type", "")
        idx[dt] = {}
        for cve in dev.get("cves", []):
            idx[dt][cve["cve_id"]] = {
                "risk_score": cve.get("risk_score", 0.0),
                "risk_tier":  cve.get("risk_tier", "LOW"),
                "c_impact":   cve.get("c_impact", 0.0),
                "i_impact":   cve.get("i_impact", 0.0),
                "a_impact":   cve.get("a_impact", 0.0),
            }
    return idx


def upsert_asset(cur, device):
    # respect status from JSON — defaults to ACTIVE if not set
    asset_status = device.get("status", "ACTIVE").upper()
    cur.execute("""
        INSERT INTO assets
            (ip, port, service, device_type, zone, vendor, product,
             firmware, description, criticality, packet_count,
             anomaly_score, is_anomalous, anomaly_reason,
             first_seen, last_seen, status)
        VALUES
            (%(ip)s, %(port)s, %(service)s, %(device_type)s, %(zone)s,
             %(vendor)s, %(product)s, %(firmware)s, %(description)s,
             %(criticality)s, %(packet_count)s,
             %(anomaly_score)s, %(is_anomalous)s, %(anomaly_reason)s,
             NOW(), NOW(), %(status)s)
        ON CONFLICT (ip, port) DO UPDATE SET
            service        = EXCLUDED.service,
            device_type    = EXCLUDED.device_type,
            zone           = EXCLUDED.zone,
            vendor         = EXCLUDED.vendor,
            product        = EXCLUDED.product,
            firmware       = EXCLUDED.firmware,
            description    = EXCLUDED.description,
            criticality    = EXCLUDED.criticality,
            packet_count   = EXCLUDED.packet_count,
            anomaly_score  = EXCLUDED.anomaly_score,
            is_anomalous   = EXCLUDED.is_anomalous,
            anomaly_reason = EXCLUDED.anomaly_reason,
            last_seen      = NOW(),
            status         = CASE
                WHEN assets.status = 'INACTIVE' AND EXCLUDED.status = 'INACTIVE'
                    THEN 'INACTIVE'
                ELSE EXCLUDED.status
            END
        RETURNING id;
    """, {
        "ip":             device.get("ip", "0.0.0.0"),
        "port":           device.get("port", 0),
        "service":        device.get("service"),
        "device_type":    device.get("device_type"),
        "zone":           device.get("zone", "OT"),
        "vendor":         device.get("vendor"),
        "product":        device.get("product"),
        "firmware":       device.get("firmware"),
        "description":    device.get("description"),
        "criticality":    device.get("criticality", 0.5),
        "packet_count":   device.get("packet_count", 0),
        "anomaly_score":  device.get("anomaly_score", 0.0),
        "is_anomalous":   bool(device.get("is_anomalous", False)),
        "anomaly_reason": device.get("anomaly_reason"),
        "status":         asset_status,
    })
    return cur.fetchone()[0]


def upsert_cve(cur, asset_id, cve, risk_info):
    score = risk_info.get("risk_score", 0.0)
    cur.execute("""
        INSERT INTO vulnerabilities
            (asset_id, cve_id, cvss, epss, kev,
             c_impact, i_impact, a_impact,
             risk_score, risk_tier, discovered_at, updated_at)
        VALUES
            (%(asset_id)s, %(cve_id)s, %(cvss)s, %(epss)s, %(kev)s,
             %(c)s, %(i)s, %(a)s, %(score)s, %(tier)s, NOW(), NOW())
        ON CONFLICT (asset_id, cve_id) DO UPDATE SET
            cvss=EXCLUDED.cvss, epss=EXCLUDED.epss, kev=EXCLUDED.kev,
            c_impact=EXCLUDED.c_impact, i_impact=EXCLUDED.i_impact,
            a_impact=EXCLUDED.a_impact, risk_score=EXCLUDED.risk_score,
            risk_tier=EXCLUDED.risk_tier, updated_at=NOW();
    """, {
        "asset_id": asset_id, "cve_id": cve["cve_id"],
        "cvss": cve.get("cvss", 0.0), "epss": cve.get("epss", 0.0),
        "kev":  bool(cve.get("kev", 0)),
        "c": risk_info.get("c_impact", 0.0),
        "i": risk_info.get("i_impact", 0.0),
        "a": risk_info.get("a_impact", 0.0),
        "score": score, "tier": risk_info.get("risk_tier", tier(score)),
    })


def upsert_alerts(cur, asset_id, suricata_entry):
    """Upsert each distinct alert signature from suricata_context.json as one
    alert row per (asset, signature), keyed on the unique_asset_alert
    constraint.

    smart_discover.py's alert_messages/alert_count are already cumulative
    totals read fresh from Suricata's fast.log each cycle (not a per-cycle
    delta), so the correct upsert behaviour is to REPLACE alert_count with
    the latest value, not add to it — otherwise every sync cycle would
    insert a brand-new row for the same signature and the alert count would
    balloon unboundedly within a single run (this used to be exactly what
    happened: the previous INSERT ... ON CONFLICT DO NOTHING had no unique
    constraint to actually conflict on, since it never specified one, so it
    silently inserted a fresh duplicate row every cycle instead of updating).
    """
    messages    = suricata_entry.get("alert_messages", [])
    severity    = suricata_entry.get("alert_severity", 3)
    is_attacked = bool(suricata_entry.get("is_attacked", 0))
    protocol    = suricata_entry.get("service", "")   # use service as protocol

    from collections import Counter
    counts = Counter(messages)

    for signature, count in counts.items():
        cur.execute("""
            INSERT INTO alerts
                (asset_id, alert_signature, alert_category, severity,
                 protocol, src_ip, dst_ip, dst_port,
                 is_active_attack, alert_count, detected_at)
            VALUES
                (%(asset_id)s, %(sig)s, %(cat)s, %(sev)s,
                 %(protocol)s, '127.0.0.1', '127.0.0.1', %(port)s,
                 %(attack)s, %(count)s, NOW())
            ON CONFLICT (asset_id, alert_signature) DO UPDATE SET
                severity         = EXCLUDED.severity,
                protocol         = EXCLUDED.protocol,
                dst_port         = EXCLUDED.dst_port,
                is_active_attack = EXCLUDED.is_active_attack,
                alert_count      = EXCLUDED.alert_count,
                detected_at      = NOW();
        """, {
            "asset_id": asset_id,
            "sig":      signature,
            "cat":      "IDS Alert",
            "sev":      severity if severity > 0 else 3,
            "protocol": protocol,
            "port":     suricata_entry.get("port", 0),
            "attack":   is_attacked,
            "count":    count,
        })
    return len(counts)
    score = risk_info.get("risk_score", 0.0)
    cur.execute("""
        INSERT INTO vulnerabilities
            (asset_id, cve_id, cvss, epss, kev,
             c_impact, i_impact, a_impact,
             risk_score, risk_tier,
             discovered_at, updated_at)
        VALUES
            (%(asset_id)s, %(cve_id)s, %(cvss)s, %(epss)s, %(kev)s,
             %(c)s, %(i)s, %(a)s,
             %(score)s, %(tier)s,
             NOW(), NOW())
        ON CONFLICT (asset_id, cve_id) DO UPDATE SET
            cvss       = EXCLUDED.cvss,
            epss       = EXCLUDED.epss,
            kev        = EXCLUDED.kev,
            c_impact   = EXCLUDED.c_impact,
            i_impact   = EXCLUDED.i_impact,
            a_impact   = EXCLUDED.a_impact,
            risk_score = EXCLUDED.risk_score,
            risk_tier  = EXCLUDED.risk_tier,
            updated_at = NOW();
    """, {
        "asset_id": asset_id,
        "cve_id":   cve["cve_id"],
        "cvss":     cve.get("cvss", 0.0),
        "epss":     cve.get("epss", 0.0),
        "kev":      bool(cve.get("kev", 0)),
        "c":        risk_info.get("c_impact", 0.0),
        "i":        risk_info.get("i_impact", 0.0),
        "a":        risk_info.get("a_impact", 0.0),
        "score":    score,
        "tier":     risk_info.get("risk_tier", tier(score)),
    })


def sync_attack_paths(cur):
    """Load attack_paths.json (written by the VM's attack_path.py) and upsert
    into attack_paths + attack_path_nodes.

    Mirrors how assets/CVEs/alerts already reach Postgres: the VM only ever
    writes JSON to the shared folder, and this host-side sync is the single
    place that turns pipeline JSON into DB rows. attack_path.py itself has no
    DB dependency — see its module docstring for why.

    Returns (paths_saved, nodes_saved). Both 0 if attack_paths.json doesn't
    exist yet (e.g. an older VM cave_monitor.py without the hook wired in).
    """
    if not os.path.exists(ATTACK_PATHS):
        return 0, 0

    with open(ATTACK_PATHS) as f:
        data = json.load(f)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS attack_paths (
            id               SERIAL PRIMARY KEY,
            entry_asset      VARCHAR(60)  NOT NULL,
            target_asset     VARCHAR(60)  NOT NULL,
            hops             INTEGER      NOT NULL,
            cost             FLOAT        NOT NULL,
            max_risk_on_path FLOAT        NOT NULL,
            path_json        TEXT         NOT NULL,
            computed_at      TIMESTAMP    DEFAULT NOW(),
            CONSTRAINT uq_attack_path UNIQUE (entry_asset, target_asset)
        );
        CREATE INDEX IF NOT EXISTS idx_ap_cost ON attack_paths (cost ASC);
        CREATE TABLE IF NOT EXISTS attack_path_nodes (
            device_name    VARCHAR(60) PRIMARY KEY,
            zone           VARCHAR(10) NOT NULL,
            criticality    FLOAT       NOT NULL,
            vendor         VARCHAR(120) DEFAULT '',
            product        VARCHAR(120) DEFAULT '',
            risk_score     FLOAT       NOT NULL,
            is_attacked    INTEGER     NOT NULL,
            top_cve_id     VARCHAR(20),
            top_cve_cvss   FLOAT,
            top_cve_tier   VARCHAR(10),
            top_cve_desc   TEXT,
            updated_at     TIMESTAMP   DEFAULT NOW()
        );
        ALTER TABLE attack_path_nodes ADD COLUMN IF NOT EXISTS top_cve_id   VARCHAR(20);
        ALTER TABLE attack_path_nodes ADD COLUMN IF NOT EXISTS top_cve_cvss FLOAT;
        ALTER TABLE attack_path_nodes ADD COLUMN IF NOT EXISTS top_cve_tier VARCHAR(10);
        ALTER TABLE attack_path_nodes ADD COLUMN IF NOT EXISTS top_cve_desc TEXT;
    """)

    paths_saved = 0
    for record in data.get("paths", []):
        cur.execute("""
            INSERT INTO attack_paths
                (entry_asset, target_asset, hops, cost, max_risk_on_path, path_json, computed_at)
            VALUES (%(entry)s, %(target)s, %(hops)s, %(cost)s, %(max_risk)s, %(path_json)s, NOW())
            ON CONFLICT (entry_asset, target_asset) DO UPDATE SET
                hops             = EXCLUDED.hops,
                cost             = EXCLUDED.cost,
                max_risk_on_path = EXCLUDED.max_risk_on_path,
                path_json        = EXCLUDED.path_json,
                computed_at      = NOW();
        """, {
            "entry":     record["entry"],
            "target":    record["target"],
            "hops":      record["hops"],
            "cost":      record["cost"],
            "max_risk":  record["max_risk_on_path"],
            "path_json": json.dumps(record["path"]),
        })
        paths_saved += 1

    nodes_saved = 0
    for name, attrs in data.get("nodes", {}).items():
        cur.execute("""
            INSERT INTO attack_path_nodes
                (device_name, zone, criticality, vendor, product, risk_score, is_attacked,
                 top_cve_id, top_cve_cvss, top_cve_tier, top_cve_desc, updated_at)
            VALUES (%(name)s, %(zone)s, %(criticality)s, %(vendor)s, %(product)s, %(risk_score)s, %(is_attacked)s,
                    %(top_cve_id)s, %(top_cve_cvss)s, %(top_cve_tier)s, %(top_cve_desc)s, NOW())
            ON CONFLICT (device_name) DO UPDATE SET
                zone          = EXCLUDED.zone,
                criticality   = EXCLUDED.criticality,
                vendor        = EXCLUDED.vendor,
                product       = EXCLUDED.product,
                risk_score    = EXCLUDED.risk_score,
                is_attacked   = EXCLUDED.is_attacked,
                top_cve_id    = EXCLUDED.top_cve_id,
                top_cve_cvss  = EXCLUDED.top_cve_cvss,
                top_cve_tier  = EXCLUDED.top_cve_tier,
                top_cve_desc  = EXCLUDED.top_cve_desc,
                updated_at    = NOW();
        """, {
            "name":          name,
            "zone":          attrs.get("zone", "OT"),
            "criticality":   attrs.get("criticality", 0.5),
            "vendor":        attrs.get("vendor", ""),
            "product":       attrs.get("product", ""),
            "risk_score":    attrs.get("risk_score", 0.0),
            "is_attacked":   int(attrs.get("is_attacked", 0)),
            "top_cve_id":    attrs.get("top_cve_id"),
            "top_cve_cvss":  attrs.get("top_cve_cvss"),
            "top_cve_tier":  attrs.get("top_cve_tier"),
            "top_cve_desc":  attrs.get("top_cve_desc"),
        })
        nodes_saved += 1

    return paths_saved, nodes_saved


def _run_policy_check(db_config):
    """Run policy compliance for all assets and save to DB."""
    try:
        import sys as _sys, os as _os, pandas as _pd
        _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), 'Policy_Compliance'))
        import psycopg2 as _pg
        from policy_predictor import PolicyCompliancePredictor
        predictor = PolicyCompliancePredictor()
        conn = _pg.connect(**db_config)
        cur = conn.cursor()
        cur.execute('SELECT id, device_type, vendor, zone, service, port, criticality FROM assets ORDER BY id')
        checked = 0
        for aid, dt, vendor, zone, svc, port, crit in cur.fetchall():
            cur.execute('SELECT AVG(cvss),AVG(epss),AVG(c_impact),AVG(i_impact),AVG(a_impact),COUNT(*) FROM vulnerabilities WHERE asset_id=%s',(aid,))
            cv = cur.fetchone(); has_cv = cv[5] > 0
            enc = 1 if svc in ('HTTPS','SSH') else 0
            features = {
                'device_type': dt or 'Unknown', 'vendor': vendor or 'Unknown',
                'zone': zone or 'OT', 'service': svc or 'Unknown',
                'port': int(port or 0), 'encrypted': enc,
                'cvss': float(cv[0] or 0) if has_cv else 0.0,
                'epss': float(cv[1] or 0) if has_cv else 0.0,
                'kev': 0,
                'c_impact': float(cv[2] or 0) if has_cv else 0.0,
                'i_impact': float(cv[3] or 0) if has_cv else 0.0,
                'a_impact': float(cv[4] or 0) if has_cv else 0.0,
                'criticality': float(crit or 0.5),
                'days_since_patch': 30, 'firmware_eol': 0, 'alert_count': 0
            }
            res = predictor.predict(_pd.DataFrame([features]))[0]
            cur.execute('''
                INSERT INTO policy_compliance
                    (asset_id,compliance_status,compliance_score,confidence,explanation,key_factors)
                VALUES (%s,%s,%s,%s,%s,'{}')
                ON CONFLICT (asset_id) DO UPDATE SET
                    compliance_status=EXCLUDED.compliance_status,
                    compliance_score=EXCLUDED.compliance_score,
                    confidence=EXCLUDED.confidence,
                    explanation=EXCLUDED.explanation,
                    checked_at=NOW()
            ''', (aid, res['compliance_status'], float(res['compliance_score']),
                  float(res['confidence']), res['explanation']))
            checked += 1
        conn.commit()
        conn.close()
        print(f"  Policy check: {checked} assets checked")
    except Exception as e:
        print(f"  Policy check failed: {e}")


def sync(wipe=False, reset_status=False):
    import psycopg2
    conn = psycopg2.connect(**DB_CONFIG)

    if wipe:
        print("Wiping existing data...")
        cur = conn.cursor()
        cur.execute("TRUNCATE alerts, vulnerabilities, assets RESTART IDENTITY CASCADE;")
        conn.commit()
        print("  Done.")
    elif reset_status:
        # Mark all assets INACTIVE and clear alerts — used on fresh startup before VM sends data
        print("Resetting asset statuses and clearing alerts...")
        cur = conn.cursor()
        cur.execute("TRUNCATE alerts RESTART IDENTITY;")
        cur.execute("UPDATE assets SET status = 'INACTIVE';")
        conn.commit()
        print("  Done.")

    # load assets.json — all 11 devices with full device info
    if not os.path.exists(ASSETS):
        print(f"ERROR: {ASSETS} not found"); sys.exit(1)
    with open(ASSETS, encoding='utf-8-sig') as f:
        assets_list = json.load(f)

    if not assets_list:
        print("assets.json is empty — VM pipeline not ready yet, adding permanent assets only")
        import psycopg2
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        for pa in PERMANENT_ASSETS:
            asset_id = upsert_asset(cur, pa)
            for cve in pa.get("cves", []):
                upsert_cve(cur, asset_id, cve, {"risk_score":0.0,"risk_tier":"LOW","c_impact":0.0,"i_impact":0.0,"a_impact":0.0})
            print(f"  OK {pa['vendor']} {pa['product']} [permanent]")
        ap_paths, ap_nodes = sync_attack_paths(cur)
        if ap_paths or ap_nodes:
            print(f"  Attack paths synced: {ap_paths} paths, {ap_nodes} nodes")
        conn.commit()
        conn.close()
        _run_policy_check(DB_CONFIG)
        return

    # load risk_scored_results.json — CVEs + risk scores keyed by device_type
    risk_idx = build_risk_index(SCORED)
    if not risk_idx:
        print(f"WARNING: {SCORED} not found or empty — CVEs will have no risk scores")

    # also build cve list index from scored results
    cve_by_type = {}
    if os.path.exists(SCORED):
        with open(SCORED) as f:
            scored_data = json.load(f)
        for dev in scored_data.get("devices", []):
            cve_by_type[dev.get("device_type", "")] = dev.get("cves", [])

    # load suricata_context.json — alerts per device keyed by port
    suricata_by_port = {}
    if os.path.exists(SURICATA):
        with open(SURICATA) as f:
            suricata_list = json.load(f)
        for entry in suricata_list:
            suricata_by_port[entry.get("port")] = entry
    else:
        print(f"WARNING: {SURICATA} not found — alerts will be empty")

    # load anomaly_results.json — behavioral anomaly score per device, keyed by port
    anomaly_by_port = {}
    if os.path.exists(ANOMALY):
        with open(ANOMALY) as f:
            anomaly_list = json.load(f)
        for entry in anomaly_list:
            anomaly_by_port[entry.get("port")] = entry

    print(f"\nSyncing {len(assets_list)} assets...")

    assets_saved = cves_saved = 0
    cur = conn.cursor()

    # ── Pre-seed all master assets as INACTIVE ────────────────────────────────
    # They will be promoted to ACTIVE when the VM reports them in assets.json
    active_ports = {a.get("port") for a in assets_list}
    for ma in MASTER_ASSETS:
        ma_with_status = dict(ma)
        ma_with_status["status"] = "ACTIVE" if ma["port"] in active_ports else "INACTIVE"
        ma_with_status["packet_count"] = next(
            (a.get("packet_count", 0) for a in assets_list if a.get("port") == ma["port"]), 0
        )
        upsert_asset(cur, ma_with_status)

    for device in assets_list:
        dt    = device.get("device_type", "")
        cves  = cve_by_type.get(dt, [])

        anomaly_entry = anomaly_by_port.get(device.get("port"))
        if anomaly_entry:
            device["anomaly_score"]  = anomaly_entry.get("anomaly_score", 0.0)
            device["is_anomalous"]   = anomaly_entry.get("is_anomalous", False)
            device["anomaly_reason"] = anomaly_entry.get("reason")

        asset_id = upsert_asset(cur, device)
        assets_saved += 1

        dt_risks = risk_idx.get(dt, {})
        for cve in cves:
            risk_info = dt_risks.get(cve["cve_id"], {
                "risk_score": cve.get("risk_score", 0.0),
                "risk_tier":  cve.get("risk_tier", "LOW"),
                "c_impact":   cve.get("c_impact", 0.0),
                "i_impact":   cve.get("i_impact", 0.0),
                "a_impact":   cve.get("a_impact", 0.0),
            })
            upsert_cve(cur, asset_id, cve, risk_info)
            cves_saved += 1

        # insert alerts from suricata_context.json
        suricata_entry = suricata_by_port.get(device.get("port"))
        alert_count = 0
        if suricata_entry and suricata_entry.get("alert_count", 0) > 0:
            alert_count = upsert_alerts(cur, asset_id, suricata_entry)

        print(f"  OK {device.get('vendor','')} {device.get('product','')} "
              f"({dt}) — {len(cves)} CVEs, {alert_count} alert types")

    # ── Always add permanent Windows-side assets (not discovered by VM) ─────
    permanent_ports = {ma["port"] for ma in MASTER_ASSETS}
    for pa in PERMANENT_ASSETS:
        asset_id = upsert_asset(cur, pa)
        # only count if not already counted via MASTER_ASSETS
        if pa["port"] not in permanent_ports:
            assets_saved += 1
        dt_risks = risk_idx.get(pa.get("device_type", ""), {})
        for cve in pa.get("cves", []):
            ri = dt_risks.get(cve["cve_id"], {
                "risk_score": 0.0, "risk_tier": "LOW",
                "c_impact": 0.0, "i_impact": 0.0, "a_impact": 0.0
            })
            upsert_cve(cur, asset_id, cve, ri)
            cves_saved += 1
        print(f"  OK {pa['vendor']} {pa['product']} ({pa['device_type']}) — {len(pa.get('cves',[]))} CVEs [permanent]")

    # ── Padding asset — status re-rolled every sync so it toggles over time ──
    padding = dict(PADDING_ASSET)
    padding["status"] = random.choices(["ACTIVE", "INACTIVE"], weights=[75, 25])[0]
    upsert_asset(cur, padding)
    print(f"  OK {padding['vendor']} {padding['product']} ({padding['device_type']}) — [padding, {padding['status']}]")

    ap_paths, ap_nodes = sync_attack_paths(cur)

    conn.commit()
    conn.close()

    print(f"\n{'='*50}")
    print(f"  Assets synced : {assets_saved}")
    print(f"  CVEs synced   : {cves_saved}")
    if ap_paths or ap_nodes:
        print(f"  Attack paths  : {ap_paths} paths, {ap_nodes} nodes")
    print(f"{'='*50}")

    # ── Run policy compliance check for all assets ────────────────────────────
    _run_policy_check(DB_CONFIG)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--wipe", action="store_true",
                        help="Clear all existing data before syncing")
    parser.add_argument("--reset", action="store_true",
                        help="Set all assets to INACTIVE before syncing (soft reset, keeps CVE/alert history)")
    args = parser.parse_args()
    sync(wipe=args.wipe, reset_status=args.reset)
