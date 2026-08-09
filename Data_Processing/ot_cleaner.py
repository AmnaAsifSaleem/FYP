"""
ot_cleaner.py
─────────────
Cleans ot_cves.csv by removing false positives.
Keeps only genuine ICS/OT vendor CVEs.

Put this script in:
  D:\Downloads\CAVE-OT Datasets\

Run:
  python ot_cleaner.py

Input:
  ot_cves.csv           <- produced by data_processor.py

Output:
  ot_cves_clean.csv     <- genuine OT CVEs only
  ot_cleaning_report.txt
"""

import os
import sys
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pipeline_paths import DATASET_FOLDER

# ── Config ────────────────────────────────────────────────────────────────────

# ── Genuine OT/ICS Vendors ────────────────────────────────────────────────────
# ONLY these vendors are accepted in the clean OT dataset
# This list is based on ICS-CERT and IEC 62443 recognized vendors

GENUINE_OT_VENDORS = [
    # Schneider Electric family
    "schneider",
    "schneider-electric",
    "schneider electric",
    "modicon",
    "ecostruxure",
    "unity pro",
    "triconex",

    # Siemens family
    "siemens",
    "simatic",
    "scalance",
    "sinema",
    "ruggedcom",
    "desigo",
    "apogee",

    # Rockwell Automation family
    "rockwell",
    "rockwellautomation",
    "rockwell automation",
    "allen-bradley",
    "allen bradley",
    "logix",
    "factorytalk",
    "rslogix",
    "micrologix",
    "compactlogix",
    "controllogix",

    # Honeywell
    "honeywell",
    "experion",
    "matrikon",
    "uniformance",

    # ABB
    "abb",
    "ac500",
    "symphony",
    "freelance",
    "ability",

    # GE / General Electric
    "ge digital",
    "general electric",
    "cimplicity",
    "proficy",
    "ifix",
    "ge fanuc",

    # Mitsubishi Electric
    "mitsubishi electric",
    "mitsubishielectric",
    "melsec",
    "got2000",
    "melsoft",

    # Omron
    "omron",
    "sysmac",
    "cx-programmer",
    "cx programmer",

    # Beckhoff
    "beckhoff",
    "twincat",

    # CODESYS (used by many PLC vendors)
    "codesys",
    "3s-smart",
    "3s smart",

    # Advantech
    "advantech",
    "webaccess",
    "wise-paas",

    # Moxa
    "moxa",

    # Phoenix Contact
    "phoenix contact",
    "phoenixcontact",
    "phoenix-contact",

    # WAGO
    "wago",

    # Emerson
    "emerson",
    "deltav",
    "ovation",
    "rosemount",
    "fisher",

    # Yokogawa
    "yokogawa",
    "centum",
    "stardom",

    # AVEVA / Wonderware
    "aveva",
    "wonderware",
    "intouch",
    "system platform",

    # Inductive Automation
    "inductive automation",
    "ignition",

    # Kepware
    "kepware",
    "kepserverex",

    # Other genuine ICS vendors
    "indusoft",
    "iconics",
    "genesis64",
    "prosoft",
    "red lion",
    "redlion",
    "dataquality",
    "novatech",
    "elipse",
    "vtscada",
    "cogent",
    "kepserver",
    "circontrol",
    "meinberg",
    "tridium",
    "niagara",
    "hirschmann",
    "belden",
    "digi international",
    "comtrol",
    "ixon",
    "secomea",
    "tosibox",
    "ewon",
    "talk2m",
    "netbiter",
    "netgain",
    "spectrum controls",
    "proface",
    "weintek",
    "delta electronics",
    "delta-electronics",
    "b&r",
    "br automation",
    "eaton",
    "schweitzer",
    "sel ",
    "abb cylon",
    "sauter",
    "distech",
    "automated logic",
    "johnson controls",
    "metasys",
    "tyco",
    "pelco",
    "bosch rexroth",
    "rexroth",
    "lenze",
    "danfoss",
    "festo",
    "turck",
    "ifm",
    "pilz",
    "safety relay",
    "saia",
    "saia-burgess",
    "microsys",
    "atvise",
    "softing",
    "hilscher",
    "anybus",
    "hms networks",
    "netmodule",
    "belden hirschmann",
    "opswat",
    "claroty",
    "nozomi",
    "dragos",
    "waterfall",
    "fortiphyd",
    "cyberx",
    "indegy",
    "radiflow",
    "siga",
    "otorio",
]

# ── IT vendors to explicitly exclude ─────────────────────────────────────────
# Even if description mentions OT keywords, these are IT vendors
# and should NOT be in the OT dataset

EXCLUDE_VENDORS = [
    "linux",
    "microsoft",
    "oracle",
    "qualcomm",
    "ibm",
    "google",
    "apple",
    "adobe",
    "cisco",
    "juniper",
    "vmware",
    "redhat",
    "red hat",
    "ubuntu",
    "debian",
    "canonical",
    "suse",
    "fedora",
    "centos",
    "android",
    "mozilla",
    "firefox",
    "chrome",
    "webkit",
    "openssl",
    "openssh",
    "apache",
    "nginx",
    "wordpress",
    "drupal",
    "joomla",
    "php",
    "python",
    "ruby",
    "perl",
    "java",
    "spring",
    "struts",
    "jenkins",
    "gitlab",
    "github",
    "atlassian",
    "jira",
    "confluence",
    "zoom",
    "slack",
    "teams",
    "samsung",
    "huawei",
    "zte",
    "netgear",
    "dlink",
    "d-link",
    "tp-link",
    "asus",
    "synology",
    "qnap",
    "palo alto",
    "fortinet",
    "checkpoint",
    "sophos",
    "trend micro",
    "symantec",
    "mcafee",
    "kaspersky",
    "avast",
    "avg",
    "norton",
    "crowdstrike",
    "sailpoint",
    "okta",
    "splunk",
    "elastic",
    "mongodb",
    "mysql",
    "postgresql",
    "sqlite",
    "redis",
    "kafka",
    "hadoop",
    "spark",
    "tensorflow",
    "pytorch",
    "wordpress",
    "magento",
    "shopify",
    "salesforce",
    "sap",
    "peoplesoft",
    "dell",
    "hp",
    "hewlett",
    "lenovo",
    "acer",
    "intel",
    "amd",
    "nvidia",
    "broadcom",
    "mediatek",
    "arm",
    "marvell",
    "realtek",
]

# ── OT specific keywords for description check ────────────────────────────────
# If vendor is unknown/blank, check if description has these strong OT keywords

OT_DESCRIPTION_KEYWORDS = [
    "programmable logic controller",
    "plc ",
    " plc,",
    "scada system",
    "distributed control system",
    "industrial control system",
    "remote terminal unit",
    " rtu ",
    "human machine interface",
    " hmi ",
    "historian server",
    "engineering workstation",
    "safety instrumented system",
    "sis ",
    "modbus tcp",
    "profinet",
    "ethernet/ip",
    "dnp3",
    "iec 61850",
    "iec-61850",
    "iec 62443",
    "industrial ethernet",
    "opc server",
    "opc ua",
    "fieldbus",
    "industrial protocol",
    "automation controller",
    "process control",
]

# ── Main Cleaner ──────────────────────────────────────────────────────────────

def is_genuine_ot(row):
    """
    Returns True if this CVE is genuinely OT/ICS related.
    
    Logic:
    1. If vendor matches an IT exclude list → False
    2. If vendor matches genuine OT vendor list → True
    3. If vendor is blank/unknown but description has strong OT keywords → True
    4. Otherwise → False
    """
    vendor  = str(row['vendor']).lower().strip()
    product = str(row['product']).lower().strip()
    desc    = str(row['description']).lower().strip()

    combined = vendor + " " + product + " " + desc

    # Rule 1 — Explicitly exclude IT vendors
    for excl in EXCLUDE_VENDORS:
        if excl in vendor:
            return False

    # Rule 2 — Accept genuine OT vendors
    for ot_v in GENUINE_OT_VENDORS:
        if ot_v in combined:
            return True

    # Rule 3 — Blank vendor but strong OT keywords in description
    if vendor in ('', 'unknown', ' '):
        for kw in OT_DESCRIPTION_KEYWORDS:
            if kw in desc:
                return True

    return False


def clean(folder):
    print("=" * 60)
    print("  CAVE-OT OT DATASET CLEANER")
    print("=" * 60)

    input_path = os.path.join(folder, 'ot_cves.csv')

    if not os.path.exists(input_path):
        print(f"[!] ot_cves.csv not found in {folder}")
        print("    Run data_processor.py first")
        return

    # ── Load ─────────────────────────────────────────────────
    print(f"\n[*] Loading ot_cves.csv...")
    df = pd.read_csv(input_path)
    print(f"[+] Loaded {len(df)} rows")

    # ── Show what we have before cleaning ────────────────────
    print(f"\n  Top vendors BEFORE cleaning:")
    for vendor, count in df['vendor'].value_counts().head(15).items():
        print(f"    {vendor:<35} {count}")

    # ── Apply cleaning ────────────────────────────────────────
    print(f"\n[*] Applying OT vendor filter...")
    df['_keep'] = df.apply(is_genuine_ot, axis=1)

    removed = df[df['_keep'] == False]
    clean_df = df[df['_keep'] == True].drop(columns=['_keep'])

    print(f"\n  Removed {len(removed)} false positive rows")
    print(f"  Kept    {len(clean_df)} genuine OT CVEs")

    # ── Show what was removed ─────────────────────────────────
    print(f"\n  Top vendors REMOVED (false positives):")
    for vendor, count in removed['vendor'].value_counts().head(10).items():
        print(f"    {vendor:<35} {count}")

    # ── Show what remains ─────────────────────────────────────
    print(f"\n  Top vendors AFTER cleaning:")
    for vendor, count in clean_df['vendor'].value_counts().head(15).items():
        print(f"    {vendor:<35} {count}")

    # ── Save ──────────────────────────────────────────────────
    output_path = os.path.join(folder, 'ot_cves_clean.csv')
    clean_df.to_csv(output_path, index=False)

    # ── Report ────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  CLEANING REPORT")
    print(f"{'='*60}")
    print(f"""
  Before cleaning   : {len(df)} CVEs
  After cleaning    : {len(clean_df)} CVEs
  Removed           : {len(removed)} false positives

  CVSS Distribution (clean OT CVEs):
  Critical  (9.0-10.0)  : {(clean_df['cvss'] >= 9.0).sum()}
  High      (7.0-8.9)   : {((clean_df['cvss'] >= 7.0) & (clean_df['cvss'] < 9.0)).sum()}
  Medium    (4.0-6.9)   : {((clean_df['cvss'] >= 4.0) & (clean_df['cvss'] < 7.0)).sum()}
  Low       (0.1-3.9)   : {((clean_df['cvss'] > 0)   & (clean_df['cvss'] < 4.0)).sum()}

  With EPSS scores  : {(clean_df['epss'] > 0).sum()}
  In CISA KEV       : {(clean_df['kev'] == 1).sum()}
    """)

    report_path = os.path.join(folder, 'ot_cleaning_report.txt')
    with open(report_path, 'w') as f:
        f.write(f"Before: {len(df)}\n")
        f.write(f"After: {len(clean_df)}\n")
        f.write(f"Removed: {len(removed)}\n")
        f.write(f"KEV in clean OT: {(clean_df['kev']==1).sum()}\n")

    print(f"  [+] Saved: ot_cves_clean.csv")
    print(f"  [+] Saved: ot_cleaning_report.txt")
    print(f"\n  → Next step: model_trainer.py")


if __name__ == "__main__":
    clean(DATASET_FOLDER)