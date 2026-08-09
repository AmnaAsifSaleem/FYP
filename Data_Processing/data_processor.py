"""
data_processor.py
─────────────────
Processes NVD 2.0 format + EPSS + CISA KEV
Produces processed_cves.csv and ot_cves.csv

Put this script in:
  D:\Downloads\CAVE-OT Datasets\

Run:
  python data_processor.py

Input files:
  nvdcve-2.0-2016.json.zip  to  nvdcve-2.0-2025.json.zip
  epss_scores-current.csv.gz
  cisa_data.json

Output:
  processed_cves.csv     <- full dataset for model training
  ot_cves.csv            <- OT/ICS CVEs only
  processing_report.txt  <- summary
"""

import os
import sys
import json
import zipfile
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pipeline_paths import DATASET_FOLDER

# ── Config ────────────────────────────────────────────────────────────────────

NVD_FILES = [
    "nvdcve-2.0-2016.json.zip",
    "nvdcve-2.0-2017.json.zip",
    "nvdcve-2.0-2018.json.zip",
    "nvdcve-2.0-2019.json.zip",
    "nvdcve-2.0-2020.json.zip",
    "nvdcve-2.0-2021.json.zip",
    "nvdcve-2.0-2022.json.zip",
    "nvdcve-2.0-2023.json.zip",
    "nvdcve-2.0-2024.json.zip",
    "nvdcve-2.0-2025.json.zip",
    "nvdcve-2.0-2026.json.zip",
]

EPSS_FILE = "epss_scores-current.csv.gz"
KEV_FILE  = "cisa_data.json"

# ── OT Vendor Keywords ────────────────────────────────────────────────────────

OT_VENDORS = [
    "schneider", "modicon", "ecostruxure", "unity pro",
    "siemens", "simatic", "scalance", "sinema", "ruggedcom",
    "rockwell", "allen-bradley", "logix", "factorytalk", "rslogix",
    "honeywell", "experion", "matrikon",
    "abb", "ac500", "symphony",
    "general electric", "cimplicity", "proficy",
    "mitsubishi", "melsec", "got2000",
    "omron", "sysmac", "cx-programmer",
    "beckhoff", "twincat",
    "codesys",
    "advantech", "webaccess",
    "moxa",
    "phoenix contact",
    "wago",
    "emerson", "deltav", "ovation",
    "yokogawa", "centum",
    "aveva", "wonderware", "intouch",
    "kepware",
    "indusoft",
    "iconics",
    "dnp3", "modbus", "profinet",
    "bacnet", "iec 61850", "iec-61850",
    "scada", "plc", "rtu", "hmi",
    "industrial control", "ics", "ot network",
    "remote terminal", "programmable logic",
    "distributed control", "dcs",
]

# ── CIA Impact Map ────────────────────────────────────────────────────────────

CIA_MAP = {
    "NONE":     0.00,
    "LOW":      0.22,
    "HIGH":     0.56,
    "PARTIAL":  0.22,
    "COMPLETE": 0.56,
}

# ── Step 1: Parse NVD 2.0 ────────────────────────────────────────────────────

def parse_nvd_files(folder):
    print("\n" + "="*60)
    print("  STEP 1 — Parsing NVD 2.0 ZIP files")
    print("="*60)

    all_cves = []

    for filename in NVD_FILES:
        filepath = os.path.join(folder, filename)

        if not os.path.exists(filepath):
            print(f"  [!] Not found, skipping: {filename}")
            continue

        print(f"\n  Processing {filename}...")

        try:
            with zipfile.ZipFile(filepath, 'r') as z:
                json_files = [f for f in z.namelist() if f.endswith('.json')]
                if not json_files:
                    print(f"    [!] No JSON inside zip")
                    continue

                with z.open(json_files[0]) as f:
                    data = json.load(f)

            # NVD 2.0 key is 'vulnerabilities'
            vuln_list = data.get('vulnerabilities', [])
            print(f"    Found {len(vuln_list)} CVEs")

            year_cves = []
            for item in vuln_list:
                parsed = parse_nvd_item(item)
                if parsed:
                    year_cves.append(parsed)

            print(f"    Parsed {len(year_cves)} valid CVEs")
            all_cves.extend(year_cves)

        except Exception as e:
            print(f"    [!] Error: {e}")
            import traceback
            traceback.print_exc()

    print(f"\n  Total CVEs parsed: {len(all_cves)}")
    return all_cves


def parse_nvd_item(item):
    """Parse one CVE from NVD 2.0 format."""
    try:
        cve_data = item.get('cve', {})

        # CVE ID
        cve_id = cve_data.get('id', '')
        if not cve_id:
            return None

        # English description
        desc = ""
        for d in cve_data.get('descriptions', []):
            if d.get('lang') == 'en':
                desc = d.get('value', '')
                break

        # Vendor + product from CPE
        # NVD 2.0 uses 'cpeMatch' (camelCase)
        vendor        = ""
        product       = ""
        version_start = ""
        version_end   = ""

        for config in cve_data.get('configurations', []):
            for node in config.get('nodes', []):
                for cpe_match in node.get('cpeMatch', []):
                    criteria = cpe_match.get('criteria', '')
                    parts = criteria.split(':')
                    if len(parts) >= 5:
                        vendor  = vendor  or parts[3].replace('_', ' ')
                        product = product or parts[4].replace('_', ' ')

                    version_start = (version_start
                                     or cpe_match.get('versionStartIncluding', '')
                                     or cpe_match.get('versionStartExcluding', ''))
                    version_end   = (version_end
                                     or cpe_match.get('versionEndIncluding', '')
                                     or cpe_match.get('versionEndExcluding', ''))

        # CVSS scores
        # NVD 2.0: cve_data['metrics']['cvssMetricV31'][0]['cvssData']
        cvss       = None
        c_impact   = 0.00
        i_impact   = 0.00
        a_impact   = 0.00
        attack_vec = ""
        complexity = ""

        metrics = cve_data.get('metrics', {})

        if 'cvssMetricV31' in metrics:
            m          = metrics['cvssMetricV31'][0]['cvssData']
            cvss       = float(m.get('baseScore', 0))
            c_impact   = CIA_MAP.get(m.get('confidentialityImpact', 'NONE').upper(), 0.00)
            i_impact   = CIA_MAP.get(m.get('integrityImpact',       'NONE').upper(), 0.00)
            a_impact   = CIA_MAP.get(m.get('availabilityImpact',    'NONE').upper(), 0.00)
            attack_vec = m.get('attackVector', '')
            complexity = m.get('attackComplexity', '')

        elif 'cvssMetricV30' in metrics:
            m          = metrics['cvssMetricV30'][0]['cvssData']
            cvss       = float(m.get('baseScore', 0))
            c_impact   = CIA_MAP.get(m.get('confidentialityImpact', 'NONE').upper(), 0.00)
            i_impact   = CIA_MAP.get(m.get('integrityImpact',       'NONE').upper(), 0.00)
            a_impact   = CIA_MAP.get(m.get('availabilityImpact',    'NONE').upper(), 0.00)
            attack_vec = m.get('attackVector', '')
            complexity = m.get('attackComplexity', '')

        elif 'cvssMetricV2' in metrics:
            m          = metrics['cvssMetricV2'][0]['cvssData']
            cvss       = float(m.get('baseScore', 0))
            c_impact   = CIA_MAP.get(m.get('confidentialityImpact', 'NONE').upper(), 0.00)
            i_impact   = CIA_MAP.get(m.get('integrityImpact',       'NONE').upper(), 0.00)
            a_impact   = CIA_MAP.get(m.get('availabilityImpact',    'NONE').upper(), 0.00)
            attack_vec = m.get('accessVector', '')
            complexity = m.get('accessComplexity', '')

        if not cvss or cvss == 0:
            return None

        # OT detection
        combined = (vendor + " " + product + " " + desc).lower()
        is_ot    = 1 if any(kw in combined for kw in OT_VENDORS) else 0

        return {
            "cve_id":        cve_id,
            "vendor":        vendor.lower().strip(),
            "product":       product.lower().strip(),
            "version_start": version_start,
            "version_end":   version_end,
            "cvss":          cvss,
            "c_impact":      c_impact,
            "i_impact":      i_impact,
            "a_impact":      a_impact,
            "attack_vector": attack_vec,
            "complexity":    complexity,
            "description":   desc[:300],
            "is_ot":         is_ot,
        }

    except Exception:
        return None


# ── Step 2: Parse EPSS ────────────────────────────────────────────────────────

def parse_epss(folder):
    print("\n" + "="*60)
    print("  STEP 2 — Parsing EPSS dataset")
    print("="*60)

    filepath = os.path.join(folder, EPSS_FILE)

    if not os.path.exists(filepath):
        print(f"  [!] Not found: {EPSS_FILE}")
        return {}

    try:
        df = pd.read_csv(filepath, compression='gzip', comment='#')
        df.columns = df.columns.str.strip().str.lower()

        if 'cve' in df.columns:
            df = df.rename(columns={'cve': 'cve_id'})

        epss_dict = dict(zip(df['cve_id'], df['epss'].astype(float)))
        print(f"  EPSS scores loaded: {len(epss_dict)} CVEs")
        return epss_dict

    except Exception as e:
        print(f"  [!] Error: {e}")
        return {}


# ── Step 3: Parse CISA KEV ────────────────────────────────────────────────────

def parse_kev(folder):
    print("\n" + "="*60)
    print("  STEP 3 — Parsing CISA KEV")
    print("="*60)

    filepath = os.path.join(folder, KEV_FILE)

    if not os.path.exists(filepath):
        print(f"  [!] Not found: {KEV_FILE}")
        return set()

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        if 'vulnerabilities' in data:
            kev_ids = {v['cveID'] for v in data['vulnerabilities']}
        elif isinstance(data, list):
            kev_ids = {v.get('cveID') or v.get('cve_id', '') for v in data}
        else:
            kev_ids = set()

        print(f"  KEV entries loaded: {len(kev_ids)} CVEs")
        return kev_ids

    except Exception as e:
        print(f"  [!] Error: {e}")
        return set()


# ── Step 4: Join ──────────────────────────────────────────────────────────────

def join_datasets(nvd_cves, epss_dict, kev_ids):
    print("\n" + "="*60)
    print("  STEP 4 — Joining all datasets")
    print("="*60)

    for cve in nvd_cves:
        cve['epss'] = epss_dict.get(cve['cve_id'], 0.0)
        cve['kev']  = 1 if cve['cve_id'] in kev_ids else 0

    df = pd.DataFrame(nvd_cves)

    print(f"  Total records          : {len(df)}")
    print(f"  OT specific (is_ot=1)  : {(df['is_ot']==1).sum()}")
    print(f"  General IT (is_ot=0)   : {(df['is_ot']==0).sum()}")
    print(f"  With EPSS scores       : {(df['epss']>0).sum()}")
    print(f"  In CISA KEV            : {(df['kev']==1).sum()}")

    return df


# ── Step 5: Clean and Save ────────────────────────────────────────────────────

def clean_and_save(df, folder):
    print("\n" + "="*60)
    print("  STEP 5 — Cleaning and saving")
    print("="*60)

    before = len(df)
    df = df[df['cvss'] > 0]
    print(f"  Dropped (no CVSS)      : {before - len(df)}")

    before = len(df)
    df = df.drop_duplicates(subset=['cve_id'])
    print(f"  Dropped (duplicates)   : {before - len(df)}")

    df['epss']          = df['epss'].fillna(0.0)
    df['kev']           = df['kev'].fillna(0).astype(int)
    df['vendor']        = df['vendor'].fillna('unknown')
    df['product']       = df['product'].fillna('unknown')
    df['version_start'] = df['version_start'].fillna('')
    df['version_end']   = df['version_end'].fillna('')
    df['attack_vector'] = df['attack_vector'].fillna('')
    df['complexity']    = df['complexity'].fillna('')
    df['description']   = df['description'].fillna('')

    df = df[[
        'cve_id', 'vendor', 'product',
        'version_start', 'version_end',
        'cvss', 'epss', 'kev',
        'c_impact', 'i_impact', 'a_impact',
        'attack_vector', 'complexity',
        'is_ot', 'description',
    ]]

    out_full = os.path.join(folder, 'processed_cves.csv')
    df.to_csv(out_full, index=False)
    print(f"\n  [+] Saved: processed_cves.csv ({len(df)} rows)")

    ot_df  = df[df['is_ot'] == 1]
    out_ot = os.path.join(folder, 'ot_cves.csv')
    ot_df.to_csv(out_ot, index=False)
    print(f"  [+] Saved: ot_cves.csv ({len(ot_df)} OT CVEs)")

    return df


# ── Step 6: Report ────────────────────────────────────────────────────────────

def print_report(df, folder):
    print("\n" + "="*60)
    print("  FINAL REPORT")
    print("="*60)

    ot_df = df[df['is_ot'] == 1]

    print(f"""
  Total CVEs processed     : {len(df)}
  OT specific CVEs         : {len(ot_df)}
  CVEs with EPSS scores    : {(df['epss'] > 0).sum()}
  CVEs in CISA KEV         : {(df['kev'] == 1).sum()}

  CVSS Distribution:
  Critical  (9.0-10.0)     : {(df['cvss'] >= 9.0).sum()}
  High      (7.0-8.9)      : {((df['cvss'] >= 7.0) & (df['cvss'] < 9.0)).sum()}
  Medium    (4.0-6.9)      : {((df['cvss'] >= 4.0) & (df['cvss'] < 7.0)).sum()}
  Low       (0.1-3.9)      : {((df['cvss'] > 0)   & (df['cvss'] < 4.0)).sum()}

  Top OT Vendors:""")

    for vendor, count in ot_df['vendor'].value_counts().head(10).items():
        print(f"    {vendor:<35} {count} CVEs")

    report_path = os.path.join(folder, 'processing_report.txt')
    with open(report_path, 'w') as f:
        f.write(f"Total CVEs: {len(df)}\n")
        f.write(f"OT CVEs: {len(ot_df)}\n")
        f.write(f"CVEs with EPSS: {(df['epss']>0).sum()}\n")
        f.write(f"KEV CVEs: {(df['kev']==1).sum()}\n")

    print(f"\n  [+] Report saved: processing_report.txt")
    print(f"  → Next step: model_trainer.py")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("="*60)
    print("  CAVE-OT DATA PROCESSOR  (NVD 2.0)")
    print("="*60)
    print(f"  Folder: {DATASET_FOLDER}\n")

    if not os.path.exists(DATASET_FOLDER):
        print(f"[!] Folder not found: {DATASET_FOLDER}")
        return

    nvd_cves  = parse_nvd_files(DATASET_FOLDER)
    if not nvd_cves:
        print("\n[!] No CVEs parsed. Check zip files.")
        return

    epss_dict = parse_epss(DATASET_FOLDER)
    kev_ids   = parse_kev(DATASET_FOLDER)
    df        = join_datasets(nvd_cves, epss_dict, kev_ids)
    df        = clean_and_save(df, DATASET_FOLDER)
    print_report(df, DATASET_FOLDER)

if __name__ == "__main__":
    main()