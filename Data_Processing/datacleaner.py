"""
data_cleaner.py
───────────────
Final cleaning pass before model training.
Fixes vendor names, product names, description text.
Produces training-ready files.

Put this script in:
  D:\Downloads\CAVE-OT Datasets\

Run:
  python data_cleaner.py

Input:
  processed_cves.csv      <- from data_processor.py
  ot_cves_clean.csv       <- from ot_cleaner.py

Output:
  training_ready.csv      <- clean general dataset (230k rows)
  ot_training_ready.csv   <- clean OT dataset (6k rows)
  cleaning_report.txt
"""

import os
import sys
import re
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pipeline_paths import DATASET_FOLDER

# ── Config ────────────────────────────────────────────────────────────────────

# ── Vendor Name Normalisation Map ─────────────────────────────────────────────
# Maps messy vendor strings → clean standard name
# Order matters: longer/more specific entries first

VENDOR_NORMALISE = {
    # Schneider Electric
    "schneider-electric":           "schneider electric",
    "schneider_electric":           "schneider electric",
    "schneiderelectric":            "schneider electric",
    "schneider electric":           "schneider electric",
    "schneider":                    "schneider electric",
    "modicon":                      "schneider electric",
    "ecostruxure":                  "schneider electric",
    "triconex":                     "schneider electric",

    # Siemens
    "siemens ag":                   "siemens",
    "siemens-ag":                   "siemens",
    "simatic":                      "siemens",
    "scalance":                     "siemens",
    "sinema":                       "siemens",
    "ruggedcom":                    "siemens",
    "desigo":                       "siemens",

    # Rockwell Automation
    "rockwellautomation":           "rockwell automation",
    "rockwell_automation":          "rockwell automation",
    "rockwell":                     "rockwell automation",
    "allen-bradley":                "rockwell automation",
    "allen bradley":                "rockwell automation",
    "allenbradley":                 "rockwell automation",

    # Mitsubishi Electric
    "mitsubishielectric":           "mitsubishi electric",
    "mitsubishi_electric":          "mitsubishi electric",
    "mitsubishi":                   "mitsubishi electric",
    "melsec":                       "mitsubishi electric",

    # Phoenix Contact
    "phoenixcontact":               "phoenix contact",
    "phoenix-contact":              "phoenix contact",
    "phoenix_contact":              "phoenix contact",

    # ABB
    "abb ltd":                      "abb",
    "abb inc":                      "abb",

    # Delta Electronics
    "deltaww":                      "delta electronics",
    "delta_electronics":            "delta electronics",
    "delta-electronics":            "delta electronics",
    "deltaelectronics":             "delta electronics",

    # Honeywell
    "honeywell international":      "honeywell",
    "honeywell inc":                "honeywell",

    # GE
    "general electric":             "ge digital",
    "ge fanuc":                     "ge digital",
    "ge-ip":                        "ge digital",
    "geip":                         "ge digital",

    # Emerson
    "emerson electric":             "emerson",
    "emerson process":              "emerson",
    "emerson automation":           "emerson",

    # Yokogawa
    "yokogawa electric":            "yokogawa",
    "yokogawa co":                  "yokogawa",

    # AVEVA / Wonderware
    "aveva group":                  "aveva",
    "aveva software":               "aveva",
    "wonderware":                   "aveva",
    "invensys":                     "aveva",

    # Advantech
    "advantech co":                 "advantech",
    "advantech ltd":                "advantech",

    # CODESYS
    "3s-smart software solutions":  "codesys",
    "3s smart":                     "codesys",
    "codesys gmbh":                 "codesys",

    # Beckhoff
    "beckhoff automation":          "beckhoff",

    # Omron
    "omron corporation":            "omron",
    "omron corp":                   "omron",

    # WAGO
    "wago kontakttechnik":          "wago",
    "wago gmbh":                    "wago",

    # Moxa
    "moxa inc":                     "moxa",
    "moxa technologies":            "moxa",
}

# ── Product Name Cleaning ─────────────────────────────────────────────────────
# Words to remove from product names (noise words)

PRODUCT_NOISE_WORDS = [
    "firmware",
    "software",
    "version",
    "versions",
    "application",
    "applications",
    "system",
    "systems",
    "platform",
    "suite",
    "series",
    "family",
    "product",
    "products",
    "solution",
    "solutions",
    "module",
    "modules",
    "component",
    "components",
    "interface",
    "server",
    "client",
    "agent",
    "service",
    "services",
    "tool",
    "tools",
    "utility",
    "utilities",
    "package",
    "packages",
    "library",
    "libraries",
    "runtime",
    "engine",
    "framework",
    "sdk",
    "api",
]

# ── Text Cleaning ─────────────────────────────────────────────────────────────

def clean_description(text):
    """
    Clean CVE description text:
    - Remove URLs
    - Remove special characters
    - Remove extra whitespace
    - Lowercase
    - Keep only ASCII
    """
    if not text or pd.isna(text):
        return ""

    text = str(text).lower()

    # Remove URLs
    text = re.sub(r'http[s]?://\S+', '', text)
    text = re.sub(r'www\.\S+', '', text)

    # Remove special characters but keep spaces, letters, numbers, dots
    text = re.sub(r'[^a-z0-9\s\.\-\_\/]', ' ', text)

    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text).strip()

    # Truncate to 200 chars (enough context for similarity)
    return text[:200]


def normalise_vendor(vendor):
    """Normalise vendor name to standard form."""
    if not vendor or pd.isna(vendor):
        return "unknown"

    v = str(vendor).lower().strip()

    # Remove common suffixes
    for suffix in [' inc', ' inc.', ' ltd', ' ltd.', ' llc',
                   ' corp', ' corp.', ' co.', ' gmbh', ' ag',
                   ' plc', ' s.a.', ' b.v.', ' oy']:
        v = v.replace(suffix, '')

    v = v.strip()

    # Apply normalisation map
    for messy, clean in VENDOR_NORMALISE.items():
        if messy in v:
            return clean

    return v


def normalise_product(product):
    """Clean product name."""
    if not product or pd.isna(product):
        return "unknown"

    p = str(product).lower().strip()

    # Replace underscores and hyphens with spaces
    p = p.replace('_', ' ').replace('-', ' ')

    # Remove noise words
    words = p.split()
    words = [w for w in words if w not in PRODUCT_NOISE_WORDS]
    p = ' '.join(words)

    # Remove extra whitespace
    p = re.sub(r'\s+', ' ', p).strip()

    return p if p else "unknown"


def normalise_version(ver):
    """Standardise version string format."""
    if not ver or pd.isna(ver):
        return ""

    v = str(ver).strip()

    # Remove 'v' or 'V' prefix
    v = re.sub(r'^[vV]', '', v)

    # Keep only digits and dots
    v = re.sub(r'[^0-9\.]', '', v)

    return v.strip()


# ── Main Cleaner ──────────────────────────────────────────────────────────────

def clean_dataframe(df, name):
    """Apply all cleaning steps to a dataframe."""

    print(f"\n  Cleaning {name}...")
    print(f"  Rows before: {len(df)}")

    # ── Step 1: Normalise vendor names ───────────────────────
    print("  [1] Normalising vendor names...")
    df['vendor'] = df['vendor'].apply(normalise_vendor)

    # ── Step 2: Normalise product names ──────────────────────
    print("  [2] Normalising product names...")
    df['product'] = df['product'].apply(normalise_product)

    # ── Step 3: Normalise version strings ────────────────────
    print("  [3] Normalising version strings...")
    df['version_start'] = df['version_start'].apply(normalise_version)
    df['version_end']   = df['version_end'].apply(normalise_version)

    # ── Step 4: Clean descriptions ───────────────────────────
    print("  [4] Cleaning descriptions...")
    df['description'] = df['description'].apply(clean_description)

    # ── Step 5: Remove rows where vendor AND product unknown ─
    print("  [5] Removing rows with no vendor AND no product...")
    before = len(df)
    mask = ~((df['vendor'] == 'unknown') & (df['product'] == 'unknown'))
    df = df[mask]
    print(f"      Removed {before - len(df)} rows")

    # ── Step 6: Remove rows with no description AND no product
    print("  [6] Removing rows with no description AND no product...")
    before = len(df)
    mask = ~((df['description'] == '') & (df['product'] == 'unknown'))
    df = df[mask]
    print(f"      Removed {before - len(df)} rows")

    # ── Step 7: Ensure correct data types ────────────────────
    print("  [7] Fixing data types...")
    df['cvss']     = pd.to_numeric(df['cvss'],     errors='coerce').fillna(0.0)
    df['epss']     = pd.to_numeric(df['epss'],     errors='coerce').fillna(0.0)
    df['kev']      = pd.to_numeric(df['kev'],      errors='coerce').fillna(0).astype(int)
    df['c_impact'] = pd.to_numeric(df['c_impact'], errors='coerce').fillna(0.0)
    df['i_impact'] = pd.to_numeric(df['i_impact'], errors='coerce').fillna(0.0)
    df['a_impact'] = pd.to_numeric(df['a_impact'], errors='coerce').fillna(0.0)
    df['is_ot']    = pd.to_numeric(df['is_ot'],    errors='coerce').fillna(0).astype(int)

    # ── Step 8: Remove duplicate CVE IDs ─────────────────────
    print("  [8] Removing duplicates...")
    before = len(df)
    df = df.drop_duplicates(subset=['cve_id'])
    print(f"      Removed {before - len(df)} duplicates")

    print(f"  Rows after:  {len(df)}")
    return df


def print_sample(df, name, n=5):
    """Show sample rows after cleaning."""
    print(f"\n  Sample rows from {name}:")
    print(f"  {'CVE ID':<20} {'Vendor':<25} {'Product':<25} {'CVSS':<6} {'EPSS':<7} {'KEV'}")
    print(f"  {'-'*20} {'-'*25} {'-'*25} {'-'*6} {'-'*7} {'-'*3}")
    for _, row in df.head(n).iterrows():
        print(f"  {row['cve_id']:<20} {row['vendor'][:24]:<25} {row['product'][:24]:<25} "
              f"{row['cvss']:<6} {row['epss']:<7.4f} {row['kev']}")


def main():
    print("=" * 60)
    print("  CAVE-OT FINAL DATA CLEANER")
    print("=" * 60)
    print(f"  Folder: {DATASET_FOLDER}")

    if not os.path.exists(DATASET_FOLDER):
        print(f"\n[!] Folder not found: {DATASET_FOLDER}")
        return

    # ── Load files ────────────────────────────────────────────
    full_path = os.path.join(DATASET_FOLDER, 'processed_cves.csv')
    ot_path   = os.path.join(DATASET_FOLDER, 'ot_cves_clean.csv')

    if not os.path.exists(full_path):
        print("[!] processed_cves.csv not found. Run data_processor.py first.")
        return

    if not os.path.exists(ot_path):
        print("[!] ot_cves_clean.csv not found. Run ot_cleaner.py first.")
        return

    print("\n[*] Loading datasets...")
    df_full = pd.read_csv(full_path)
    df_ot   = pd.read_csv(ot_path)
    print(f"  processed_cves.csv : {len(df_full)} rows")
    print(f"  ot_cves_clean.csv  : {len(df_ot)} rows")

    # ── Clean both ────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  CLEANING GENERAL DATASET")
    print("=" * 60)
    df_full_clean = clean_dataframe(df_full.copy(), "processed_cves.csv")

    print("\n" + "=" * 60)
    print("  CLEANING OT DATASET")
    print("=" * 60)
    df_ot_clean = clean_dataframe(df_ot.copy(), "ot_cves_clean.csv")

    # ── Show samples ──────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  SAMPLE OUTPUT")
    print("=" * 60)
    print_sample(df_ot_clean, "ot_training_ready.csv")

    # ── Save ──────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  SAVING")
    print("=" * 60)

    out_full = os.path.join(DATASET_FOLDER, 'training_ready.csv')
    out_ot   = os.path.join(DATASET_FOLDER, 'ot_training_ready.csv')

    df_full_clean.to_csv(out_full, index=False)
    df_ot_clean.to_csv(out_ot, index=False)

    print(f"\n  [+] Saved: training_ready.csv     ({len(df_full_clean)} rows)")
    print(f"  [+] Saved: ot_training_ready.csv  ({len(df_ot_clean)} rows)")

    # ── Final report ──────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  FINAL REPORT")
    print(f"{'='*60}")
    print(f"""
  General Dataset (training_ready.csv):
  ───────────────────────────────────────
  Total CVEs          : {len(df_full_clean)}
  With EPSS scores    : {(df_full_clean['epss'] > 0).sum()}
  In CISA KEV         : {(df_full_clean['kev'] == 1).sum()}
  OT flagged (is_ot)  : {(df_full_clean['is_ot'] == 1).sum()}

  OT Dataset (ot_training_ready.csv):
  ───────────────────────────────────────
  Total OT CVEs       : {len(df_ot_clean)}
  With EPSS scores    : {(df_ot_clean['epss'] > 0).sum()}
  In CISA KEV         : {(df_ot_clean['kev'] == 1).sum()}

  Top OT vendors after normalisation:""")

    for vendor, count in df_ot_clean['vendor'].value_counts().head(10).items():
        print(f"    {vendor:<35} {count} CVEs")

    report_path = os.path.join(DATASET_FOLDER, 'cleaning_report.txt')
    with open(report_path, 'w') as f:
        f.write(f"General dataset: {len(df_full_clean)} rows\n")
        f.write(f"OT dataset: {len(df_ot_clean)} rows\n")
        f.write(f"KEV in general: {(df_full_clean['kev']==1).sum()}\n")
        f.write(f"KEV in OT: {(df_ot_clean['kev']==1).sum()}\n")

    print(f"\n  [+] Saved: cleaning_report.txt")
    print(f"\n  → Next step: model_trainer.py")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()