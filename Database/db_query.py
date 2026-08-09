"""
CAVE-OT Database Query Tool
============================
Run this to see what is stored in the database.

Usage (run from Database folder):
    python db_query.py              shows everything
    python db_query.py assets       shows all assets
    python db_query.py critical     shows critical CVEs
    python db_query.py alerts       shows all alerts
"""

import sys
import psycopg2.extras
from db_manager import (
    get_connection,
    get_dashboard_summary,
    get_all_assets,
    get_vulnerabilities_for_asset,
    get_critical_vulnerabilities,
)


def show_summary(conn):
    s = get_dashboard_summary(conn)
    print("\n" + "=" * 55)
    print("CAVE-OT DATABASE SUMMARY")
    print("=" * 55)
    print(f"  Total assets      : {s['total_assets']}")
    print(f"  Active assets     : {s['active_assets']}")
    print(f"  Inactive assets   : {s['total_assets'] - s['active_assets']}")
    print(f"  Total CVEs        : {s['total_cves']}")
    print(f"  Critical CVEs     : {s['critical_cves']}")
    print(f"  High CVEs         : {s['high_cves']}")
    print(f"  KEV CVEs          : {s['kev_cves']}")
    print(f"  Total alerts      : {s['total_alerts']}")
    print(f"  Active attacks    : {s['active_attacks']}")
    print(f"  Generated at      : {s['generated_at']}")


def show_assets(conn):
    assets = get_all_assets(conn)
    print("\n" + "=" * 95)
    print("ALL ASSETS")
    print("=" * 95)
    print(f"{'ID':<4} {'IP':<16} {'PORT':<6} {'VENDOR':<22} {'PRODUCT':<20} {'STATUS':<10} {'LAST SEEN'}")
    print("-" * 95)
    for a in assets:
        last_seen = str(a['last_seen'])[:19] if a['last_seen'] else 'N/A'
        print(f"{a['id']:<4} {a['ip']:<16} {a['port']:<6} "
              f"{str(a['vendor'] or ''):<22} {str(a['product'] or ''):<20} "
              f"{a['status']:<10} {last_seen}")


def show_critical(conn):
    cves = get_critical_vulnerabilities(conn, limit=30)
    print("\n" + "=" * 105)
    print("CRITICAL & HIGH VULNERABILITIES")
    print("=" * 105)
    print(f"{'CVE ID':<20} {'CVSS':<6} {'EPSS':<8} {'RISK':<6} {'TIER':<10} {'IP':<16} {'VENDOR':<22} {'PRODUCT'}")
    print("-" * 105)
    for v in cves:
        kev = " [KEV]" if v['kev'] else ""
        print(f"{v['cve_id']:<20} {v['cvss']:<6} {v['epss']:<8.4f} "
              f"{v['risk_score']:<6} {v['risk_tier']:<10} {v['ip']:<16} "
              f"{str(v['vendor'] or ''):<22} {v['product']}{kev}")


def show_alerts(conn):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT al.id, al.detected_at, al.alert_signature,
               al.severity, al.is_active_attack,
               a.ip, a.vendor, a.product
        FROM alerts al
        JOIN assets a ON a.id = al.asset_id
        ORDER BY al.detected_at DESC LIMIT 20;
    """)
    alerts = cur.fetchall()
    print("\n" + "=" * 80)
    print("RECENT ALERTS")
    print("=" * 80)
    if not alerts:
        print("  No alerts yet. Alerts come from Suricata.")
    else:
        print(f"{'ID':<5} {'TIME':<20} {'SEV':<5} {'ACTIVE':<8} {'IP':<16} {'SIGNATURE'}")
        print("-" * 80)
        for al in alerts:
            t      = str(al['detected_at'])[:19]
            active = "YES" if al['is_active_attack'] else "no"
            sig    = str(al['alert_signature'] or 'N/A')[:30]
            print(f"{al['id']:<5} {t:<20} {al['severity']:<5} {active:<8} {al['ip']:<16} {sig}")


def main():
    conn    = get_connection()
    command = sys.argv[1] if len(sys.argv) > 1 else "all"

    if command == "assets":
        show_assets(conn)
    elif command == "critical":
        show_critical(conn)
    elif command == "alerts":
        show_alerts(conn)
    else:
        show_summary(conn)
        show_assets(conn)
        show_critical(conn)
        show_alerts(conn)

    conn.close()


if __name__ == "__main__":
    main()
