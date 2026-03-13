#!/usr/bin/env python3
"""Display statistics collected by rns-statsd from a SQLite database."""

import argparse
import sqlite3
import sys
from datetime import datetime, timezone

# Known name_hash -> app+aspect mappings (SHA-256 of the string, first 10 bytes)
KNOWN_NAMES = {
    "6ec60bc318e2c0f0d908": "lxmf.delivery",
    "e023ea4cabdd7fcd2868": "lxmf.propagation",
    "e03a09b77ac21b22258e": "nomadnetwork.node",
    "629404a89a06de5e2f64": "lxst.telephony",
    "213e6311bcec54ab4fde": "call.audio",
    "d11f60fdef3493ff0588": "retibbs.bbs",
    "27a116f23e07b6b9931f": "rrc.hub",
    "db370f50a7f92e5e51f6": "rnstransport.longhaul",
    "505c3e43c4cc1f9c64fe": "rnstransport.gateway",
    "e8126712ffbd9c8ce5e0": "rnstransport.peering",
    "31436bde96387d60f4f5": "rnstransport.backhaulpeering",
    "3bf01989ad00bf2af554": "rnstransport.haulpeering",
    "ac9fd3a81e4036f86e1d": "rns_manager.device",
    "ef171fe2640be4955613": "call.video",
    "fd68805f2ea383c8d6f6": "rnstransport.directpeering",
    "48ceca7217e0501d5550": "lxmf.messenger",
    "fa07e2e35e7a39cb8e26": "nomadnetwork.browser",
}


def fmt_hash(blob):
    return blob.hex() if isinstance(blob, (bytes, memoryview)) else str(blob)


def fmt_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def fmt_ts(ms):
    if ms is None:
        return "n/a"
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def section(title):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def show_overview(cur):
    section("OVERVIEW")
    cur.execute("SELECT COUNT(*) FROM seen_announces")
    announces = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM seen_identities")
    identities = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM seen_destinations")
    destinations = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM seen_names")
    names = cur.fetchone()[0]

    cur.execute("SELECT MIN(seen_at_ms), MAX(seen_at_ms) FROM seen_announces")
    first, last = cur.fetchone()

    print(f"  Unique announces : {announces:,}")
    print(f"  Identities       : {identities:,}")
    print(f"  Destinations     : {destinations:,}")
    print(f"  Name hashes      : {names:,}")
    if first and last:
        span_h = (last - first) / 3_600_000
        print(f"  Time span        : {fmt_ts(first)} -> {fmt_ts(last)} ({span_h:.1f}h)")
        if span_h > 0:
            print(f"  Announce rate     : {announces / span_h:.0f}/h")


def show_packets(cur):
    section("PACKET COUNTERS")
    cur.execute("""
        SELECT direction, packet_type, SUM(packets), SUM(bytes)
        FROM packet_counters
        GROUP BY direction, packet_type
        ORDER BY SUM(packets) DESC
    """)
    rows = cur.fetchall()
    if not rows:
        print("  (no data)")
        return
    print(f"  {'Direction':<6} {'Type':<14} {'Packets':>12} {'Bytes':>12}")
    print(f"  {'-'*6} {'-'*14} {'-'*12} {'-'*12}")
    for d, t, p, b in rows:
        print(f"  {d:<6} {t:<14} {p:>12,} {fmt_bytes(b):>12}")


def show_names(cur, limit):
    section(f"TOP ANNOUNCED SERVICES (name hashes, limit {limit})")
    cur.execute("""
        SELECT name_hash, announce_count, first_seen_ms, last_seen_ms
        FROM seen_names
        ORDER BY announce_count DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    if not rows:
        print("  (no data)")
        return
    print(f"  {'Name Hash':<22} {'Known Name':<36} {'Count':>8} {'Last Seen'}")
    print(f"  {'-'*22} {'-'*36} {'-'*8} {'-'*19}")
    for nh, count, _first, last in rows:
        h = fmt_hash(nh)
        known = KNOWN_NAMES.get(h, "")
        print(f"  {h:<22} {known:<36} {count:>8,} {fmt_ts(last)}")


def show_identities(cur, limit):
    section(f"TOP IDENTITIES (by announce count, limit {limit})")
    cur.execute("""
        SELECT identity_hash, announce_count, first_seen_ms, last_seen_ms
        FROM seen_identities
        ORDER BY announce_count DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    if not rows:
        print("  (no data)")
        return
    print(f"  {'Identity Hash':<34} {'Announces':>10} {'First Seen':<20} {'Last Seen'}")
    print(f"  {'-'*34} {'-'*10} {'-'*20} {'-'*19}")
    for ih, count, first, last in rows:
        print(f"  {fmt_hash(ih):<34} {count:>10,} {fmt_ts(first):<20} {fmt_ts(last)}")


def show_destinations(cur, limit):
    section(f"TOP DESTINATIONS (by announce count, limit {limit})")
    cur.execute("""
        SELECT destination_hash, identity_hash, name_hash, announce_count,
               last_hops, last_seen_ms
        FROM seen_destinations
        ORDER BY announce_count DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    if not rows:
        print("  (no data)")
        return
    print(f"  {'Destination':<34} {'Service':<28} {'Count':>8} {'Hops':>5} {'Last Seen'}")
    print(f"  {'-'*34} {'-'*28} {'-'*8} {'-'*5} {'-'*19}")
    for dh, _ih, nh, count, hops, last in rows:
        name = KNOWN_NAMES.get(fmt_hash(nh), fmt_hash(nh)[:16] + "..")
        print(f"  {fmt_hash(dh):<34} {name:<28} {count:>8,} {hops:>5} {fmt_ts(last)}")


def show_process(cur, limit):
    section(f"PROCESS VITALS (last {limit} samples)")
    cur.execute("""
        SELECT ts_ms, pid, rss_bytes, cpu_user_ms, cpu_system_ms, threads, fds
        FROM process_samples
        ORDER BY ts_ms DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    if not rows:
        print("  (no data)")
        return
    rows.reverse()

    print(f"  {'Timestamp':<20} {'PID':>8} {'RSS':>10} {'CPU usr':>10} {'CPU sys':>10} {'Thr':>5} {'FDs':>5}")
    print(f"  {'-'*20} {'-'*8} {'-'*10} {'-'*10} {'-'*10} {'-'*5} {'-'*5}")
    prev_user = prev_sys = None
    for ts, pid, rss, cpu_u, cpu_s, thr, fds in rows:
        u_delta = f"+{cpu_u - prev_user}ms" if prev_user is not None else f"{cpu_u}ms"
        s_delta = f"+{cpu_s - prev_sys}ms" if prev_sys is not None else f"{cpu_s}ms"
        prev_user, prev_sys = cpu_u, cpu_s
        print(f"  {fmt_ts(ts):<20} {pid:>8} {fmt_bytes(rss):>10} {u_delta:>10} {s_delta:>10} {thr:>5} {fds:>5}")

    # Summary from first to last
    first, last = rows[0], rows[-1]
    span_s = (last[0] - first[0]) / 1000
    if span_s > 0:
        cpu_total = (last[3] - first[3]) + (last[4] - first[4])
        avg_cpu = cpu_total / span_s * 100 / 1000
        print(f"\n  Monitoring span: {span_s/3600:.1f}h | Avg CPU: {avg_cpu:.2f}% | Current RSS: {fmt_bytes(last[2])}")


def show_recent_announces(cur, limit):
    section(f"RECENT ANNOUNCES (last {limit})")
    cur.execute("""
        SELECT destination_hash, identity_hash, name_hash, hops, interface_id, seen_at_ms
        FROM seen_announces
        ORDER BY seen_at_ms DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    if not rows:
        print("  (no data)")
        return
    print(f"  {'Destination':<34} {'Service':<24} {'Hops':>5} {'Seen At'}")
    print(f"  {'-'*34} {'-'*24} {'-'*5} {'-'*19}")
    for dh, _ih, nh, hops, _iface, ts in rows:
        name = KNOWN_NAMES.get(fmt_hash(nh), fmt_hash(nh)[:16] + "..")
        print(f"  {fmt_hash(dh):<34} {name:<24} {hops:>5} {fmt_ts(ts)}")


def main():
    parser = argparse.ArgumentParser(description="Display rns-statsd statistics")
    parser.add_argument("db", help="Path to the stats SQLite database")
    parser.add_argument("-n", "--limit", type=int, default=20, help="Max rows per section (default: 20)")
    parser.add_argument("-s", "--section", choices=["overview", "packets", "names", "identities",
                        "destinations", "process", "recent"], help="Show only a specific section")
    args = parser.parse_args()

    try:
        conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    except sqlite3.OperationalError as e:
        print(f"Error: cannot open database: {e}", file=sys.stderr)
        sys.exit(1)

    cur = conn.cursor()

    sections = {
        "overview": lambda: show_overview(cur),
        "packets": lambda: show_packets(cur),
        "names": lambda: show_names(cur, args.limit),
        "identities": lambda: show_identities(cur, args.limit),
        "destinations": lambda: show_destinations(cur, args.limit),
        "process": lambda: show_process(cur, args.limit),
        "recent": lambda: show_recent_announces(cur, args.limit),
    }

    if args.section:
        sections[args.section]()
    else:
        for fn in sections.values():
            fn()

    conn.close()
    print()


if __name__ == "__main__":
    main()
