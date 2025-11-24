#!/usr/bin/env python3
"""
network_discovery_make_network_file_progress.py

Same behavior as the previous discovery script but with a live progress display:
- Passive sniff (tshark) -> discover internal /24s -> fixed baselines
- Concurrent nmap -sn sweeps (streaming to network_<timestamp>.txt)
- Per-target timeout & host-timeout controls
- Live progress monitor (updates once/sec): total/pending/active/completed, active targets, hosts found, elapsed
- Final color-coded summary (per-target)
"""

import argparse
import ipaddress
import subprocess
import sys
import signal
import shutil
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from threading import Lock, Thread
from collections import Counter

NMAP_BIN = "/usr/bin/nmap"   # hardcoded
TSHARK_BIN = shutil.which("tshark") or "tshark"

# ---------- ANSI colors ----------
class Colors:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.RESET = "\033[0m" if enabled else ""
        self.DIM   = "\033[2m" if enabled else ""
        self.BOLD  = "\033[1m" if enabled else ""
        self.RED   = "\033[31m" if enabled else ""
        self.GREEN = "\033[32m" if enabled else ""
        self.YELLOW= "\033[33m" if enabled else ""
        self.BLUE  = "\033[34m" if enabled else ""
        self.CYAN  = "\033[36m" if enabled else ""
        self.GRAY  = "\033[90m" if enabled else ""

    def wrap(self, s, color): return f"{color}{s}{self.RESET}" if self.enabled else s

def color_ok(s, C):     return C.wrap(s, C.GREEN)
def color_warn(s, C):   return C.wrap(s, C.YELLOW)
def color_err(s, C):    return C.wrap(s, C.RED)
def color_info(s, C):   return C.wrap(s, C.CYAN)
def color_dim(s, C):    return C.wrap(s, C.GRAY)

# ---------- helpers ----------
def run(cmd, *, timeout=None, check=True):
    return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=check)

def capture_pcap(iface: str, duration: int, snaplen: int, out_pcap: Path, C: Colors):
    print(f"[*] Capturing on {iface} for {duration}s -> {out_pcap}")
    try:
        run([TSHARK_BIN, "-i", iface, "-a", f"duration:{duration}", "-s", str(snaplen), "-w", str(out_pcap)], check=False)
    except FileNotFoundError:
        print(color_err("[!] tshark not found in PATH.", C), file=sys.stderr); sys.exit(1)

def extract_ipv4_from_ip(pcap: Path, C: Colors):
    try:
        r = run([TSHARK_BIN, "-r", str(pcap), "-T", "fields", "-e", "ip.src", "-e", "ip.dst"], check=False)
    except FileNotFoundError:
        print(color_err("[!] tshark not found in PATH.", C), file=sys.stderr); sys.exit(1)

    if r.returncode != 0:
        print(color_warn(f"[!] tshark read warning (rc={r.returncode}): {r.stderr[:200]}", C), file=sys.stderr)

    addrs = set()
    for line in r.stdout.splitlines():
        for tok in line.split("\t"):
            tok = tok.strip()
            if not tok:
                continue
            # Properly validate IPv4 address
            try:
                ip = ipaddress.ip_address(tok)
                if isinstance(ip, ipaddress.IPv4Address):
                    addrs.add(tok)
            except ValueError:
                continue
    return addrs

def extract_ipv4_from_arp(pcap: Path, C: Colors):
    try:
        r = run([TSHARK_BIN, "-r", str(pcap), "-Y", "arp", "-T", "fields",
                 "-e", "arp.src.proto_ipv4", "-e", "arp.dst.proto_ipv4"], check=False)
    except FileNotFoundError:
        print(color_err("[!] tshark not found in PATH.", C), file=sys.stderr); sys.exit(1)

    if r.returncode != 0:
        print(color_warn(f"[!] tshark ARP read warning (rc={r.returncode}): {r.stderr[:200]}", C), file=sys.stderr)

    addrs = set()
    for line in r.stdout.splitlines():
        for tok in line.split("\t"):
            tok = tok.strip()
            if not tok:
                continue
            # Properly validate IPv4 address
            try:
                ip = ipaddress.ip_address(tok)
                if isinstance(ip, ipaddress.IPv4Address):
                    addrs.add(tok)
            except ValueError:
                continue
    return addrs

def extract_ipv4_from_dns(pcap: Path, C: Colors):
    """Extract IPs from DNS queries and responses"""
    try:
        # Get DNS A record answers
        r = run([TSHARK_BIN, "-r", str(pcap), "-Y", "dns.a", "-T", "fields",
                 "-e", "dns.a", "-e", "ip.src", "-e", "ip.dst"], check=False)
    except FileNotFoundError:
        print(color_err("[!] tshark not found in PATH.", C), file=sys.stderr); sys.exit(1)

    if r.returncode != 0:
        print(color_warn(f"[!] tshark DNS read warning (rc={r.returncode}): {r.stderr[:200]}", C), file=sys.stderr)

    addrs = set()
    for line in r.stdout.splitlines():
        for tok in line.split("\t"):
            tok = tok.strip()
            if not tok:
                continue
            # Handle comma-separated multiple DNS answers
            for ip_str in tok.split(","):
                ip_str = ip_str.strip()
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if isinstance(ip, ipaddress.IPv4Address):
                        addrs.add(ip_str)
                except ValueError:
                    continue
    return addrs

def extract_ipv4_from_dhcp(pcap: Path, C: Colors):
    """Extract IPs from DHCP packets"""
    try:
        r = run([TSHARK_BIN, "-r", str(pcap), "-Y", "dhcp", "-T", "fields",
                 "-e", "dhcp.ip.your", "-e", "dhcp.ip.client", "-e", "dhcp.ip.server",
                 "-e", "dhcp.option.dhcp_server_id", "-e", "dhcp.option.router"], check=False)
    except FileNotFoundError:
        print(color_err("[!] tshark not found in PATH.", C), file=sys.stderr); sys.exit(1)

    if r.returncode != 0:
        print(color_warn(f"[!] tshark DHCP read warning (rc={r.returncode}): {r.stderr[:200]}", C), file=sys.stderr)

    addrs = set()
    for line in r.stdout.splitlines():
        for tok in line.split("\t"):
            tok = tok.strip()
            if not tok:
                continue
            # Handle comma-separated values (DHCP options can have multiple values)
            for ip_str in tok.split(","):
                ip_str = ip_str.strip()
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if isinstance(ip, ipaddress.IPv4Address):
                        addrs.add(ip_str)
                except ValueError:
                    continue
    return addrs

def extract_mac_to_ip_mapping(pcap: Path, C: Colors):
    """Extract MAC to IP mappings from ARP packets"""
    try:
        r = run([TSHARK_BIN, "-r", str(pcap), "-Y", "arp", "-T", "fields",
                 "-e", "arp.src.proto_ipv4", "-e", "arp.src.hw_mac"], check=False)
    except FileNotFoundError:
        return {}

    if r.returncode != 0:
        return {}

    mac_to_ips = {}
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            ip_str = parts[0].strip()
            mac_str = parts[1].strip()
            if ip_str and mac_str:
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if isinstance(ip, ipaddress.IPv4Address):
                        if mac_str not in mac_to_ips:
                            mac_to_ips[mac_str] = set()
                        mac_to_ips[mac_str].add(ip_str)
                except ValueError:
                    continue
    return mac_to_ips

# ---------- internal filter ----------
RFC1918 = [ipaddress.ip_network(s) for s in ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")]
CUSTOM  = [ipaddress.ip_network("172.132.0.0/16")]
ALLOW   = list(ipaddress.collapse_addresses(RFC1918 + CUSTOM))
BLOCK   = [ipaddress.ip_network(s) for s in (
    "0.0.0.0/8","127.0.0.0/8","224.0.0.0/4","240.0.0.0/4",
    "192.0.2.0/24","198.51.100.0/24","203.0.113.0/24","255.255.255.255/32"
)]
def ip_in(nets, ip): return any(ip in n for n in nets)

def keep_internal(ips):
    kept = []
    for s in ips:
        try:
            ip = ipaddress.ip_address(s)
            if not isinstance(ip, ipaddress.IPv4Address): continue
            if ip_in(BLOCK, ip): continue
            if ip_in(ALLOW, ip): kept.append(s)
        except ValueError:
            continue
    kept.sort(key=lambda x: list(map(int, x.split("."))))
    return kept

# ---------- aggregation ----------
def aggregate_subnets(ips, prefix=24):
    counts = Counter()
    for s in ips:
        try:
            ip = ipaddress.ip_address(s)
            if isinstance(ip, ipaddress.IPv4Address):
                counts[ipaddress.ip_network(f"{s}/{prefix}", strict=False)] += 1
        except ValueError:
            pass
    return [str(net) for net,_ in counts.most_common()]

def calculate_target_size(target):
    """Calculate number of hosts in a CIDR target"""
    try:
        net = ipaddress.ip_network(target, strict=False)
        return net.num_addresses
    except:
        return 256  # default guess

def import_subnets_from_previous_network(file_path: Path, prefix: int, C: Colors):
    """
    Import IPs from a previous network.txt file and aggregate into subnets.
    Filters to only include private IPs (RFC1918 + custom ranges).
    Returns list of unique CIDR subnets.
    """
    if not file_path.exists():
        print(color_err(f"[!] Previous network file not found: {file_path}", C), file=sys.stderr)
        return []

    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        print(color_err(f"[!] Error reading previous network file: {e}", C), file=sys.stderr)
        return []

    # Extract and filter IPs
    imported_ips = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # Handle lines that might have IPs plus other data (take first token)
        ip_str = line.split()[0] if line.split() else line

        try:
            ip = ipaddress.ip_address(ip_str)
            if not isinstance(ip, ipaddress.IPv4Address):
                continue
            # Filter to only private IPs
            if ip_in(ALLOW, ip) and not ip_in(BLOCK, ip):
                imported_ips.append(ip_str)
        except ValueError:
            continue

    if not imported_ips:
        print(color_warn("[!] No valid private IPs found in previous network file", C))
        return []

    # Aggregate into subnets
    subnets = aggregate_subnets(imported_ips, prefix=prefix)
    return subnets

# ---------- nmap sweep ----------
def nmap_ping_sweep(target, host_timeout_s=90, max_retries=1, per_target_timeout=None, min_rate=300, ping_methods="default"):
    """
    Run nmap ping sweep on a target with multiple ping methods.
    ping_methods: "default" (ICMP only), "aggressive" (ICMP+TCP+ARP), or "stealth" (TCP SYN only)
    Returns (set of IPs, error_string or None)
    """
    cmd = [NMAP_BIN, "-sn", "-n", "-T5", "--max-retries", str(max_retries),
           "--host-timeout", f"{host_timeout_s}s", "--min-rate", str(min_rate)]

    # Add ping method flags
    if ping_methods == "aggressive":
        # ICMP echo, ICMP timestamp, TCP SYN 80/443, ARP
        cmd.extend(["-PE", "-PP", "-PS80,443", "-PA80,443", "-PR"])
    elif ping_methods == "stealth":
        # TCP SYN only to common ports (no ICMP)
        cmd.extend(["-PS21,22,23,25,80,135,139,443,445,3389", "-PA80,443", "--disable-arp-ping"])
    elif ping_methods == "arp-only":
        # ARP only (fastest for local networks)
        cmd.extend(["-PR", "--disable-ping"])
    # else: default nmap behavior

    cmd.extend([target, "-oG", "-"])

    try:
        r = run(cmd, timeout=per_target_timeout, check=True)
    except subprocess.TimeoutExpired:
        return set(), "timeout(subprocess)"
    except subprocess.CalledProcessError as e:
        return set(), f"nmap_error(rc={e.returncode})"
    except FileNotFoundError:
        return set(), "nmap_not_found"
    except Exception as e:
        return set(), f"exception({type(e).__name__})"

    up = set()
    for line in r.stdout.splitlines():
        if line.startswith("Host:") and "Status: Up" in line:
            parts = line.split()
            if len(parts) >= 2:
                # Validate IP before adding
                try:
                    ip = ipaddress.ip_address(parts[1])
                    if isinstance(ip, ipaddress.IPv4Address):
                        up.add(parts[1])
                except ValueError:
                    continue
    return up, None

# ---------- streaming append (thread-safe) ----------
from threading import Lock
def append_lines(path: Path, items, lock: Lock):
    if not items: return
    with lock:
        with open(path, "a") as f:
            for it in items:
                f.write(f"{it}\n")

# ---------- signals ----------
stop_requested = False
def handle_stop(signum, frame):
    global stop_requested
    stop_requested = True
    print("\n[!] Interrupt received; finishing in-flight tasks…", file=sys.stderr)

# ---------- main ----------
def main():
    signal.signal(signal.SIGINT, handle_stop)
    signal.signal(signal.SIGTERM, handle_stop)

    default_workers = 8
    ap = argparse.ArgumentParser(description="Make network_<timestamp>.txt (live IPv4s) — passive sniff + concurrent nmap -sn with progress")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--iface", help="Interface to capture from (e.g., eth0)")
    mode.add_argument("--pcap", help="Use existing pcap file")
    ap.add_argument("--duration", type=int, default=60, help="Capture seconds (default 60)")
    ap.add_argument("--snaplen", type=int, default=256, help="Snaplen bytes (default 256)")
    ap.add_argument("--prefix", type=int, default=24, help="Aggregate discovered IPs into /prefix (default 24)")
    ap.add_argument("--workers", type=int, default=default_workers, help=f"Max concurrent nmap workers (default {default_workers})")
    ap.add_argument("--per-target-timeout", type=int, default=180, help="Subprocess timeout per target sweep (default 180s)")
    ap.add_argument("--host-timeout", type=int, default=90, help="nmap --host-timeout seconds per host (default 90)")
    ap.add_argument("--max-retries", type=int, default=1, help="nmap --max-retries (default 1)")
    ap.add_argument("--min-rate", type=int, default=300, help="nmap --min-rate packets/sec (default 300)")
    ap.add_argument("--ping-method", choices=["default", "aggressive", "stealth", "arp-only"], default="default",
                    help="Ping method: default (ICMP), aggressive (ICMP+TCP+ARP), stealth (TCP only), arp-only (ARP only)")
    ap.add_argument("--extract-dns", action="store_true", help="Extract IPs from DNS responses (slower)")
    ap.add_argument("--extract-dhcp", action="store_true", help="Extract IPs from DHCP packets (slower)")
    ap.add_argument("--import-network", metavar="FILE", help="Import IPs from previous year's network.txt and scan those subnets")
    ap.add_argument("--import-prefix", type=int, default=16, help="Aggregate imported IPs into /PREFIX subnets (default: 16 for /16)")
    ap.add_argument("--delete-imported", action="store_true", help="Delete imported network file after processing (avoid artifacts)")
    ap.add_argument("--extra-cidr", action="append", help="Add manual internal CIDRs")
    ap.add_argument("--prioritize-discovered", action="store_true", help="Scan discovered subnets first (recommended)")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors in summary/progress")
    ap.add_argument("--outdir", default="recon_out", help="Output directory")
    ap.add_argument("--label", default="", help="Optional filename label")
    args = ap.parse_args()

    C = Colors(enabled=not args.no_color and sys.stdout.isatty())

    outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    tag = ts + (f"_{args.label}" if args.label else "")

    # passive capture
    if args.iface:
        pcap = outdir / f"capture_{tag}.pcapng"
        capture_pcap(args.iface, args.duration, args.snaplen, pcap, C)
    else:
        pcap = Path(args.pcap)
        if not pcap.exists():
            print(color_err(f"[!] pcap not found: {pcap}", C), file=sys.stderr); sys.exit(1)

    print(f"[*] Extracting IPs from pcap: {pcap}")
    ip_from_ip = extract_ipv4_from_ip(pcap, C)
    ip_from_arp = extract_ipv4_from_arp(pcap, C)
    ip_set = ip_from_ip | ip_from_arp

    # Optional DNS extraction (can find internal IPs resolved by DNS)
    if args.extract_dns:
        print("[*] Extracting IPs from DNS packets...")
        ip_from_dns = extract_ipv4_from_dns(pcap, C)
        ip_set |= ip_from_dns
        print(color_info(f"[+] Extracted {len(ip_from_dns)} IPs from DNS layer", C))

    # Optional DHCP extraction (finds DHCP servers, gateways, assigned IPs)
    if args.extract_dhcp:
        print("[*] Extracting IPs from DHCP packets...")
        ip_from_dhcp = extract_ipv4_from_dhcp(pcap, C)
        ip_set |= ip_from_dhcp
        print(color_info(f"[+] Extracted {len(ip_from_dhcp)} IPs from DHCP layer", C))

    # MAC to IP mapping for detecting multi-homed hosts
    mac_to_ips = extract_mac_to_ip_mapping(pcap, C)
    multi_ip_hosts = {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 1}

    print(color_info(f"[+] Extracted {len(ip_from_ip)} IPs from IP layer", C))
    print(color_info(f"[+] Extracted {len(ip_from_arp)} IPs from ARP layer", C))
    print(color_info(f"[+] Total unique IPs: {len(ip_set)}", C))
    if multi_ip_hosts:
        print(color_info(f"[+] Detected {len(multi_ip_hosts)} multi-IP hosts (load balancers/VMs?)", C))

    internal_ips = keep_internal(ip_set)
    print(color_info(f"[+] Internal IPs after filtering: {len(internal_ips)}", C))

    # discovered /24 targets
    discovered_targets = aggregate_subnets(internal_ips, prefix=args.prefix)
    print(color_info(f"[+] Discovered /{args.prefix} subnets: {len(discovered_targets)}", C))
    if discovered_targets:
        print(color_dim(f"    Discovered: {', '.join(discovered_targets[:5])}" +
                       (f" ... (+{len(discovered_targets)-5} more)" if len(discovered_targets) > 5 else ""), C))

    # Import subnets from previous year's audit
    imported_targets = []
    imported_file_path = None
    if args.import_network:
        imported_file_path = Path(args.import_network)
        print(f"[*] Importing subnets from previous network file: {args.import_network}")
        imported_targets = import_subnets_from_previous_network(
            imported_file_path,
            prefix=args.import_prefix,
            C=C
        )
        if imported_targets:
            print(color_info(f"[+] Imported {len(imported_targets)} /{args.import_prefix} subnets from previous audit", C))
            print(color_dim(f"    Imported: {', '.join(imported_targets[:5])}" +
                           (f" ... (+{len(imported_targets)-5} more)" if len(imported_targets) > 5 else ""), C))

        # Securely delete the imported file if requested (avoid leaving artifacts on client systems)
        if args.delete_imported and imported_file_path.exists():
            try:
                imported_file_path.unlink()
                print(color_info(f"[+] Deleted imported file: {imported_file_path} (artifact cleanup)", C))
            except Exception as e:
                print(color_warn(f"[!] Could not delete imported file: {e}", C), file=sys.stderr)

    # fixed baselines (per your playbook)
    baseline_targets = [
        "10.1.0.0/16", "10.10.0.0/16", "10.50.0.0/16", "10.100.0.0/16",
        "172.16.0.0/16", "172.132.0.0/16", "192.168.0.0/16",
    ]

    extras = [c for c in (args.extra_cidr or [])]

    # Smart prioritization: scan discovered subnets first (they have active hosts)
    if args.prioritize_discovered:
        # Discovered first, then imported (from prev audit), then extras, then baselines
        target_order = discovered_targets + imported_targets + extras + baseline_targets
        print(color_info("[+] Prioritizing discovered subnets (active traffic detected)", C))
    else:
        # Original order: discovered, imported, extras, baselines
        target_order = discovered_targets + imported_targets + extras + baseline_targets

    ordered_targets = []
    for t in target_order:
        if t not in ordered_targets:
            ordered_targets.append(t)

    if not ordered_targets:
        print(color_warn("[!] No targets to sweep (empty capture and no baselines?)", C))
        print(color_info(f"[+] Passive capture -> {pcap.resolve()}", C))
        print("\n" + color_ok("✔ All output files saved in:", C))
        print(f"    {outdir.resolve()}")
        return 0

    # Warn about large networks
    total_hosts = sum(calculate_target_size(t) for t in ordered_targets)
    large_targets = [t for t in ordered_targets if calculate_target_size(t) > 1024]
    if large_targets:
        print(color_warn(f"[!] Warning: {len(large_targets)} large network(s) detected (>{1024} hosts)", C))
        print(color_dim(f"    Large networks: {', '.join(large_targets[:3])}" +
                       (f" ... (+{len(large_targets)-3} more)" if len(large_targets) > 3 else ""), C))
        print(color_info(f"[+] Estimated total hosts to scan: {total_hosts:,}", C))
        estimated_time_min = (total_hosts / args.min_rate) / 60
        print(color_info(f"[+] Estimated scan time: ~{estimated_time_min:.1f} minutes (at {args.min_rate} packets/sec)", C))

    # prepare streaming network file
    network_txt = outdir / f"network_{tag}.txt"
    network_txt.write_text("")  # truncate/create
    file_lock = Lock()
    seen_lock = Lock()  # lock for the seen set
    seen = set()

    # bookkeeping for progress & summary
    total_targets = len(ordered_targets)
    pending = list(ordered_targets)
    in_progress = set()
    completed = []
    target_rows = []  # dicts with metadata
    progress_lock = Lock()
    start_time = time.monotonic()
    total_found = 0

    def record_row(row):
        with progress_lock:
            target_rows.append(row)
            completed.append(row["target"])
            if row["target"] in in_progress:
                in_progress.discard(row["target"])
            if row["target"] in pending:
                try: pending.remove(row["target"])
                except ValueError: pass

    # monitor thread
    def monitor():
        while True:
            with progress_lock:
                done = len(completed)
                running = len(in_progress)
                pend = len(pending)
                active_list = list(in_progress)[:3]
            with seen_lock:
                found = len(seen)
            elapsed = int(time.monotonic() - start_time)
            # build status line
            status = f"Targets: total={total_targets} done={done} running={running} pend={pend} | hosts={found} | elapsed={elapsed}s"
            if active_list:
                status += " | active=" + ",".join(active_list)
            # pad/clear line
            sys.stdout.write("\r" + status + " " * 10)
            sys.stdout.flush()
            if done == total_targets or stop_requested:
                break
            time.sleep(1)
        # final newline to not overwrite summary
        sys.stdout.write("\n")
        sys.stdout.flush()

    # worker wrapper
    def worker(target):
        # Check if stop was requested before starting
        if stop_requested:
            row = {"target": target, "status": "skipped", "found": 0, "elapsed": 0, "error": "interrupted"}
            record_row(row)
            return 0

        with progress_lock:
            in_progress.add(target)
            if target in pending:
                try: pending.remove(target)
                except ValueError: pass
        start = time.monotonic()
        ips, err = nmap_ping_sweep(target, host_timeout_s=args.host_timeout,
                                   max_retries=args.max_retries,
                                   per_target_timeout=args.per_target_timeout,
                                   min_rate=args.min_rate,
                                   ping_methods=args.ping_method)
        elapsed = time.monotonic() - start
        if err:
            row = {"target": target, "status": "failed", "found": 0, "elapsed": elapsed, "error": err}
            record_row(row)
            return 0
        # filter internal & dedupe
        new_ips = []
        for s in ips:
            try:
                ip = ipaddress.ip_address(s)
                if ip_in(ALLOW, ip) and not ip_in(BLOCK, ip):
                    with seen_lock:
                        if s not in seen:
                            seen.add(s)
                            new_ips.append(s)
            except Exception:
                continue
        # stream to file
        append_lines(network_txt, new_ips, file_lock)
        row = {"target": target, "status": "ok", "found": len(new_ips), "elapsed": elapsed, "error": None}
        record_row(row)
        return len(new_ips)

    # start monitor
    mon = Thread(target=monitor, daemon=True)
    mon.start()

    # run concurrent sweeps
    max_workers = max(1, min(args.workers, len(ordered_targets)))
    print(f"[*] Sweeping {len(ordered_targets)} target(s) with {max_workers} worker(s)…")
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(worker, t): t for t in ordered_targets}
        try:
            for fut in as_completed(futures):
                t = futures[fut]
                try:
                    n = fut.result()
                    total_found += n
                    with seen_lock:
                        total_seen = len(seen)
                    print(color_info(f"[+] {t}: {n} new host(s) (running total: {total_seen})", C))
                except Exception as e:
                    print(color_err(f"[!] {t} raised: {e}", C), file=sys.stderr)
        except KeyboardInterrupt:
            print("\n" + color_warn("[!] Interrupted; partial results preserved.", C), file=sys.stderr)

    # wait for monitor to finish its last iteration
    mon.join(timeout=2)

    # final dedupe & sort
    try:
        lines = list({ln.strip() for ln in network_txt.read_text().splitlines() if ln.strip()})
        lines.sort(key=lambda x: list(map(int, x.split("."))))
        network_txt.write_text("\n".join(lines) + ("\n" if lines else ""))
        total_found = len(lines)
    except FileNotFoundError:
        total_found = 0

    # ---------- Color summary ----------
    print("\n" + color_info("=== Discovery Summary ===", C))
    def sort_key(r):
        pri = 0 if r["status"] == "failed" else (1 if r["status"] == "ok" else 2)
        return (pri, -r["found"], r["target"])
    for r in sorted(target_rows, key=sort_key):
        elapsed_ms = int(r["elapsed"] * 1000)
        if r["status"] == "ok":
            line = f"[OK]   {r['target']:<18} hosts={r['found']:<5} time={elapsed_ms}ms"
            print(color_ok(line, C))
        elif r["status"] == "failed":
            line = f"[FAIL] {r['target']:<18} hosts=0     time={elapsed_ms}ms err={r['error']}"
            print(color_err(line, C))
        else:
            line = f"[SKIP] {r['target']:<18} hosts=0     reason={r.get('error','')}"
            print(color_warn(line, C))

    ok_count = sum(1 for r in target_rows if r["status"] == "ok")
    fail_count = sum(1 for r in target_rows if r["status"] == "failed")
    skip_count = sum(1 for r in target_rows if r["status"] not in ("ok","failed"))
    print(color_info(f"\nTotals: targets={len(target_rows)} ok={ok_count} failed={fail_count} skipped={skip_count}", C))
    print(color_info(f"Live hosts collected: {total_found}", C))

    # final paths
    print("\n" + color_ok(f"[+] Network file -> {network_txt.resolve()} ({total_found} IPs)", C))
    print(color_ok(f"[+] Passive capture -> {pcap.resolve()}", C))
    print("\n" + color_ok("✔ All output files saved in:", C))
    print(f"    {outdir.resolve()}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
