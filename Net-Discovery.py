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
        r = run([TSHARK_BIN, "-r", str(pcap), "-T", "fields", "-e", "ip.src", "-e", "ip.dst"])
    except FileNotFoundError:
        print(color_err("[!] tshark not found in PATH.", C), file=sys.stderr); sys.exit(1)
    addrs = set()
    for line in r.stdout.splitlines():
        for tok in line.split("\t"):
            tok = tok.strip()
            if tok.count(".") == 3:
                addrs.add(tok)
    return addrs

def extract_ipv4_from_arp(pcap: Path, C: Colors):
    try:
        r = run([TSHARK_BIN, "-r", str(pcap), "-Y", "arp", "-T", "fields",
                 "-e", "arp.src.proto_ipv4", "-e", "arp.dst.proto_ipv4"])
    except FileNotFoundError:
        print(color_err("[!] tshark not found in PATH.", C), file=sys.stderr); sys.exit(1)
    addrs = set()
    for line in r.stdout.splitlines():
        for tok in line.split("\t"):
            tok = tok.strip()
            if tok.count(".") == 3:
                addrs.add(tok)
    return addrs

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

# ---------- nmap sweep ----------
def nmap_ping_sweep(target, host_timeout_s=90, max_retries=1, per_target_timeout=None):
    cmd = [NMAP_BIN, "-sn", "-n", "-T5", "--max-retries", str(max_retries),
           "--host-timeout", f"{host_timeout_s}s", target, "-oG", "-"]
    try:
        r = run(cmd, timeout=per_target_timeout, check=True)
    except subprocess.TimeoutExpired:
        return set(), "timeout(subprocess)"
    except subprocess.CalledProcessError as e:
        return set(), f"nmap_error(rc={e.returncode})"
    up = set()
    for line in r.stdout.splitlines():
        if line.startswith("Host:") and "Status: Up" in line:
            parts = line.split()
            if len(parts) >= 2 and parts[1].count(".")==3:
                up.add(parts[1])
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
    ap.add_argument("--extra-cidr", action="append", help="Add manual internal CIDRs")
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

    ip_set = set()
    ip_set |= extract_ipv4_from_ip(pcap, C)
    ip_set |= extract_ipv4_from_arp(pcap, C)
    internal_ips = keep_internal(ip_set)

    # discovered /24 targets
    discovered_targets = aggregate_subnets(internal_ips, prefix=args.prefix)

    # fixed baselines (per your playbook)
    baseline_targets = [
        "10.1.0.0/16", "10.10.0.0/16", "10.50.0.0/16", "10.100.0.0/16",
        "172.16.0.0/16", "172.132.0.0/16", "192.168.0.0/16",
    ]

    extras = [c for c in (args.extra_cidr or [])]
    ordered_targets = []
    for t in discovered_targets + extras + baseline_targets:
        if t not in ordered_targets:
            ordered_targets.append(t)

    if not ordered_targets:
        print(color_warn("[!] No targets to sweep (empty capture and no baselines?)", C))
        print(color_info(f"[+] Passive capture -> {pcap.resolve()}", C))
        print("\n" + color_ok("✔ All output files saved in:", C))
        print(f"    {outdir.resolve()}")
        return 0

    # prepare streaming network file
    network_txt = outdir / f"network_{tag}.txt"
    network_txt.write_text("")  # truncate/create
    file_lock = Lock()
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
                found = len(seen)
                active_list = list(in_progress)[:3]
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
        nonlocal total_found
        with progress_lock:
            in_progress.add(target)
            if target in pending:
                try: pending.remove(target)
                except ValueError: pass
        start = time.monotonic()
        ips, err = nmap_ping_sweep(target, host_timeout_s=args.host_timeout,
                                   max_retries=args.max_retries,
                                   per_target_timeout=args.per_target_timeout)
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
                    print(color_info(f"[+] {t}: {n} new host(s) (running total: {len(seen)})", C))
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
