#!/usr/bin/env python3
"""TCP connect port scanner. For hosts you own or are authorised to test."""

import argparse
import ipaddress
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_THREADS = 500
MAX_PORT = 65535


def parse_ports(spec: str) -> list[int]:
    """Turn '22,80,100-200' into a sorted list of unique ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            raise ValueError("empty port entry")
        if "-" in part:
            start_s, _, end_s = part.partition("-")
            start, end = int(start_s), int(end_s)
            if start > end:
                raise ValueError(f"bad range '{part}' (start > end)")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= MAX_PORT]
    if bad:
        raise ValueError(f"port out of range 1-{MAX_PORT}: {min(bad)}")
    return sorted(ports)


def is_local_or_private(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_loopback or addr.is_private


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_port(ip: str, port: int, timeout: float, grab_banner: bool) -> dict:
    """Return {'port', 'state', 'banner'}. State: open / closed / filtered."""
    result = {"port": port, "state": "filtered", "banner": ""}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            result["state"] = "open"
            if grab_banner:
                try:
                    result["banner"] = s.recv(128).decode(errors="replace").strip()
                except OSError:
                    pass  # many services stay silent until spoken to
    except ConnectionRefusedError:
        result["state"] = "closed"
    except (socket.timeout, TimeoutError):
        result["state"] = "filtered"
    except OSError:
        result["state"] = "filtered"  # unreachable, no route, etc.
    return result


def run_scan(ip, ports, timeout, threads, grab_banner):
    results = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(scan_port, ip, p, timeout, grab_banner) for p in ports]
        try:
            for f in as_completed(futures):
                results.append(f.result())
        except KeyboardInterrupt:
            for f in futures:
                f.cancel()
            print("\nInterrupted; showing partial results.", file=sys.stderr)
    return sorted(results, key=lambda r: r["port"])


def build_parser():
    p = argparse.ArgumentParser(
        description="TCP connect port scanner. Only scan hosts you own or have "
        "written permission to test."
    )
    p.add_argument("target", help="hostname or IPv4 address")
    p.add_argument("-p", "--ports", default="1-1024",
                   help="e.g. 22,80,443 or 1-1024 (default: 1-1024)")
    p.add_argument("-t", "--timeout", type=float, default=1.0,
                   help="seconds per connection attempt (default: 1.0)")
    p.add_argument("-w", "--threads", type=int, default=100,
                   help=f"concurrent workers (default: 100, max {MAX_THREADS})")
    p.add_argument("-b", "--banner", action="store_true",
                   help="try to read a banner from open ports")
    p.add_argument("-o", "--output", help="write results to this JSON file")
    p.add_argument("--show-closed", action="store_true",
                   help="also list closed/filtered ports")
    p.add_argument("--authorized", action="store_true",
                   help="confirm you have permission to scan a non-local target")
    return p


def main() -> int:
    args = build_parser().parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        msg = "not a number (use e.g. 22,80 or 1-1024)" if "invalid literal" in str(e) else str(e)
        print(f"error: invalid ports: {msg}", file=sys.stderr)
        return 2
    if args.timeout <= 0:
        print("error: timeout must be positive", file=sys.stderr)
        return 2
    if not 1 <= args.threads <= MAX_THREADS:
        print(f"error: threads must be 1-{MAX_THREADS}", file=sys.stderr)
        return 2

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"error: cannot resolve '{args.target}'", file=sys.stderr)
        return 2

    if not is_local_or_private(ip) and not args.authorized:
        print(f"{args.target} ({ip}) is not a local/private address.\n"
              "Only scan systems you own or have written permission to test.\n"
              "Re-run with --authorized to confirm.", file=sys.stderr)
        return 3

    print(f"Scanning {args.target} ({ip}): {len(ports)} ports, "
          f"{args.threads} threads, {args.timeout}s timeout")
    start = time.time()
    results = run_scan(ip, ports, args.timeout, args.threads, args.banner)
    elapsed = time.time() - start

    shown = results if args.show_closed else [r for r in results if r["state"] == "open"]
    print(f"\n{'PORT':<8}{'STATE':<10}{'SERVICE':<14}BANNER")
    for r in shown:
        print(f"{r['port']:<8}{r['state']:<10}{service_name(r['port']):<14}{r['banner']}")
    if not shown:
        print("(no open ports found)")

    counts = {s: sum(r["state"] == s for r in results)
              for s in ("open", "closed", "filtered")}
    print(f"\nDone in {elapsed:.2f}s: {counts['open']} open, "
          f"{counts['closed']} closed, {counts['filtered']} filtered")

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"target": args.target, "ip": ip,
                       "seconds": round(elapsed, 2), "results": results}, f, indent=2)
        print(f"Saved to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
