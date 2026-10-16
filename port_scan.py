#!/usr/bin/env python3
"""
port_scan.py - Nmap-based port scan attack generator for Project 3 (AI-Assisted IDS/IPS with DMZ)

Runs an Nmap TCP service-detection scan against a target (default: DMZ-Web) and
writes structured JSON findings to disk, timestamped for later correlation against
Suricata's eve.json alert log.

Usage:
    python3 port_scan.py [--target 172.16.30.10] [--outdir ./results]
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import nmap
except ImportError:
    print("ERROR: python-nmap not installed. Run: pip install --break-system-packages python-nmap", file=sys.stderr)
    sys.exit(1)


def run_scan(target: str) -> dict:
    """Run an Nmap -sV -Pn scan against the target and return structured results."""
    scanner = nmap.PortScanner()

    start_time = datetime.now(timezone.utc).isoformat()

    # -sV: service/version detection
    # -Pn: skip host discovery (ping), required since the DMZ firewall policy
    #      does not explicitly permit ICMP for the test-harness policy
    scanner.scan(hosts=target, arguments="-sV -Pn")

    end_time = datetime.now(timezone.utc).isoformat()

    result = {
        "scan_type": "nmap_port_scan",
        "target": target,
        "start_time": start_time,
        "end_time": end_time,
        "command_line": scanner.command_line(),
        "hosts": [],
    }

    for host in scanner.all_hosts():
        host_info = {
            "host": host,
            "state": scanner[host].state(),
            "ports": [],
        }

        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in sorted(ports):
                port_data = scanner[host][proto][port]
                host_info["ports"].append({
                    "port": port,
                    "protocol": proto,
                    "state": port_data.get("state"),
                    "service": port_data.get("name"),
                    "product": port_data.get("product"),
                    "version": port_data.get("version"),
                    "extrainfo": port_data.get("extrainfo"),
                })

        result["hosts"].append(host_info)

    return result


def main():
    parser = argparse.ArgumentParser(description="Nmap port scan attack generator")
    parser.add_argument("--target", default="172.16.30.10", help="Target IP (default: DMZ-Web)")
    parser.add_argument("--outdir", default="./results", help="Output directory for JSON results")
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"[+] Starting Nmap scan against {args.target} ...")
    result = run_scan(args.target)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outfile = outdir / f"port_scan_{args.target}_{timestamp}.json"

    with open(outfile, "w") as f:
        json.dump(result, f, indent=2)

    print(f"[+] Scan complete. Results written to {outfile}")

    # Quick console summary
    for host in result["hosts"]:
        print(f"\nHost: {host['host']} ({host['state']})")
        for p in host["ports"]:
            print(f"  {p['port']}/{p['protocol']}  {p['state']:6s}  {p['service']:10s}  {p['product'] or ''} {p['version'] or ''}")


if __name__ == "__main__":
    main()

