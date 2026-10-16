#!/usr/bin/env python3
"""
alert_correlator.py - Deterministic alert parser/correlator for Project 3
(AI-Assisted IDS/IPS with DMZ)

Reads Suricata's eve.json (plus any rotated .gz logs), reads the structured
JSON output from the attack generator scripts (port_scan.py, ssh_bruteforce.py,
web_attack.py), and correlates each attack's timestamp window against Suricata
alerts to produce a deterministic detection-rate report.

This is the deterministic detection/correlation layer -- no LLM involved.
Per the project's core architecture principle, the LLM (in report_generator.py)
only ever explains and prioritizes these findings; it does not decide what
counts as detected.

Usage:
    python3 alert_correlator.py [--eve-log ./suricata_eve.json]
                                  [--eve-log-rotated ./suricata_eve.json.1.gz]
                                  [--results-dir ./results]
                                  [--outdir ./results]
"""

import argparse
import gzip
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def load_eve_alerts(eve_path: Path) -> list:
    """Load all alert-type events from a plaintext eve.json file."""
    alerts = []
    if not eve_path.exists():
        return alerts
    with open(eve_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert":
                alerts.append(event)
    return alerts


def load_eve_alerts_gz(eve_gz_path: Path) -> list:
    """Load all alert-type events from a gzipped eve.json.N.gz file."""
    alerts = []
    if not eve_gz_path.exists():
        return alerts
    with gzip.open(eve_gz_path, "rt") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert":
                alerts.append(event)
    return alerts


def parse_iso(ts: str) -> datetime:
    """Parse an ISO8601 timestamp (handles both +00:00 and +0200 style offsets)."""
    ts = ts.replace("Z", "+00:00")
    # Suricata timestamps look like 2026-07-19T00:11:56.419736+0200 (no colon in offset)
    if len(ts) >= 5 and ts[-5] in ("+", "-") and ts[-3] != ":":
        ts = ts[:-2] + ":" + ts[-2:]
    return datetime.fromisoformat(ts)


def load_attack_results(results_dir: Path) -> list:
    """Load all attack-generator JSON result files (port_scan_*, ssh_bruteforce_*, web_attack_*)."""
    attacks = []
    for pattern in ("port_scan_*.json", "ssh_bruteforce_*.json", "web_attack_*.json"):
        for path in sorted(results_dir.glob(pattern)):
            with open(path) as f:
                data = json.load(f)
            data["_source_file"] = path.name
            attacks.append(data)
    return attacks


def correlate(attacks: list, alerts: list, buffer_seconds: int = 15) -> list:
    """For each attack, find alerts whose timestamp falls within the attack's time window,
    expanded by buffer_seconds on each side to absorb clock skew between hosts and
    measurement-boundary effects (e.g. the last HTTP request's alert logging slightly
    after the Python-measured end_time)."""
    from datetime import timedelta
    findings = []

    for attack in attacks:
        start = parse_iso(attack["start_time"]) - timedelta(seconds=buffer_seconds)
        end = parse_iso(attack["end_time"]) + timedelta(seconds=buffer_seconds)
        target = attack.get("target")

        matched_alerts = []
        for alert in alerts:
            alert_ts = parse_iso(alert["timestamp"])
            alert_dest = alert.get("dest_ip")
            # match on time window AND destination IP (the DMZ-Web target)
            if start <= alert_ts <= end and alert_dest == target:
                matched_alerts.append({
                    "timestamp": alert["timestamp"],
                    "signature": alert.get("alert", {}).get("signature"),
                    "signature_id": alert.get("alert", {}).get("signature_id"),
                    "severity": alert.get("alert", {}).get("severity"),
                    "dest_port": alert.get("dest_port"),
                })

        findings.append({
            "attack_type": attack["scan_type"],
            "source_file": attack["_source_file"],
            "target": target,
            "start_time": attack["start_time"],
            "end_time": attack["end_time"],
            "detected": len(matched_alerts) > 0,
            "alert_count": len(matched_alerts),
            "matched_alerts": matched_alerts,
        })

    return findings


def main():
    parser = argparse.ArgumentParser(description="Deterministic alert parser/correlator")
    parser.add_argument("--eve-log", default="./suricata_eve.json", help="Path to current eve.json")
    parser.add_argument("--eve-log-rotated", default="./suricata_eve.json.1.gz", help="Path to rotated eve.json.1.gz (optional)")
    parser.add_argument("--results-dir", default="./results", help="Directory containing attack result JSON files")
    parser.add_argument("--outdir", default="./results", help="Output directory for the correlation report")
    parser.add_argument("--buffer-seconds", type=int, default=15, help="Seconds of slack added to each attack window to absorb clock skew (default: 15)")
    args = parser.parse_args()

    eve_path = Path(args.eve_log)
    eve_gz_path = Path(args.eve_log_rotated)
    results_dir = Path(args.results_dir)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"[+] Loading Suricata alerts from {eve_path} ...")
    alerts = load_eve_alerts(eve_path)
    print(f"    {len(alerts)} alerts found in current log")

    print(f"[+] Loading Suricata alerts from {eve_gz_path} (if present) ...")
    alerts_rotated = load_eve_alerts_gz(eve_gz_path)
    print(f"    {len(alerts_rotated)} alerts found in rotated log")

    all_alerts = alerts + alerts_rotated
    print(f"[+] Total alerts loaded: {len(all_alerts)}")

    print(f"[+] Loading attack results from {results_dir} ...")
    attacks = load_attack_results(results_dir)
    print(f"    {len(attacks)} attack result files found")

    if not attacks:
        print("ERROR: No attack result files found. Run port_scan.py / ssh_bruteforce.py / web_attack.py first.", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Correlating attacks against alerts (buffer: +/-{args.buffer_seconds}s) ...")
    findings = correlate(attacks, all_alerts, buffer_seconds=args.buffer_seconds)

    detected_count = sum(1 for f in findings if f["detected"])
    total_count = len(findings)
    detection_rate = detected_count / total_count if total_count else 0.0

    report = {
        "report_type": "fault_injection_evaluation",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "correlation_buffer_seconds": args.buffer_seconds,
        "total_attacks_tested": total_count,
        "attacks_detected": detected_count,
        "detection_rate": round(detection_rate, 3),
        "findings": findings,
    }

    outfile = outdir / f"correlation_report_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    with open(outfile, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[+] Correlation report written to {outfile}")
    print(f"\n=== SUMMARY ===")
    print(f"Detection rate: {detected_count}/{total_count} ({detection_rate*100:.1f}%)")
    print()
    for finding in findings:
        status = "DETECTED" if finding["detected"] else "NOT DETECTED"
        print(f"  [{status:13s}] {finding['attack_type']:30s} ({finding['source_file']}) - {finding['alert_count']} alert(s)")


if __name__ == "__main__":
    main()
