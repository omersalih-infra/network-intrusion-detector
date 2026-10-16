#!/usr/bin/env python3
"""
report_generator.py - AI reporting layer for Project 3 (AI-Assisted IDS/IPS with DMZ)

Reads the deterministic alert_correlator.py output (correlation_report_*.json) and
sends it to a local Ollama instance (qwen2.5:7b) to produce a human-readable
markdown findings report: explanation, prioritization, and plain-language summary.

Per the project's core architecture principle, the LLM here is NON-AUTHORITATIVE:
it never decides whether an attack was detected -- that is fixed, deterministic
output from alert_correlator.py. The LLM only explains, prioritizes, and writes
prose around numbers it is given. The prompt explicitly instructs the model not
to alter, invent, or reinterpret the detection results.

Requires Ollama running locally with the qwen2.5:7b model pulled:
    ollama pull qwen2.5:7b

Usage:
    python3 report_generator.py [--report ./results/correlation_report_*.json]
                                  [--outdir ./results]
                                  [--ollama-url http://localhost:11434]
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from glob import glob
from pathlib import Path

try:
    import requests
except ImportError:
    print("ERROR: requests not installed. Run: pip install --break-system-packages requests", file=sys.stderr)
    sys.exit(1)


def find_latest_report(results_dir: Path) -> Path:
    """Find the most recently generated correlation_report_*.json file."""
    candidates = sorted(results_dir.glob("correlation_report_*.json"))
    if not candidates:
        print(f"ERROR: No correlation_report_*.json files found in {results_dir}", file=sys.stderr)
        sys.exit(1)
    return candidates[-1]


def build_prompt(report: dict) -> str:
    """Build a constrained prompt: the LLM explains/prioritizes, it does not
    alter or reinterpret the deterministic detection results."""

    findings_summary = []
    for f in report["findings"]:
        findings_summary.append({
            "attack_type": f["attack_type"],
            "detected": f["detected"],
            "alert_count": f["alert_count"],
            "signatures_matched": [a["signature"] for a in f["matched_alerts"]] if f["matched_alerts"] else [],
        })

    prompt = f"""You are writing the findings section of a network security evaluation report.

STRICT RULES:
- The detection results below are DETERMINISTIC and FINAL. They were computed by
  correlating timestamped attack logs against Suricata IDS alerts. You must NOT
  change, question, or reinterpret which attacks were "detected" vs "not detected" --
  treat these booleans as ground truth.
- Your job is ONLY to: (1) explain in plain language what each result means,
  (2) prioritize findings by security significance, (3) suggest plausible reasons
  for detection gaps where relevant, and (4) write a short executive summary.
- Do not invent statistics, CVEs, or details not present in the data below.
- Be concise and factual. Avoid marketing language or unwarranted alarm.

DETECTION RESULTS (ground truth, do not alter):
Total attacks tested: {report['total_attacks_tested']}
Attacks detected: {report['attacks_detected']}
Detection rate: {report['detection_rate'] * 100:.1f}%

Per-attack findings:
{json.dumps(findings_summary, indent=2)}

Write a findings report with these sections:
1. Executive Summary (2-3 sentences)
2. Detection Results by Attack Type (one short paragraph each)
3. Analysis of Detection Gaps (why the undetected attacks likely were not flagged)
4. Prioritized Recommendations (ranked by security impact)

Output in markdown."""

    return prompt


def call_ollama(prompt: str, ollama_url: str, model: str = "qwen2.5:7b") -> str:
    """Send the prompt to a local Ollama instance and return the generated text."""
    endpoint = f"{ollama_url}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_predict": 600,  # cap output length for predictable CPU-only timing
        },
    }

    print(f"[+] Sending findings to Ollama ({model}) for report generation ...")
    print("    (this may take several minutes on CPU-only inference)")

    resp = requests.post(endpoint, json=payload, timeout=900)
    resp.raise_for_status()
    data = resp.json()
    return data.get("response", "")


def validate_llm_output(markdown_text: str, report: dict) -> list:
    """Deterministic sanity check on the LLM's output.

    Scans the generated markdown for any percentage figures and flags any that
    don't match the ground-truth detection rate or a per-attack-type figure
    derivable from the correlation report. This does NOT correct the LLM's
    output -- it only flags discrepancies for human review, since the LLM
    reporting layer is explicitly non-authoritative and must never silently
    have its errors "fixed" and passed through as if they were correct.

    Returns a list of warning strings (empty if no issues found).
    """
    warnings = []

    ground_truth_pct = round(report["detection_rate"] * 100, 1)
    total = report["total_attacks_tested"]
    detected = report["attacks_detected"]

    valid_percentages = {0.0, 100.0, ground_truth_pct}
    for n in range(0, total + 1):
        if total:
            valid_percentages.add(round((n / total) * 100, 1))

    found = re.findall(r"(\d+(?:\.\d+)?)\s*%", markdown_text)
    for raw in found:
        pct = round(float(raw), 1)
        if pct not in valid_percentages:
            warnings.append(
                f"LLM output contains percentage '{raw}%' that does not match the "
                f"ground-truth detection rate ({ground_truth_pct}%, {detected}/{total}) "
                f"or any derivable per-attack-type fraction. Manual review required."
            )

    # Stricter check: "N attack(s) (M% of total)" must have M consistent with N/total
    for match in re.finditer(r"(\d+)\s*attacks?\s*\((\d+(?:\.\d+)?)\s*%\s*of\s*total\)", markdown_text, re.IGNORECASE):
        stated_n, stated_pct = int(match.group(1)), round(float(match.group(2)), 1)
        expected_pct = round((stated_n / total) * 100, 1) if total else 0.0
        if stated_pct != expected_pct:
            warnings.append(
                f"LLM output states '{stated_n} attack(s) ({stated_pct}% of total)' but "
                f"{stated_n}/{total} = {expected_pct}%, not {stated_pct}%. This is an internal "
                f"inconsistency in the LLM's own arithmetic. Manual review required."
            )

    for match in re.finditer(r"(\d+)\s*(?:out of|/)\s*(\d+)", markdown_text):
        stated_detected, stated_total = int(match.group(1)), int(match.group(2))
        if stated_total == total and stated_detected != detected:
            warnings.append(
                f"LLM output states '{stated_detected} out of {stated_total}' which "
                f"contradicts ground truth ({detected}/{total}). Manual review required."
            )

    return warnings


def main():
    parser = argparse.ArgumentParser(description="AI reporting layer (non-authoritative explanation/prioritization)")
    parser.add_argument("--report", default=None, help="Path to a specific correlation_report_*.json (default: latest in results dir)")
    parser.add_argument("--results-dir", default="./results", help="Directory to search for correlation reports")
    parser.add_argument("--outdir", default="./results", help="Output directory for the generated markdown report")
    parser.add_argument("--ollama-url", default="http://localhost:11434", help="Ollama API base URL")
    parser.add_argument("--model", default="qwen2.5:7b", help="Ollama model name")
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    report_path = Path(args.report) if args.report else find_latest_report(results_dir)
    print(f"[+] Reading correlation report: {report_path}")

    with open(report_path) as f:
        report = json.load(f)

    prompt = build_prompt(report)

    try:
        markdown_report = call_ollama(prompt, args.ollama_url, args.model)
    except requests.exceptions.ConnectionError:
        print(f"ERROR: Could not connect to Ollama at {args.ollama_url}. Is it running? (ollama serve)", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Ollama request failed: {e}", file=sys.stderr)
        sys.exit(1)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outfile = outdir / f"findings_report_{timestamp}.md"

    print("[+] Validating LLM output against deterministic ground truth ...")
    validation_warnings = validate_llm_output(markdown_report, report)

    if validation_warnings:
        print(f"\n*** VALIDATION WARNINGS ({len(validation_warnings)}) ***")
        for w in validation_warnings:
            print(f"  - {w}")
        warning_block = (
            "\n> **VALIDATION WARNINGS** — the following statements in this "
            "AI-generated section could not be automatically verified against "
            "the deterministic correlation data and require manual review "
            "before inclusion in the final report:\n"
            + "\n".join(f"> - {w}" for w in validation_warnings)
            + "\n"
        )
    else:
        print("    No discrepancies found.")
        warning_block = ""

    header = f"""# IDS/IPS Fault-Injection Evaluation -- Findings Report
*Generated: {datetime.now(timezone.utc).isoformat()}*
*Source data: {report_path.name}*
*Detection results are deterministic (computed by alert_correlator.py); the analysis below was generated by qwen2.5:7b and is explanatory/prioritization only, not authoritative for detection status.*
{warning_block}
---

"""

    with open(outfile, "w") as f:
        f.write(header + markdown_report)

    print(f"\n[+] Report written to {outfile}")
    print("\n" + "=" * 60)
    print(markdown_report)


if __name__ == "__main__":
    main()
