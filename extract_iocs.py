#!/usr/bin/env python3
"""
extract_iocs.py — Wazuh alert IOC extractor
Repo:   rootverdict/detonation-siem-pipeline
Author: rootverdict
Date:   2026-06-24

Reads Wazuh alerts.json, extracts IOCs from matching rule IDs,
and outputs structured JSON ready for MISP ingestion (W2).

IOC types extracted:
  - SHA256 hashes      (Sysmon EID 1 Hashes field)
  - IPv4 addresses     (srcip / dstip fields)
  - Domains            (QueryName from Sysmon EID 22)
  - Process image paths (win.eventdata.image)
  - Command lines      (win.eventdata.commandLine)

Usage:
  python3 extract_iocs.py --alerts /path/to/alerts.json --rules 100001,100002
  python3 extract_iocs.py --alerts /path/to/alerts.json --rules all
  python3 extract_iocs.py --alerts /path/to/alerts.json --rules 100001 --out iocs.json
"""

import json
import re
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path


# ── IOC regex patterns ──────────────────────────────────────────────────────
# Matches standard IPv4 addresses, excluding loopback and link-local
RE_IPV4 = re.compile(
    r"(?!127\.|169\.254\.|0\.0\.0\.0)(\d{1,3}\.){3}\d{1,3}"
)

# Matches SHA256 hashes (64 hex chars), case-insensitive
RE_SHA256 = re.compile(r"[a-fA-F0-9]{64}")

# Matches domains with common TLDs — excludes bare hostnames
RE_DOMAIN = re.compile(
    r"(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|gov|edu|ru|cn|de|co|uk|xyz|top|info)",
    re.IGNORECASE,
)


def extract_from_text(text: str) -> dict:
    """Run all regex patterns against a text blob and return matched IOCs."""
    return {
        "ipv4":   list(set(RE_IPV4.findall(text))),
        "sha256": list(set(RE_SHA256.findall(text))),
        "domain": list(set(RE_DOMAIN.findall(text))),
    }


def parse_alert(alert: dict) -> dict:
    """
    Extract structured IOCs from a single Wazuh alert dict.
    Walks win.eventdata, data.srcip, data.dstip, and the raw full_log.
    Returns a flat IOC dict with source metadata attached.
    """
    iocs = {
        "ipv4":        [],
        "sha256":      [],
        "domain":      [],
        "image":       None,
        "commandLine": None,
    }

    # Pull win.eventdata fields if present
    eventdata = alert.get("data", {}).get("win", {}).get("eventdata", {})

    # Image path — direct extraction
    if eventdata.get("image"):
        iocs["image"] = eventdata["image"]

    # CommandLine — direct extraction
    if eventdata.get("commandLine"):
        iocs["commandLine"] = eventdata["commandLine"]

    # Hashes field from Sysmon (format: "SHA256=aabbcc...,MD5=...")
    hashes_raw = eventdata.get("hashes", "")
    for part in hashes_raw.split(","):
        if part.upper().startswith("SHA256="):
            iocs["sha256"].append(part.split("=", 1)[1].strip())

    # srcip / dstip from top-level data
    for field in ("srcip", "dstip"):
        val = alert.get("data", {}).get(field, "")
        if val and RE_IPV4.match(val):
            iocs["ipv4"].append(val)

    # DNS query name from Sysmon EID 22
    query_name = eventdata.get("queryName", "")
    if query_name and RE_DOMAIN.search(query_name):
        iocs["domain"].append(query_name)

    # Fallback — regex scan the full_log blob for anything missed above
    full_log = alert.get("full_log", "")
    if full_log:
        blob_iocs = extract_from_text(full_log)
        for key in ("ipv4", "sha256", "domain"):
            iocs[key] = list(set(iocs[key] + blob_iocs[key]))

    # Remove empty lists/None values for clean output
    return {k: v for k, v in iocs.items() if v}


def build_output_record(alert: dict, iocs: dict) -> dict:
    """Combine alert metadata with extracted IOCs into one output record."""
    return {
        "timestamp":   alert.get("timestamp", ""),
        "rule_id":     alert.get("rule", {}).get("id", ""),
        "rule_desc":   alert.get("rule", {}).get("description", ""),
        "agent":       alert.get("agent", {}).get("name", ""),
        "mitre":       alert.get("rule", {}).get("mitre", {}).get("id", []),
        "iocs":        iocs,
        "extracted_at": datetime.now(timezone.utc).isoformat(),
    }


def load_alerts(path: str, rule_filter: list) -> list:
    """
    Stream-parse alerts.json (one JSON object per line).
    Filter by rule IDs if provided; 'all' bypasses the filter.
    Returns list of matching alert dicts.
    """
    results = []
    path_obj = Path(path)

    if not path_obj.exists():
        print(f"[ERROR] alerts.json not found at: {path}", file=sys.stderr)
        sys.exit(1)

    with open(path_obj, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError as e:
                # Skip malformed lines — alerts.json can have partial writes
                print(f"[WARN] Line {lineno}: JSON parse error — {e}", file=sys.stderr)
                continue

            rule_id = alert.get("rule", {}).get("id", "")

            # Apply rule filter
            if rule_filter != ["all"] and rule_id not in rule_filter:
                continue

            iocs = parse_alert(alert)

            # Only include alerts that yielded at least one IOC
            if iocs:
                results.append(build_output_record(alert, iocs))

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Extract IOCs from Wazuh alerts.json for MISP ingestion"
    )
    parser.add_argument(
        "--alerts",
        default="/var/ossec/logs/alerts/alerts.json",
        help="Path to Wazuh alerts.json (default: /var/ossec/logs/alerts/alerts.json)",
    )
    parser.add_argument(
        "--rules",
        default="100001,100002",
        help="Comma-separated rule IDs to filter, or 'all' (default: 100001,100002)",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output file path (default: print to stdout)",
    )
    args = parser.parse_args()

    rule_filter = (
        ["all"] if args.rules.strip().lower() == "all"
        else [r.strip() for r in args.rules.split(",")]
    )

    print(f"[INFO] Reading alerts from: {args.alerts}", file=sys.stderr)
    print(f"[INFO] Filtering rules: {rule_filter}", file=sys.stderr)

    records = load_alerts(args.alerts, rule_filter)

    print(f"[INFO] Extracted {len(records)} records with IOCs", file=sys.stderr)

    output = json.dumps(records, indent=2)

    if args.out:
        with open(args.out, "w") as fh:
            fh.write(output)
        print(f"[INFO] Written to: {args.out}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
