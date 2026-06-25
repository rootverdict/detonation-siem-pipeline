#!/usr/bin/env python3
"""
push_to_misp.py — Push IOCs extracted by extract_iocs.py into MISP.

Features:
  - Deconfliction: searches MISP before creating to avoid duplicate events/attributes
  - 30-day expiry: sets to_ids=True and tags each attribute with tlp:amber
  - Maps rule_id → MISP event title for clean event naming
  - Accepts IOC JSON file as input (output of extract_iocs.py)

Usage:
  python3 push_to_misp.py --input iocs.json
  python3 push_to_misp.py --input iocs.json --dry-run
"""

import argparse
import json
import sys
from datetime import datetime, timedelta

from pymisp import MISPEvent, MISPAttribute, PyMISP

# ─── Configuration ────────────────────────────────────────────────────────────
MISP_URL      = "https://192.168.100.6:8443"
MISP_KEY      = "05IzBsR0cG3p8YmX6t41TrSZQBpGUCMHyOzUCqhp"   # replace with actual key
MISP_VERIFSSL = False                  # self-signed cert in lab

# Days until IOC expires (attribute timestamp + this = expiry tag)
IOC_EXPIRY_DAYS = 30

# Map Wazuh rule IDs to human-readable MISP event titles
RULE_EVENT_MAP = {
    "100001": "T1059.001 - PowerShell Encoded Command Execution",
    "100002": "T1053.005 - Scheduled Task Creation via schtasks.exe",
    "100003": "T1071.001 - C2 Domain DNS Beacon",
}

# Map IOC field names to MISP attribute types
MISP_TYPE_MAP = {
    "sha256":      "sha256",
    "ip":          "ip-dst",
    "domain":      "domain",
    "image":       "filename",
    "commandLine": "text",
}
# ──────────────────────────────────────────────────────────────────────────────


def connect_misp() -> PyMISP:
    """Establish authenticated MISP connection."""
    try:
        misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFSSL)
        print("[+] Connected to MISP")
        return misp
    except Exception as e:
        print(f"[-] MISP connection failed: {e}")
        sys.exit(1)


def event_exists(misp: PyMISP, title: str) -> int | None:
    """
    Deconfliction check — search MISP for an existing event with this title.
    Returns event ID if found, None otherwise.
    """
    result = misp.search_index(eventinfo=title)
    if result:
        event_id = result[0]["id"]
        print(f"[~] Deconfliction hit: event '{title}' already exists (ID {event_id})")
        return int(event_id)
    return None


def attribute_exists(misp: PyMISP, event_id: int, value: str) -> bool:
    """Check if an attribute value already exists in a given event."""
    result = misp.search(eventid=event_id, value=value, pythonify=True)
    return len(result) > 0


def build_event(title: str, mitre_ids: list[str]) -> MISPEvent:
    """
    Create a new MISPEvent object with standard lab metadata.
    Tags: tlp:amber, ATT&CK technique IDs
    """
    event = MISPEvent()
    event.info          = title
    event.distribution  = 0          # Your organisation only
    event.threat_level_id = 2        # Medium
    event.analysis      = 1          # Ongoing

    # Tag with TLP and ATT&CK technique
    event.add_tag("tlp:amber")
    event.add_tag("SOC-Lab")
    for technique in mitre_ids:
        event.add_tag(f"misp-galaxy:mitre-attack-pattern={technique}")

    return event


def push_ioc_record(misp: PyMISP, record: dict, dry_run: bool) -> None:
    """
    Process one IOC record from extract_iocs.py output.
    Creates or reuses a MISP event, then adds each IOC as an attribute.
    """
    rule_id   = record.get("rule_id", "unknown")
    mitre_ids = record.get("mitre", [])
    iocs      = record.get("iocs", {})
    agent     = record.get("agent", "unknown")

    # Resolve event title from rule ID
    title = RULE_EVENT_MAP.get(rule_id, f"Wazuh Rule {rule_id} - {record.get('rule_desc', '')}")

    print(f"\n[*] Processing rule {rule_id} → event: '{title}'")

    if dry_run:
        print(f"    [DRY-RUN] Would create/update event: {title}")
        for ioc_type, values in iocs.items():
            if not isinstance(values, list):
                values = [values]
            for v in values:
                misp_type = MISP_TYPE_MAP.get(ioc_type, "text")
                print(f"    [DRY-RUN] Would add attribute: {misp_type} = {v}")
        return

    # Deconfliction — reuse existing event or create new one
    event_id = event_exists(misp, title)
    if event_id is None:
        event = build_event(title, mitre_ids)
        created = misp.add_event(event, pythonify=True)
        event_id = int(created.id)
        print(f"[+] Created new MISP event ID {event_id}")
    else:
        print(f"[~] Reusing existing event ID {event_id}")

    # Calculate expiry date string (used as comment for traceability)
    expiry_date = (datetime.utcnow() + timedelta(days=IOC_EXPIRY_DAYS)).strftime("%Y-%m-%d")
    comment     = f"Source: Wazuh agent {agent} | Expires: {expiry_date}"

    # Add each IOC as a MISP attribute
    added = 0
    for ioc_type, values in iocs.items():
        # Normalise to list — some fields are strings, some are lists
        if not isinstance(values, list):
            values = [values]

        misp_type = MISP_TYPE_MAP.get(ioc_type, "text")

        for value in values:
            if not value:
                continue

            # Deconflict at attribute level — skip if already present
            if attribute_exists(misp, event_id, value):
                print(f"    [~] Attribute already exists, skipping: {value[:60]}")
                continue

            attr = MISPAttribute()
            attr.type    = misp_type
            attr.value   = value
            attr.to_ids  = misp_type in ("sha256", "ip-dst", "domain")  # flag for IDS export
            attr.comment = comment

            misp.add_attribute(event_id, attr)
            print(f"    [+] Added {misp_type}: {value[:80]}")
            added += 1

    print(f"[+] Event {event_id} updated — {added} new attributes added")


def main():
    parser = argparse.ArgumentParser(description="Push Wazuh IOCs into MISP")
    parser.add_argument("--input",   required=True, help="Path to extract_iocs.py JSON output")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without pushing to MISP")
    args = parser.parse_args()

    # Load IOC records
    try:
        with open(args.input) as f:
            records = json.load(f)
        print(f"[+] Loaded {len(records)} IOC records from {args.input}")
    except Exception as e:
        print(f"[-] Failed to load input file: {e}")
        sys.exit(1)

    # Connect (skip in dry-run to allow offline testing)
    misp = None if args.dry_run else connect_misp()

    # Process each record
    for record in records:
        push_ioc_record(misp, record, dry_run=args.dry_run)

    print("\n[✓] push_to_misp.py complete")


if __name__ == "__main__":
    main()
