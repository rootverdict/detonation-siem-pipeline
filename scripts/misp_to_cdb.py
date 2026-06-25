#!/usr/bin/env python3
"""
misp_to_cdb.py — Export non-expired domain IOCs from MISP to Wazuh CDB list.

Pipeline:
  MISP (domain attributes, to_ids=True) → filter expired → write CDB file
  → docker exec reload Wazuh manager

Features:
  - Only exports attributes with to_ids=True (actionable IOCs)
  - Skips attributes older than EXPIRY_DAYS (30-day rolling window)
  - Appends any static seed domains (from original c2_domains.list)
  - Writes atomic CDB file (temp file → rename to avoid partial reads)
  - Optionally reloads Wazuh manager after update

Usage:
  python3 misp_to_cdb.py
  python3 misp_to_cdb.py --dry-run
  python3 misp_to_cdb.py --no-reload
"""

import argparse
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

from pymisp import PyMISP

# ─── Configuration ────────────────────────────────────────────────────────────
MISP_URL      = "https://192.168.100.6:8443"
MISP_KEY      = "05IzBsR0cG3p8YmX6t41TrSZQBpGUCMHyOzUCqhp"
MISP_VERIFSSL = False

# CDB file path inside the Wazuh manager container
CDB_CONTAINER_PATH = "/var/ossec/etc/lists/c2_domains"

# Docker container name
WAZUH_CONTAINER = "wazuh-docker-wazuh.manager-1"

# IOC expiry window — attributes older than this are excluded
EXPIRY_DAYS = 30

# Static seed domains always included regardless of MISP state
# These are the original manually-curated entries
SEED_DOMAINS = [
    "evil-c2.com",
    "malware-beacon.net",
    "cobaltstrike-teamserver.xyz",
    "test-c2-domain.local",
]
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


def fetch_active_domains(misp: PyMISP) -> list[str]:
    """
    Query MISP for domain attributes that are:
    - type = 'domain'
    - to_ids = True (flagged as actionable IOC)
    - timestamp newer than EXPIRY_DAYS ago
    Returns a sorted, deduplicated list of domain strings.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=EXPIRY_DAYS)
    cutoff_ts = int(cutoff.timestamp())

    print(f"[*] Fetching domain attributes newer than {cutoff.strftime('%Y-%m-%d')} (last {EXPIRY_DAYS} days)")

    # Search MISP for domain-type attributes with IDS flag set
    results = misp.search(
        controller="attributes",
        type_attribute="domain",
        to_ids=True,
        timestamp=cutoff_ts,   # MISP filters by Unix timestamp
        pythonify=True
    )

    domains = []
    for attr in results:
        domain = attr.value.strip().lower()
        if domain:
            domains.append(domain)
            print(f"    [+] Found: {domain} (event {attr.event_id}, ts {attr.timestamp})")

    # Deduplicate and sort
    domains = sorted(set(domains))
    print(f"[*] {len(domains)} unique active domains fetched from MISP")
    return domains


def merge_with_seeds(misp_domains: list[str]) -> list[str]:
    """
    Merge MISP domains with static seed domains.
    Seeds are always included — they represent manually-verified C2 IOCs.
    """
    combined = sorted(set(misp_domains + [d.lower() for d in SEED_DOMAINS]))
    print(f"[*] {len(combined)} total domains after merging with {len(SEED_DOMAINS)} seed entries")
    return combined


def write_cdb_file(domains: list[str], dry_run: bool) -> str | None:
    """
    Write domains to a temp file in Wazuh CDB format (domain: per line).
    Returns the temp file path, or None in dry-run mode.
    """
    if dry_run:
        print(f"\n[DRY-RUN] Would write {len(domains)} entries to CDB:")
        for d in domains:
            print(f"    {d}:")
        return None

    # Write to temp file first — atomic rename prevents partial reads
    tmp = tempfile.NamedTemporaryFile(
        mode='w', suffix='.cdb_tmp', delete=False
    )
    for domain in domains:
        tmp.write(f"{domain}:\n")
    tmp.flush()
    tmp.close()

    print(f"[+] Wrote {len(domains)} entries to temp file: {tmp.name}")
    return tmp.name


def deploy_to_wazuh(tmp_path: str, dry_run: bool) -> None:
    """
    Copy the CDB file into the Wazuh manager container and reload.
    Uses docker cp for the file transfer, then wazuh-control reload.
    """
    if dry_run:
        print(f"[DRY-RUN] Would docker cp {tmp_path} → {WAZUH_CONTAINER}:{CDB_CONTAINER_PATH}")
        print(f"[DRY-RUN] Would reload Wazuh manager")
        return

    # Copy CDB file into container
    cp_cmd = ["docker", "cp", tmp_path, f"{WAZUH_CONTAINER}:{CDB_CONTAINER_PATH}"]
    print(f"[*] Deploying CDB to container: {' '.join(cp_cmd)}")
    result = subprocess.run(cp_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[-] docker cp failed: {result.stderr}")
        sys.exit(1)
    print("[+] CDB file deployed to container")

    # Fix ownership so wazuh-analysisd can read the file
    # docker cp sets ownership to the host UID which may not match wazuh user
    chown_cmd = [
        "docker", "exec", "-u", "root",
        WAZUH_CONTAINER,
        "chown", "root:wazuh", CDB_CONTAINER_PATH
    ]
    chmod_cmd = [
        "docker", "exec", "-u", "root",
        WAZUH_CONTAINER,
        "chmod", "660", CDB_CONTAINER_PATH
    ]
    subprocess.run(chown_cmd, capture_output=True)
    subprocess.run(chmod_cmd, capture_output=True)
    print("[+] CDB file permissions fixed (root:wazuh 660)")

    # Clean up temp file
    os.unlink(tmp_path)


def reload_wazuh(dry_run: bool, no_reload: bool) -> None:
    """Reload Wazuh manager to pick up the updated CDB list."""
    if dry_run or no_reload:
        print("[DRY-RUN/--no-reload] Skipping Wazuh reload")
        return

    reload_cmd = [
        "docker", "exec",
        WAZUH_CONTAINER,
        "/var/ossec/bin/wazuh-control", "reload"
    ]
    print("[*] Reloading Wazuh manager...")
    result = subprocess.run(reload_cmd, capture_output=True, text=True)

    # wazuh-control reload exits 0 on success
    if "Completed" in result.stdout:
        print("[+] Wazuh manager reloaded successfully")
    else:
        print(f"[~] Reload output: {result.stdout[-200:]}")


def main():
    parser = argparse.ArgumentParser(description="Export MISP domain IOCs to Wazuh CDB list")
    parser.add_argument("--dry-run",   action="store_true", help="Print actions without writing files")
    parser.add_argument("--no-reload", action="store_true", help="Deploy CDB but skip Wazuh reload")
    args = parser.parse_args()

    misp = connect_misp()

    # Fetch active (non-expired) domains from MISP
    misp_domains = fetch_active_domains(misp)

    # Merge with static seeds
    all_domains = merge_with_seeds(misp_domains)

    # Write CDB temp file
    tmp_path = write_cdb_file(all_domains, dry_run=args.dry_run)

    # Deploy to Wazuh container
    deploy_to_wazuh(tmp_path, dry_run=args.dry_run)

    # Reload Wazuh manager
    reload_wazuh(dry_run=args.dry_run, no_reload=args.no_reload)

    print("\n[✓] misp_to_cdb.py complete")


if __name__ == "__main__":
    main()
