# Detonation SIEM Pipeline

SOC Detection Lab — P1: Detection Engineering

## Overview
Wazuh-based detection pipeline with custom rules, Sigma mappings, and IOC integration via MISP.

## Structure
- `rules/` — Wazuh XML detection rules mapped to MITRE ATT&CK
- `sigma/` — Sigma rules alongside every Wazuh rule
- `scripts/` — IOC ingestion, MISP integration, automation
- `docs/` — ADS (Alert Design Sheets) per detection rule

## Stack
- Wazuh 4.9.0
- MISP
- Python 3 (aryan-soc venv)

## ATT&CK Coverage
See `docs/attack-coverage.md` (added W4)
