#!/usr/bin/env python3
"""Synchronize an ip/port inventory through the authenticated trade-access API.

This compatibility entry point retains the previous input/audit defaults.
All queries and mutations use the API so the server owns multi-firewall
orchestration, desired state, locking and task recovery. Dry-run is the default.
Use --execute to apply changes and --token-file or TRADE_ACCESS_API_TOKEN
for authentication. Existing audits from the former direct-runner script are
not compatible; select a new --audit-output file for the first API run.
"""

import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.sync_firewall_inventory_api import SyncError, main as sync_inventory_main


DEFAULT_INPUT = PROJECT_ROOT / "最新ip_ports.json"
DEFAULT_AUDIT = PROJECT_ROOT / "firewall_alignment_audit.json"


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    return sync_inventory_main([
        "--input", str(DEFAULT_INPUT),
        "--audit-output", str(DEFAULT_AUDIT),
        "--api-base-url", os.environ.get("TRADE_ACCESS_API_BASE_URL", "http://127.0.0.1:8000"),
        *arguments,
    ])


if __name__ == "__main__":
    try:
        main()
    except (SyncError, ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
