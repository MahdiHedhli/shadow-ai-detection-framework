#!/usr/bin/env python3
"""Create a private per-company manifest from an exact-task RMM CSV export.

Only company IDs and display names for the selected scanner task are retained.
Execution output and all unrelated task rows are read but never copied or logged.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

import build_dashboard_feed
import import_rmm_task_export


MAX_EXPORT_BYTES = import_rmm_task_export.MAX_EXPORT_BYTES
MAX_ROWS = import_rmm_task_export.MAX_ROWS
class DiscoveryError(ValueError):
    """Raised when the RMM export cannot safely produce a client manifest."""


def discover_clients(input_path: Path, task_name: str) -> list[dict[str, str]]:
    source = build_dashboard_feed.outside_public_repo(input_path, "RMM source export")
    if source.is_symlink():
        raise DiscoveryError("RMM source export must not be a symbolic link")
    if not task_name.strip() or task_name != task_name.strip() or task_name[:1] in "=+-@":
        raise DiscoveryError("task name must be a non-empty exact name and cannot begin with a spreadsheet formula prefix")
    try:
        if source.stat().st_size > MAX_EXPORT_BYTES:
            raise DiscoveryError("RMM source export exceeds the 512 MiB safety limit")
    except OSError as exc:
        raise DiscoveryError(f"could not inspect RMM source export: {exc}") from exc

    companies: dict[str, str] = {}
    try:
        with source.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or len(reader.fieldnames) != len(set(reader.fieldnames)):
                raise DiscoveryError("RMM source CSV must have one header for each column")
            required = {"company_unique_id", "company_name", "task_name"}
            missing = required - set(reader.fieldnames)
            if missing:
                raise DiscoveryError(f"RMM source CSV is missing required columns: {', '.join(sorted(missing))}")
            for row_number, row in enumerate(reader, start=2):
                if row_number - 1 > MAX_ROWS:
                    raise DiscoveryError("RMM source export exceeds the 10,000-row safety limit")
                if str(row.get("task_name") or "").strip() != task_name:
                    continue
                company_id = str(row.get("company_unique_id") or "").strip()
                company_name = str(row.get("company_name") or "").strip()
                if not build_dashboard_feed.valid_rmm_company_id(company_id):
                    raise DiscoveryError(f"selected task row {row_number} has an invalid company ID")
                if not company_name or len(company_name) > 120:
                    raise DiscoveryError(f"selected task row {row_number} has a missing or oversized company name")
                existing = companies.get(company_id)
                if existing is not None and existing != company_name:
                    raise DiscoveryError(f"selected task rows disagree on a company name at row {row_number}")
                companies[company_id] = company_name
    except (OSError, csv.Error, UnicodeDecodeError) as exc:
        raise DiscoveryError(f"could not read RMM source export: {exc}") from exc
    if not companies:
        raise DiscoveryError("source export contains no rows for the exact scanner task")
    labels = [name.casefold() for name in companies.values()]
    if len(labels) != len(set(labels)):
        raise DiscoveryError("company names are not unique; create a reviewed manifest to resolve client aliases")

    clients = []
    for company_id, company_name in sorted(companies.items(), key=lambda pair: pair[1].casefold()):
        digest = hashlib.sha256(company_id.encode("utf-8")).hexdigest()[:16]
        clients.append({
            "client_id": f"rmm-{digest}",
            "client_label": company_name,
            "observations": f"observations/{digest}",
            "rmm_company_unique_id": company_id,
        })
    return clients


def write_manifest(input_path: Path, task_name: str, output_path: Path) -> int:
    destination = build_dashboard_feed.outside_public_repo(output_path, "private client manifest")
    if output_path.is_symlink() or destination.exists():
        raise DiscoveryError("manifest output must be a new, non-symbolic-link file")
    clients = discover_clients(input_path, task_name)
    payload = json.dumps({"schema_version": "1.0", "clients": clients}, ensure_ascii=False, indent=2) + "\n"
    try:
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix" and destination.parent.stat().st_mode & 0o077:
            raise DiscoveryError("manifest directory must not grant group or other access (expected mode 0700 or stricter)")
        descriptor, temporary = tempfile.mkstemp(prefix=".shadow-ai-manifest-", suffix=".tmp", dir=destination.parent)
        temporary_path = Path(temporary)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary_path, destination)
            except FileExistsError as exc:
                raise DiscoveryError("manifest output appeared during creation; no file was replaced") from exc
        finally:
            temporary_path.unlink(missing_ok=True)
    except OSError as exc:
        raise DiscoveryError(f"could not write private client manifest: {exc}") from exc
    return len(clients)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="BrightGauge/RMM CSV source; left unchanged")
    parser.add_argument("--task-name", required=True, help="exact scanner task name")
    parser.add_argument("--output", required=True, type=Path, help="new private manifest path outside this repository")
    args = parser.parse_args(argv)
    try:
        count = write_manifest(args.input, args.task_name, args.output)
    except (DiscoveryError, import_rmm_task_export.ImportError, build_dashboard_feed.FeedError, OSError) as exc:
        print(f"Could not create private RMM client manifest: {exc}", file=sys.stderr)
        return 1
    print(f"Created a private manifest for {count} companies represented in the exact scanner task.")
    print("Only company names and IDs were retained; execution output and unrelated task rows were not copied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
