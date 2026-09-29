#!/usr/bin/env python3
"""Validate and archive observations from a task-scoped RMM CSV export.

The CSV, client manifest, and resulting observations contain private telemetry.
This importer accepts only rows for one exact scanner task and only mapped RMM
company IDs; keep every file outside this public repository.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import build_dashboard_feed
import rmm_output
import validate_observation


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_COLUMNS = {"company_unique_id", "task_name", "execution_output"}
MAX_EXPORT_BYTES = 512 * 1024 * 1024
MAX_OBSERVATION_BYTES = 2 * 1024 * 1024
MAX_VALIDATED_BYTES = 256 * 1024 * 1024
MAX_ROWS = 10000


class ImportError(ValueError):
    """Raised when an RMM task export cannot be safely archived."""


def canonical(document: dict[str, Any]) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def parse_scanner_output(raw: str) -> dict[str, Any]:
    """Decode transport envelopes, parse legacy JSON, and validate the result."""
    decoded = rmm_output.decode_output(raw)
    try:
        document = json.loads(decoded)
    except json.JSONDecodeError as strict_error:
        normalized: list[str] = []
        in_string = False
        escaped = False
        changed = False
        for character in decoded:
            if in_string:
                normalized.append(character)
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    in_string = False
            elif character == '"':
                in_string = True
                normalized.append(character)
            elif character == ";":
                normalized.append(",")
                changed = True
            else:
                normalized.append(character)
        if not changed or in_string:
            raise strict_error
        document = json.loads("".join(normalized))
    validate_observation.validate_document(document)
    return document


def load_clients(manifest_path: Path) -> dict[str, dict[str, Any]]:
    clients = build_dashboard_feed.load_manifest(manifest_path)
    by_company_id: dict[str, dict[str, Any]] = {}
    for client in clients:
        company_id = client.get("rmm_company_unique_id")
        if company_id:
            by_company_id[company_id] = client
    if not by_company_id:
        raise ImportError("private client manifest needs rmm_company_unique_id for at least one client")
    return by_company_id


def read_export(path: Path, task_name: str, clients_by_company: dict[str, dict[str, Any]]) -> list[tuple[Path, dict[str, Any]]]:
    path = build_dashboard_feed.outside_public_repo(path, "RMM task export")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ImportError(f"could not inspect RMM task export: {exc}") from exc
    if size > MAX_EXPORT_BYTES:
        raise ImportError("RMM task export exceeds the 512 MiB safety limit")

    staged: list[tuple[Path, dict[str, Any]]] = []
    staged_ids: dict[str, tuple[str, Path]] = {}
    total_observation_bytes = 0
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or len(reader.fieldnames) != len(set(reader.fieldnames)):
                raise ImportError("RMM CSV must have one header for each column")
            missing = REQUIRED_COLUMNS - set(reader.fieldnames)
            if missing:
                raise ImportError(f"RMM CSV is missing required columns: {', '.join(sorted(missing))}")
            for row_number, row in enumerate(reader, start=2):
                if row_number - 1 > MAX_ROWS:
                    raise ImportError("RMM task export exceeds the 10,000-row safety limit")
                if str(row.get("task_name") or "").strip() != task_name:
                    raise ImportError(f"row {row_number} is not for the requested task; export only the exact scanner task")
                company_id = str(row.get("company_unique_id") or "").strip()
                client = clients_by_company.get(company_id)
                if client is None:
                    raise ImportError(f"row {row_number} has an unmapped company_unique_id")
                raw = row.get("execution_output", "")
                if not raw or len(raw.encode("utf-8")) > MAX_OBSERVATION_BYTES:
                    raise ImportError(f"row {row_number} has missing or oversized execution_output")
                try:
                    document = parse_scanner_output(raw)
                except (json.JSONDecodeError, rmm_output.RmmOutputError, validate_observation.ObservationError, TypeError, KeyError, AttributeError) as exc:
                    raise ImportError(f"row {row_number} has invalid scanner JSON: {exc}") from exc
                observation_id = document["observation_id"]
                normalized = canonical(document)
                prior = staged_ids.get(observation_id)
                if prior is not None:
                    if prior != (normalized, client["observations"]):
                        if prior[1] != client["observations"]:
                            raise ImportError(f"duplicate observation_id maps to multiple clients at row {row_number}")
                        raise ImportError(f"duplicate observation_id has conflicting content at row {row_number}")
                    continue
                staged_ids[observation_id] = (normalized, client["observations"])
                total_observation_bytes += len(normalized.encode("utf-8"))
                if total_observation_bytes > MAX_VALIDATED_BYTES:
                    raise ImportError("validated observations exceed the 256 MiB safety limit")
                staged.append((client["observations"], document))
    except (OSError, csv.Error, UnicodeDecodeError) as exc:
        raise ImportError(f"could not read RMM task export: {exc}") from exc
    if not staged:
        raise ImportError("RMM task export contains no observation rows")
    return staged


def store_observation(archive: Path, document: dict[str, Any]) -> bool:
    try:
        build_dashboard_feed.ensure_private_directory(archive.parent, "observation archive parent")
        build_dashboard_feed.ensure_private_directory(archive, "observation archive")
    except build_dashboard_feed.FeedError as exc:
        raise ImportError(f"could not prepare private observation archive: {exc}") from exc
    destination = archive / f"{document['observation_id']}.json"
    serialized = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    if destination.exists():
        if destination.is_symlink():
            raise ImportError("existing observation path is a symbolic link")
        try:
            existing = json.loads(destination.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ImportError("existing observation file is unreadable; leaving it unchanged") from exc
        if canonical(existing) == canonical(document):
            return False
        raise ImportError("observation_id already exists with different content; leaving archive unchanged")

    descriptor, temporary = tempfile.mkstemp(prefix=".shadow-ai-import-", suffix=".tmp", dir=archive)
    staged = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(staged, destination)
        except FileExistsError:
            # A concurrent importer may have committed the same observation.
            existing = json.loads(destination.read_text(encoding="utf-8"))
            if canonical(existing) == canonical(document):
                return False
            raise ImportError("observation_id appeared with different content; archive was not replaced")
    finally:
        staged.unlink(missing_ok=True)
    return True


def import_export(input_path: Path, manifest_path: Path, task_name: str) -> tuple[int, int]:
    clients = load_clients(manifest_path)
    observations = read_export(input_path, task_name, clients)
    added = sum(store_observation(archive, document) for archive, document in observations)
    return added, len(observations) - added


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="task-scoped BrightGauge/RMM CSV outside this repository")
    parser.add_argument("--manifest", required=True, type=Path, help="private client manifest with RMM company IDs, outside this repository")
    parser.add_argument("--task-name", required=True, help="exact scanner task name selected in the source export")
    args = parser.parse_args(argv)
    try:
        added, skipped = import_export(args.input, args.manifest, args.task_name)
    except (ImportError, build_dashboard_feed.FeedError, validate_observation.ObservationError, OSError) as exc:
        print(f"Could not import RMM task export: {exc}", file=sys.stderr)
        return 1
    print(f"Validated and archived {added} new observations; {skipped} identical observations were already present.")
    print("Scanner JSON, client identifiers, and archive contents are confidential. The source CSV remains in place for your approved retention process.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
