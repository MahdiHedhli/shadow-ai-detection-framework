#!/usr/bin/env python3
"""Reduce a broad RMM CSV to explicitly allowed exact scanner tasks and mapped clients.

This is a local, privacy-preserving intake step for cases where the RMM/BrightGauge
UI cannot export a task-scoped file directly. It reads the broad source but only
writes validated observations for the selected exact tasks and company IDs in the private
client manifest. The source file is never modified or removed.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, NamedTuple

import build_dashboard_feed
import import_rmm_task_export as importer
import validate_observation


REQUIRED_COLUMNS = importer.REQUIRED_COLUMNS
MAX_EXPORT_BYTES = importer.MAX_EXPORT_BYTES
MAX_ROWS = importer.MAX_ROWS
MAX_OBSERVATION_BYTES = importer.MAX_OBSERVATION_BYTES
MAX_VALIDATED_BYTES = importer.MAX_VALIDATED_BYTES
BRIGHTGAUGE_OUTPUT_CELL_LIMIT = 30_000


class FilterError(ValueError):
    """Raised when a broad export cannot be safely reduced."""


class FilterResult(NamedTuple):
    selected: int
    skipped: int
    incomplete: int
    incomplete_company_ids: tuple[str, ...]


def parse_scanner_output(raw: str) -> dict[str, Any]:
    """Compatibility wrapper for the importer's canonical transport parser."""
    return importer.parse_scanner_output(raw)


def filter_export(
    input_path: Path,
    manifest_path: Path,
    task_names: str | list[str] | tuple[str, ...],
    output_path: Path,
    allow_truncated_rows: bool = False,
) -> FilterResult:
    """Write only validated rows for exact allowed task names and mapped companies."""
    source = build_dashboard_feed.outside_public_repo(input_path, "RMM source export")
    destination = build_dashboard_feed.outside_public_repo(output_path, "task-scoped RMM export")
    if input_path.is_symlink() or output_path.is_symlink():
        raise FilterError("source and output paths must not be symbolic links")
    if source == destination:
        raise FilterError("source and output paths must be different")
    if destination.exists():
        raise FilterError("task-scoped output already exists; choose a new private path")
    allowed_task_names = importer.normalize_task_names(task_names)

    clients = importer.load_clients(manifest_path)
    allowed_company_ids = set(clients)
    try:
        source_stat = source.stat()
        if not source.is_file():
            raise FilterError("RMM source export must be a regular file")
        # Browser downloads commonly arrive with group/world-readable modes.
        # Tighten the local source before reading its client telemetry.
        os.chmod(source, 0o600)
        source_size = source_stat.st_size
    except OSError as exc:
        raise FilterError(f"could not inspect source export: {exc}") from exc
    if source_size > MAX_EXPORT_BYTES:
        raise FilterError("source export exceeds the 512 MiB safety limit")

    try:
        build_dashboard_feed.ensure_private_directory(destination.parent, "staging directory")
    except OSError as exc:
        raise FilterError(f"could not prepare private staging directory: {exc}") from exc

    temporary_path: Path | None = None
    selected_rows = 0
    skipped_rows = 0
    incomplete_rows = 0
    incomplete_company_ids: set[str] = set()
    validated_bytes = 0
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".shadow-ai-task-filter-", suffix=".tmp", dir=destination.parent)
        temporary_path = Path(temporary)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as output:
            os.fchmod(output.fileno(), 0o600)
            writer = csv.DictWriter(
                output,
                fieldnames=["company_unique_id", "task_name", "execution_output"],
                extrasaction="ignore",
                lineterminator="\n",
            )
            writer.writeheader()
            try:
                with source.open("r", encoding="utf-8-sig", newline="") as handle:
                    reader = csv.DictReader(handle)
                    if not reader.fieldnames or len(reader.fieldnames) != len(set(reader.fieldnames)):
                        raise FilterError("RMM source CSV must have one header for each column")
                    missing = REQUIRED_COLUMNS - set(reader.fieldnames)
                    if missing:
                        raise FilterError(f"RMM source CSV is missing required columns: {', '.join(sorted(missing))}")
                    for row_number, row in enumerate(reader, start=2):
                        if row_number - 1 > MAX_ROWS:
                            raise FilterError("RMM source export exceeds the 10,000-row safety limit")
                        task_name = str(row.get("task_name") or "").strip()
                        if task_name not in allowed_task_names:
                            skipped_rows += 1
                            continue

                        company_id = str(row.get("company_unique_id") or "").strip()
                        if company_id not in allowed_company_ids:
                            raise FilterError(f"selected task row {row_number} has an unmapped company ID")
                        raw = row.get("execution_output", "")
                        if not raw or len(raw.encode("utf-8")) > MAX_OBSERVATION_BYTES:
                            raise FilterError(f"selected task row {row_number} has missing or oversized output")
                        try:
                            document = parse_scanner_output(raw)
                        except (json.JSONDecodeError, importer.rmm_output.RmmOutputError, validate_observation.ObservationError, TypeError, KeyError, AttributeError) as exc:
                            if allow_truncated_rows and len(raw) == BRIGHTGAUGE_OUTPUT_CELL_LIMIT:
                                incomplete_rows += 1
                                incomplete_company_ids.add(company_id)
                                continue
                            raise FilterError(f"selected task row {row_number} has invalid scanner JSON: {exc}") from exc

                        normalized = importer.canonical(document)
                        validated_bytes += len(normalized.encode("utf-8"))
                        if validated_bytes > MAX_VALIDATED_BYTES:
                            raise FilterError("selected observations exceed the 256 MiB safety limit")
                        writer.writerow({
                            "company_unique_id": company_id,
                            "task_name": task_name,
                            "execution_output": normalized,
                        })
                        selected_rows += 1
            except (OSError, csv.Error, UnicodeDecodeError) as exc:
                raise FilterError(f"could not read RMM source export: {exc}") from exc
            if selected_rows == 0:
                raise FilterError("source export contains no rows for the exact task and mapped clients")
            output.flush()
            os.fsync(output.fileno())

        # Atomic no-overwrite publication; source and filtered copy remain separate.
        try:
            os.link(temporary_path, destination)
        except FileExistsError as exc:
            raise FilterError("task-scoped output appeared during filtering; no file was replaced") from exc
        temporary_path.unlink()
        temporary_path = None
    except OSError as exc:
        raise FilterError(f"could not write private task-scoped export: {exc}") from exc
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return FilterResult(selected_rows, skipped_rows, incomplete_rows, tuple(sorted(incomplete_company_ids)))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="broad RMM CSV; source is left unchanged")
    parser.add_argument("--manifest", required=True, type=Path, help="private client manifest with RMM company IDs")
    parser.add_argument("--task-name", required=True, action="append", help="exact Shadow AI collector task name; repeat for additional platform/version tasks")
    parser.add_argument("--output", required=True, type=Path, help="new private task-scoped CSV outside this repository")
    parser.add_argument("--allow-truncated-rows", action="store_true", help="exclude malformed exact-30,000-character outputs and report them as incomplete")
    args = parser.parse_args(argv)
    try:
        result = filter_export(args.input, args.manifest, args.task_name, args.output, args.allow_truncated_rows)
    except (FilterError, importer.ImportError, build_dashboard_feed.FeedError, validate_observation.ObservationError) as exc:
        print(f"Could not create task-scoped Shadow AI export: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote {result.selected} validated rows for the selected exact task names; skipped {result.skipped} unrelated task rows.")
    if result.incomplete:
        print(f"Excluded {result.incomplete} malformed 30,000-character scanner output(s) as incomplete; inspect or re-export them.")
    print("The original export was left unchanged. Both files contain confidential telemetry; keep them in restricted storage.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
