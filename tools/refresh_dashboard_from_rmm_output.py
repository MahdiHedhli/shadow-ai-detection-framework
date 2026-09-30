#!/usr/bin/env python3
"""Refresh the private dashboard from one saved RMM scanner output file.

Use this when an Automation Details CSV omits or truncates a recent run. The
input must be a single scanner JSON document (or SHADOWAI_GZIP_V1 envelope),
not a broad task export. All telemetry stays in restricted storage.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

import build_dashboard_feed
import import_rmm_task_export
import refresh_dashboard_from_rmm_export


MAX_OUTPUT_BYTES = 2 * 1024 * 1024
TASK_PATTERN = re.compile(r"^Shadow AI Inventory - [A-Za-z0-9 ()-]+(?: v[0-9]+\.[0-9]+\.[0-9]+)?$")
COLLECTORS_BY_OS = {
    "windows": {"shadow-ai-rmm-windows"},
    "macos": {"shadow-ai-rmm-macos-native", "shadow-ai-rmm-macos-linux"},
    "linux": {"shadow-ai-rmm-macos-linux"},
}


class OutputError(ValueError):
    """Raised when a saved RMM output is unsafe or does not match its scope."""


def read_private_output(path: Path) -> str:
    """Read one bounded private regular file without following symlinks."""
    if path.is_symlink():
        raise OutputError("RMM output must not be a symbolic link")
    resolved = build_dashboard_feed.outside_public_repo(path, "RMM scanner output")
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(resolved, flags)
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise OutputError("RMM output must be a regular file")
            if info.st_size > MAX_OUTPUT_BYTES:
                raise OutputError("RMM output exceeds the 2 MiB safety limit")
            if os.name == "posix" and info.st_mode & 0o077:
                raise OutputError("RMM output file must not grant group or other access (expected mode 0600 or stricter)")
            raw = handle.read(MAX_OUTPUT_BYTES + 1)
    except OSError as exc:
        raise OutputError(f"could not read RMM output: {exc}") from exc
    if not raw or len(raw) > MAX_OUTPUT_BYTES:
        raise OutputError("RMM output is empty or exceeds the 2 MiB safety limit")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OutputError("RMM output must be UTF-8 text") from exc


def validate_scope(document: dict[str, object], client_label: str, task_name: str) -> str:
    if not isinstance(client_label, str) or not client_label.strip():
        raise OutputError("client label must be a non-empty exact manifest label")
    if not isinstance(task_name, str) or not TASK_PATTERN.fullmatch(task_name):
        raise OutputError("task name must be an exact Shadow AI Inventory task name")
    device = document["device"]
    collector = document["collector"]
    assert isinstance(device, dict) and isinstance(collector, dict)  # validated schema
    os_family = str(device["os_family"])
    collector_name = str(collector["name"])
    if collector_name not in COLLECTORS_BY_OS.get(os_family, set()):
        raise OutputError("collector identity does not match the observation operating system")
    task_platform = task_name.casefold()
    if (os_family == "windows" and "windows" not in task_platform) or (
        os_family in {"macos", "linux"} and not any(name in task_platform for name in ("macos", "linux"))
    ):
        raise OutputError("task name platform does not match the scanner observation")
    return collector_name


def refresh_from_output(
    input_path: Path,
    manifest_path: Path,
    client_label: str,
    task_name: str,
    staging_dir: Path,
    output_dir: Path,
    dashboard_path: Path,
    period: str | None = None,
    overwrite: bool = False,
) -> tuple[int, int, int, int, Path, Path, Path, int, int, int]:
    raw = read_private_output(input_path)
    try:
        document = import_rmm_task_export.parse_scanner_output(raw)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise OutputError(f"RMM output is not a valid scanner observation: {exc}") from exc
    validate_scope(document, client_label, task_name)

    clients = build_dashboard_feed.load_manifest(manifest_path)
    matches = [client for client in clients if client["client_label"].casefold() == client_label.strip().casefold()]
    if len(matches) != 1:
        raise OutputError("client label must match exactly one entry in the private manifest")
    company_id = matches[0]["rmm_company_unique_id"]
    if not company_id:
        raise OutputError("selected client has no RMM company ID in the private manifest")

    staging_dir = build_dashboard_feed.ensure_private_directory(
        build_dashboard_feed.outside_public_repo(staging_dir, "temporary staging directory"),
        "temporary staging directory",
    )
    descriptor, name = tempfile.mkstemp(prefix=".shadow-ai-single-run-", suffix=".csv", dir=staging_dir)
    staged_csv = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            os.fchmod(handle.fileno(), 0o600)
            writer = csv.DictWriter(handle, fieldnames=["company_unique_id", "task_name", "execution_output"])
            writer.writeheader()
            writer.writerow({"company_unique_id": company_id, "task_name": task_name, "execution_output": raw})
            handle.flush()
            os.fsync(handle.fileno())
        return refresh_dashboard_from_rmm_export.refresh_from_export(
            staged_csv, manifest_path, task_name, staging_dir, output_dir, dashboard_path, period, overwrite
        )
    finally:
        staged_csv.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="private saved single-run JSON/envelope file")
    parser.add_argument("--manifest", required=True, type=Path, help="private client manifest with RMM company IDs")
    parser.add_argument("--client", required=True, help="exact client label from the private manifest")
    parser.add_argument("--task-name", required=True, help="exact Shadow AI Inventory task name for the run")
    parser.add_argument("--staging-dir", required=True, type=Path, help="private directory for transient scoped CSV")
    parser.add_argument("--output-dir", required=True, type=Path, help="private dashboard feed directory")
    parser.add_argument("--dashboard", required=True, type=Path, help="private technician HTML dashboard path")
    parser.add_argument("--period", type=build_dashboard_feed.parse_period, help="optional month, YYYY-MM")
    parser.add_argument("--overwrite", action="store_true", help="replace existing feed/dashboard outputs")
    args = parser.parse_args(argv)
    try:
        result = refresh_from_output(
            args.input, args.manifest, args.client, args.task_name, args.staging_dir,
            args.output_dir, args.dashboard, args.period, args.overwrite,
        )
    except (OutputError, build_dashboard_feed.FeedError, import_rmm_task_export.ImportError,
            refresh_dashboard_from_rmm_export.filter_rmm_task_export.FilterError,
            OSError) as exc:
        print(f"Could not refresh Shadow AI dashboard from saved RMM output: {exc}", file=sys.stderr)
        return 1
    added, already_present, findings_count, scans_count, findings, scans, dashboard, _, _, _ = result
    print(f"Archived {added} new observation(s); {already_present} identical observation(s) already existed.")
    print(f"Built private finding feed ({findings_count} rows): {findings}")
    print(f"Built private scan feed ({scans_count} rows): {scans}")
    print(f"Built private technician dashboard: {dashboard}")
    print("The saved source file was left unchanged; transient CSV removed. Keep all outputs in restricted storage.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
