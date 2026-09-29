#!/usr/bin/env python3
"""Build the private technician dashboard from an RMM export.

The source may contain multiple task types. This command first reduces it in a
restricted temporary directory to validated rows for the exact scanner task
and mapped clients, then imports those observations and rebuilds the feeds and
dashboard. The broad source is never modified; the temporary scoped CSV is
removed when the command finishes.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

import build_dashboard_feed
import filter_rmm_task_export
import import_rmm_task_export
import refresh_dashboard
import validate_observation


def refresh_from_export(
    input_path: Path,
    manifest_path: Path,
    task_name: str,
    staging_dir: Path,
    output_dir: Path,
    dashboard_path: Path,
    period: str | None = None,
    overwrite: bool = False,
    allow_truncated_rows: bool = False,
) -> tuple[int, int, int, int, Path, Path, Path, int, int, int]:
    """Filter, validate, import, and rebuild using one restricted transient copy."""
    staging_dir = build_dashboard_feed.outside_public_repo(staging_dir, "temporary staging directory")
    try:
        staging_dir = build_dashboard_feed.ensure_private_directory(staging_dir, "temporary staging directory")
    except OSError as exc:
        raise build_dashboard_feed.FeedError(f"could not prepare private temporary staging: {exc}") from exc

    with tempfile.TemporaryDirectory(prefix=".shadow-ai-refresh-", dir=staging_dir) as temporary:
        scoped_export = Path(temporary) / "task-only.csv"
        filter_result = filter_rmm_task_export.filter_export(
            input_path, manifest_path, task_name, scoped_export, allow_truncated_rows
        )
        import_note = (
            f"Source export incomplete: {filter_result.incomplete} scanner result(s) were exactly 30,000 characters and could not be validated. Their findings are excluded; they may be truncated at the export limit. Re-export or rerun them before treating this view as complete."
            if filter_result.incomplete else None
        )
        result = refresh_dashboard.refresh(
            scoped_export,
            manifest_path,
            task_name,
            output_dir,
            dashboard_path,
            period,
            overwrite,
            import_note,
        )
    return (*result, filter_result.selected, filter_result.skipped, filter_result.incomplete)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="RMM/BrightGauge CSV source; left unchanged")
    parser.add_argument("--manifest", required=True, type=Path, help="private client manifest with RMM company IDs")
    parser.add_argument("--task-name", required=True, help="exact Shadow AI collector task name")
    parser.add_argument("--staging-dir", required=True, type=Path, help="private local directory for transient filtered CSV")
    parser.add_argument("--output-dir", required=True, type=Path, help="private directory for BrightGauge CSV feeds")
    parser.add_argument("--dashboard", required=True, type=Path, help="private path for technician HTML dashboard")
    parser.add_argument("--period", type=build_dashboard_feed.parse_period, help="optional month, YYYY-MM")
    parser.add_argument("--overwrite", action="store_true", help="replace existing feed/dashboard outputs")
    parser.add_argument("--allow-truncated-rows", action="store_true", help="exclude malformed 30,000-character outputs and visibly mark the dashboard incomplete")
    args = parser.parse_args(argv)

    try:
        result = refresh_from_export(
            args.input,
            args.manifest,
            args.task_name,
            args.staging_dir,
            args.output_dir,
            args.dashboard,
            args.period,
            args.overwrite,
            args.allow_truncated_rows,
        )
    except (
        filter_rmm_task_export.FilterError,
        import_rmm_task_export.ImportError,
        build_dashboard_feed.FeedError,
        refresh_dashboard.build_report.ReportError,
        validate_observation.ObservationError,
        OSError,
    ) as exc:
        print(f"Could not refresh Shadow AI dashboard from RMM export: {exc}", file=sys.stderr)
        return 1

    added, already_present, finding_count, scan_count, findings, scans, dashboard, filtered, skipped, incomplete = result
    print(f"Filtered to {filtered} validated rows for the exact scanner task; skipped {skipped} unrelated task rows.")
    if incomplete:
        print(f"Excluded {incomplete} malformed 30,000-character scanner output(s); dashboard is visibly marked incomplete.")
    print(f"Archived {added} new observations; {already_present} identical observations were already present.")
    print(f"Built private latest-state findings feed ({finding_count} finding rows): {findings}")
    print(f"Built private scan coverage feed ({scan_count} rows): {scans}")
    print(f"Built private sortable technician dashboard: {dashboard}")
    print("The broad source was left unchanged; the transient task-only CSV was removed. Keep outputs in restricted storage.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
