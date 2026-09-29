#!/usr/bin/env python3
"""Refresh private Shadow AI dashboard artifacts from one scoped RMM export.

The task-scoped CSV is validated and archived first. The complete accumulated
archive is then used to rebuild the BrightGauge findings/scan feeds and the
sortable technician HTML dashboard. All inputs and outputs contain confidential
client telemetry and must stay outside this public repository.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import build_dashboard_feed
import build_internal_dashboard
import build_report
import import_rmm_task_export
import validate_observation


def refresh(
    input_path: Path,
    manifest_path: Path,
    task_name: str,
    output_dir: Path,
    dashboard_path: Path,
    period: str | None = None,
    overwrite: bool = False,
) -> tuple[int, int, int, int, Path, Path, Path]:
    """Import one exact RMM task export, then rebuild all private views."""
    output_dir = build_dashboard_feed.outside_public_repo(output_dir, "dashboard feed directory")
    dashboard_path = build_dashboard_feed.outside_public_repo(dashboard_path, "dashboard output")
    for directory in (output_dir, dashboard_path.parent):
        if directory.exists():
            if not directory.is_dir():
                raise build_dashboard_feed.FeedError("dashboard output locations must be directories")
            if os.name == "posix" and directory.stat().st_mode & 0o077:
                raise build_dashboard_feed.FeedError(
                    "dashboard output directories must not grant group or other access (expected mode 0700 or stricter)"
                )
    if not overwrite:
        existing_outputs = [
            path for path in (
                output_dir / "shadow-ai-findings.csv",
                output_dir / "shadow-ai-scans.csv",
                dashboard_path,
            )
            if path.exists()
        ]
        if existing_outputs:
            raise build_dashboard_feed.FeedError(
                "dashboard outputs already exist; pass --overwrite only when replacing them is intended"
            )

    added, skipped = import_rmm_task_export.import_export(input_path, manifest_path, task_name)

    clients = build_dashboard_feed.load_manifest(manifest_path)
    providers, indicator_products = build_report.load_provider_names()
    finding_rows: list[dict[str, object]] = []
    scan_rows: list[dict[str, object]] = []
    for client in clients:
        client_findings, client_scans = build_dashboard_feed.load_client_data(
            client, period, providers, indicator_products
        )
        finding_rows.extend(client_findings)
        scan_rows.extend(client_scans)

    finding_rows.sort(key=lambda row: (
        str(row["client_label"]).casefold(), row["observed_at"], str(row["provider_name"]).casefold()
    ))
    scan_rows.sort(key=lambda row: (str(row["client_label"]).casefold(), row["collected_at"]))
    feed_paths = build_dashboard_feed.write_outputs(
        output_dir,
        build_dashboard_feed.make_csv(finding_rows, build_dashboard_feed.FINDING_FIELDS),
        build_dashboard_feed.make_csv(scan_rows, build_dashboard_feed.SCAN_FIELDS),
        overwrite,
    )

    payload = build_internal_dashboard.build_payload(manifest_path, period)
    dashboard = build_internal_dashboard.write_dashboard(
        dashboard_path, build_internal_dashboard.make_html(payload), overwrite
    )
    return added, skipped, len(finding_rows), len(scan_rows), feed_paths[0], feed_paths[1], dashboard


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="task-scoped RMM CSV outside this repository")
    parser.add_argument("--manifest", required=True, type=Path, help="private client/archive manifest")
    parser.add_argument("--task-name", required=True, help="exact scanner task name in the CSV")
    parser.add_argument("--output-dir", required=True, type=Path, help="private directory for BrightGauge CSV feeds")
    parser.add_argument("--dashboard", required=True, type=Path, help="private path for technician HTML dashboard")
    parser.add_argument("--period", type=build_dashboard_feed.parse_period, help="optional collection month, YYYY-MM")
    parser.add_argument("--overwrite", action="store_true", help="replace existing feed/dashboard outputs")
    args = parser.parse_args(argv)

    try:
        added, skipped, finding_count, scan_count, findings, scans, dashboard = refresh(
            args.input,
            args.manifest,
            args.task_name,
            args.output_dir,
            args.dashboard,
            args.period,
            args.overwrite,
        )
    except (
        import_rmm_task_export.ImportError,
        build_dashboard_feed.FeedError,
        build_report.ReportError,
        validate_observation.ObservationError,
        OSError,
    ) as exc:
        print(f"Could not refresh Shadow AI dashboard artifacts: {exc}", file=sys.stderr)
        return 1

    print(f"Archived {added} new observations; {skipped} identical observations were already present.")
    print(f"Built private latest-state findings feed ({finding_count} finding rows): {findings}")
    print(f"Built private scan coverage feed ({scan_count} rows): {scans}")
    print(f"Built private sortable technician dashboard: {dashboard}")
    print("All outputs contain confidential telemetry; connect only from approved, access-controlled locations.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
