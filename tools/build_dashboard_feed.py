#!/usr/bin/env python3
"""Build private, BrightGauge-friendly CSV feeds from isolated client archives.

The manifest, observations, review decisions, and CSV outputs contain client
telemetry and must remain outside this public repository. The findings feed is
one row per finding observation, not one row per unique finding over time.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import build_report


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_SCHEMA_VERSION = "1.0"
CLIENT_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
RMM_COMPANY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
FINDING_FIELDS = [
    "schema_version", "client_id", "client_label", "finding_key", "finding_id",
    "observation_id", "collected_at", "observed_at", "os_family", "provider_id",
    "provider_name", "product", "category", "capability", "confidence",
    "confidence_rank", "evidence_level", "review_status", "reviewed_at", "browser", "matched_domain",
    "extension_id", "display_name", "version", "classification_basis",
]
SCAN_FIELDS = [
    "schema_version", "client_id", "client_label", "period", "collected_at",
    "os_family", "collector_version", "scan_status", "partial", "finding_observations",
    "scope",
]
SAFE_ATTRIBUTES = {
    "browser", "matched_domain", "extension_id", "display_name", "version",
    "classification_basis",
}


class FeedError(ValueError):
    """Raised when a manifest or output violates feed safety requirements."""


def outside_public_repo(path: Path, what: str) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError:
        return resolved
    raise FeedError(f"{what} must be outside the public repository")


def load_manifest(path: Path) -> list[dict[str, Any]]:
    path = outside_public_repo(path, "client manifest")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FeedError(f"could not read client manifest: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise FeedError("client manifest must have schema_version 1.0")
    clients = data.get("clients")
    if not isinstance(clients, list) or not clients:
        raise FeedError("client manifest must include a non-empty clients array")
    seen_ids: set[str] = set()
    seen_labels: set[str] = set()
    seen_archives: set[Path] = set()
    seen_reviews: set[Path] = set()
    normalized: list[dict[str, Any]] = []
    for index, client in enumerate(clients):
        if not isinstance(client, dict):
            raise FeedError(f"client entry {index} must be an object")
        if set(client) - {"client_id", "client_label", "observations", "reviews", "rmm_company_unique_id"}:
            raise FeedError(f"client entry {index} contains unsupported fields")
        client_id = client.get("client_id")
        label = client.get("client_label")
        observations = client.get("observations")
        reviews = client.get("reviews")
        rmm_company_id = client.get("rmm_company_unique_id")
        if not isinstance(client_id, str) or not CLIENT_ID.fullmatch(client_id):
            raise FeedError(f"client entry {index} has an invalid client_id")
        if client_id in seen_ids:
            raise FeedError(f"duplicate client_id in manifest: {client_id}")
        if not isinstance(label, str) or not label.strip() or len(label.strip()) > 120:
            raise FeedError(f"client entry {index} needs a client_label of 1-120 characters")
        label = label.strip()
        if label.casefold() in seen_labels:
            raise FeedError("client labels must be unique ignoring case")
        if rmm_company_id is not None:
            if not isinstance(rmm_company_id, str) or not RMM_COMPANY_ID.fullmatch(rmm_company_id):
                raise FeedError(f"client entry {index} has an invalid rmm_company_unique_id")
            if any(entry.get("rmm_company_unique_id") == rmm_company_id for entry in normalized):
                raise FeedError("duplicate rmm_company_unique_id in manifest")
        if not isinstance(observations, str) or not observations.strip():
            raise FeedError(f"client entry {index} needs an observations directory or file")
        observation_path = outside_public_repo(path.parent / observations, "observation archive")
        for existing_archive in seen_archives:
            if (
                observation_path == existing_archive
                or observation_path.is_relative_to(existing_archive)
                or existing_archive.is_relative_to(observation_path)
            ):
                raise FeedError("client observation archives must not overlap or contain one another")
        review_path: Path | None = None
        if reviews is not None:
            if not isinstance(reviews, str) or not reviews.strip():
                raise FeedError(f"client entry {index} reviews must be a non-empty path when supplied")
            review_path = outside_public_repo(path.parent / reviews, "review decisions file")
            if review_path in seen_reviews:
                raise FeedError("each client must map to a separate review decisions file")
        seen_ids.add(client_id)
        seen_labels.add(label.casefold())
        seen_archives.add(observation_path)
        if review_path is not None:
            seen_reviews.add(review_path)
        normalized.append({
            "client_id": client_id,
            "client_label": label,
            "observations": observation_path,
            "reviews": review_path,
            "rmm_company_unique_id": rmm_company_id,
        })
    for client in normalized:
        review_path = client["reviews"]
        if review_path is None:
            continue
        if any(review_path.is_relative_to(archive) for archive in seen_archives):
            raise FeedError("review-decision files must be outside every client observation archive")
    return normalized


def csv_value(value: Any) -> str | int | float:
    """Neutralize spreadsheet-formula prefixes while preserving ordinary values."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return value
    text = str(value)
    stripped = text.lstrip(" \t\r\n")
    if stripped.startswith(("=", "+", "-", "@", "\t", "\r", "\n")):
        return "'" + text
    return text


def safe_attribute(attributes: dict[str, Any], name: str) -> str:
    value = attributes.get(name)
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        return str(value)[:500]
    return ""


def load_client_data(
    client: dict[str, Any],
    period: str | None,
    providers: dict[str, dict[str, Any]],
    indicator_products: dict[str, str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    archive = client["observations"]
    if not archive.exists():
        raise FeedError(f"observation archive does not exist for client_id {client['client_id']}")
    if archive.is_dir() and not list(archive.glob("*.json")):
        observations = []
    else:
        try:
            paths = build_report.collect_paths([str(archive)])
            observations = build_report.load_observations(paths, period)
        except build_report.ReportError as exc:
            if "no valid observations found" not in str(exc):
                raise FeedError(f"invalid archive for client_id {client['client_id']}: {exc}") from exc
            observations = []

    decisions = build_report.load_reviews(client["reviews"])
    finding_rows: list[dict[str, Any]] = []
    scan_rows: list[dict[str, Any]] = []
    for observation in observations:
        scan_rows.append({
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "client_id": client["client_id"],
            "client_label": client["client_label"],
            # Used only in-memory by the internal current-state dashboard to
            # choose one latest observation per endpoint. Feed schemas omit it.
            "_endpoint_key": observation["device"]["hostname"].casefold(),
            "_observation_id": observation["observation_id"],
            "period": period or observation["collected_at"][:7],
            "collected_at": observation["collected_at"],
            "os_family": observation["device"]["os_family"],
            "collector_version": observation["collector"]["version"],
            "scan_status": "partial" if observation["collector"]["partial"] else "complete",
            "partial": observation["collector"]["partial"],
            "finding_observations": len(observation["findings"]),
            "scope": ";".join(observation["scope"]),
        })
        for finding in observation["findings"]:
            provider_id = finding["provider_id"]
            provider = providers.get(provider_id, {"name": provider_id, "products": []})
            attributes = finding["attributes"]
            product = attributes.get("extension_name") or attributes.get("display_name")
            if not product:
                product = indicator_products.get(finding["indicator_id"])
            if not product:
                product = provider["products"][0] if provider["products"] else finding["capability"].replace("_", " ").title()
            finding_key = build_report.stable_finding_key(observation, finding)
            review = decisions.get(finding_key, {})
            row = {
                "schema_version": MANIFEST_SCHEMA_VERSION,
                "client_id": client["client_id"],
                "client_label": client["client_label"],
                "finding_key": finding_key,
                "finding_id": finding["finding_id"],
                "observation_id": observation["observation_id"],
                "collected_at": observation["collected_at"],
                "observed_at": finding["observed_at"],
                "os_family": observation["device"]["os_family"],
                "provider_id": provider_id,
                "provider_name": provider["name"],
                "product": str(product)[:200],
                "category": finding["category"],
                "capability": finding["capability"],
                "confidence": finding["confidence"],
                "confidence_rank": {"low": 1, "medium": 2, "high": 3}[finding["confidence"]],
                "evidence_level": finding["evidence_level"],
                "review_status": review.get("status", "open"),
                "reviewed_at": review.get("reviewed_at", ""),
                # Private in-memory lineage used to reduce the BrightGauge
                # feed to each endpoint's latest scan. It is not exported.
                "_endpoint_key": observation["device"]["hostname"].casefold(),
                "_observation_id": observation["observation_id"],
            }
            for name in SAFE_ATTRIBUTES:
                row[name] = safe_attribute(attributes, name)
            finding_rows.append(row)

    if not observations:
        scan_rows.append({
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "client_id": client["client_id"],
            "client_label": client["client_label"],
            "period": period or "",
            "collected_at": "",
            "os_family": "",
            "collector_version": "",
            "scan_status": "no_observations",
            "partial": "",
            "finding_observations": 0,
            "scope": "",
        })

    # BrightGauge is the operational present-state view. Keep only each
    # endpoint's latest scan and its findings; a latest scan with no findings
    # must replace, not inherit, older findings. The private archive remains
    # available for the monthly emailed report snapshot.
    latest_by_endpoint: dict[str, dict[str, Any]] = {}
    for scan in scan_rows:
        endpoint_key = scan.get("_endpoint_key")
        observation_id = scan.get("_observation_id")
        if not endpoint_key or not observation_id:
            continue
        previous = latest_by_endpoint.get(str(endpoint_key))
        ordering = (str(scan.get("collected_at", "")), str(observation_id))
        if previous is None or ordering > (
            str(previous.get("collected_at", "")), str(previous.get("_observation_id", ""))
        ):
            latest_by_endpoint[str(endpoint_key)] = scan

    latest_ids = {
        str(scan["_observation_id"])
        for scan in latest_by_endpoint.values()
        if scan.get("_observation_id")
    }
    current_scans = [*latest_by_endpoint.values()]
    if not observations:
        # Retain the explicit client-level no-observations row.
        current_scans.extend(scan for scan in scan_rows if scan.get("scan_status") == "no_observations")
    current_findings = [row for row in finding_rows if row.get("_observation_id") in latest_ids]
    return current_findings, current_scans


def make_csv(rows: list[dict[str, Any]], fields: list[str]) -> str:
    from io import StringIO

    output = StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({name: csv_value(row.get(name)) for name in fields})
    return output.getvalue()


def write_outputs(output_dir: Path, findings_csv: str, scans_csv: str, overwrite: bool) -> tuple[Path, Path]:
    output_dir = outside_public_repo(output_dir, "dashboard output directory")
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix" and output_dir.stat().st_mode & 0o077:
        raise FeedError("dashboard output directory must not grant group or other access (expected mode 0700 or stricter)")
    paths = (output_dir / "shadow-ai-findings.csv", output_dir / "shadow-ai-scans.csv")
    if not overwrite and any(path.exists() for path in paths):
        raise FeedError("dashboard feed files already exist; pass --overwrite only when replacing the private feed is intended")
    staged: list[Path] = []
    try:
        for destination, content in zip(paths, (findings_csv, scans_csv), strict=True):
            descriptor, temporary = tempfile.mkstemp(prefix=".shadow-ai-", suffix=".tmp", dir=output_dir)
            temp_path = Path(temporary)
            staged.append(temp_path)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        # Both files are prepared and permissioned before either visible name changes.
        if not overwrite and any(path.exists() for path in paths):
            raise FeedError("dashboard feed files appeared during export; no files were replaced")
        for temporary, destination in zip(staged, paths, strict=True):
            os.replace(temporary, destination)
        staged.clear()
    finally:
        for temporary in staged:
            temporary.unlink(missing_ok=True)
    return paths


def parse_period(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        datetime.strptime(value, "%Y-%m")
    except ValueError as exc:
        raise argparse.ArgumentTypeError("period must use YYYY-MM format") from exc
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path, help="private JSON client-to-archive manifest outside this repository")
    parser.add_argument("--output-dir", required=True, type=Path, help="private directory outside this repository; mode 0700 or stricter")
    parser.add_argument("--period", type=parse_period, help="optional collection month filter, YYYY-MM")
    parser.add_argument("--overwrite", action="store_true", help="replace existing private feed files")
    args = parser.parse_args(argv)
    try:
        clients = load_manifest(args.manifest)
        providers, indicator_products = build_report.load_provider_names()
        finding_rows: list[dict[str, Any]] = []
        scan_rows: list[dict[str, Any]] = []
        for client in clients:
            client_findings, client_scans = load_client_data(client, args.period, providers, indicator_products)
            finding_rows.extend(client_findings)
            scan_rows.extend(client_scans)
        finding_rows.sort(key=lambda row: (row["client_label"].casefold(), row["observed_at"], row["provider_name"].casefold()), reverse=False)
        scan_rows.sort(key=lambda row: (row["client_label"].casefold(), row["collected_at"]))
        finding_csv = make_csv(finding_rows, FINDING_FIELDS)
        scan_csv = make_csv(scan_rows, SCAN_FIELDS)
        output_paths = write_outputs(args.output_dir, finding_csv, scan_csv, args.overwrite)
    except (FeedError, build_report.ReportError, OSError) as exc:
        print(f"Could not build dashboard feed: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote private latest-state findings feed ({len(finding_rows)} rows): {output_paths[0]}")
    print(f"Wrote private latest-state scan coverage feed ({len(scan_rows)} endpoints): {output_paths[1]}")
    print("Client labels and telemetry are confidential; configure source permissions before connecting these files to a dashboard.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
