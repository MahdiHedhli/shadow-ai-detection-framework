#!/usr/bin/env python3
"""Revalidate browser-extension catalog URLs and retain an append-only daily history."""

from __future__ import annotations

import argparse
import csv
import re
import tempfile
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "catalog" / "browser_extensions.csv"
HISTORY_PATH = ROOT / "catalog" / "browser_extension_history.csv"
CANDIDATE_PATH = ROOT / "catalog" / "browser_extension_candidates.csv"
EXTENSION_ID_RE = re.compile(r"^[a-p]{32}$")
HISTORY_FIELDS = (
    "observed_on",
    "extension_id",
    "provider_id",
    "browser",
    "extension_name",
    "source_url",
    "verification_status",
    "observed_url",
    "http_status",
    "notes",
)
CANDIDATE_FIELDS = (
    "discovered_on",
    "extension_id",
    "provider_id",
    "browser",
    "extension_name",
    "discovery_url",
    "listing_url",
    "status",
    "notes",
)


@dataclass(frozen=True)
class FetchResult:
    status: int | None
    final_url: str
    body: bytes
    error: str = ""


def extension_id_from_url(value: str) -> str | None:
    for segment in reversed(urlparse(value).path.split("/")):
        if EXTENSION_ID_RE.fullmatch(segment):
            return segment
    return None


def fetch_listing(url: str, timeout: float) -> FetchResult:
    request = Request(
        url,
        headers={
            "Accept": "text/html,application/xhtml+xml",
            "User-Agent": "Mozilla/5.0 shadow-ai-extension-inventory/0.1",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read(2_097_153)
            if len(body) > 2_097_152:
                return FetchResult(response.status, response.geturl(), b"", "response_too_large")
            return FetchResult(response.status, response.geturl(), body)
    except HTTPError as exc:
        return FetchResult(exc.code, exc.geturl() or url, b"", f"http_{exc.code}")
    except (URLError, TimeoutError, OSError) as exc:
        return FetchResult(None, url, b"", type(exc).__name__)


def classify_result(row: dict[str, str], result: FetchResult) -> tuple[dict[str, str], dict[str, str] | None]:
    expected_id = row["extension_id"]
    observed_id = extension_id_from_url(result.final_url)
    candidate = None
    if observed_id and observed_id != expected_id:
        status = "redirected_id_review_required"
        notes = "Store URL redirected to a different extension ID; manual publisher verification required"
        candidate = {
            "discovered_on": date.today().isoformat(),
            "extension_id": observed_id,
            "provider_id": row["provider_id"],
            "browser": row["browser"],
            "extension_name": row["extension_name"],
            "discovery_url": row["source_url"],
            "listing_url": result.final_url,
            "status": "review_required",
            "notes": "Discovered through a redirect; do not promote without publisher verification",
        }
    elif result.error:
        status = "unreachable"
        notes = result.error
    elif result.status == 200 and observed_id == expected_id:
        status = "reachable_id_confirmed"
        notes = "Listing URL remains reachable with the cataloged ID; publisher identity was not auto-trusted"
    else:
        status = "unconfirmed"
        notes = "Listing response did not confirm the cataloged ID"
    history = {
        "observed_on": date.today().isoformat(),
        "extension_id": expected_id,
        "provider_id": row["provider_id"],
        "browser": row["browser"],
        "extension_name": row["extension_name"],
        "source_url": row["source_url"],
        "verification_status": status,
        "observed_url": result.final_url,
        "http_status": "" if result.status is None else str(result.status),
        "notes": notes,
    }
    return history, candidate


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_rows(path: Path, fields: tuple[str, ...], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="", dir=path.parent, delete=False) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        temporary = Path(handle.name)
    temporary.replace(path)


def update_inventory(
    timeout: float = 20.0,
    fetcher: Callable[[str, float], FetchResult] = fetch_listing,
) -> tuple[int, int]:
    catalog = read_rows(CATALOG_PATH)
    today = date.today().isoformat()
    history = read_rows(HISTORY_PATH)
    recorded_observations = {
        (row.get("observed_on", ""), row.get("extension_id", "")) for row in history
    }
    candidates = read_rows(CANDIDATE_PATH)
    active_ids = {row["extension_id"] for row in catalog}
    candidate_ids = {row.get("extension_id", "") for row in candidates}
    new_candidates = 0
    for row in catalog:
        result = fetcher(row["source_url"], timeout)
        observation, candidate = classify_result(row, result)
        observation_key = (today, row["extension_id"])
        # A dated observation is immutable. In particular, an automated URL
        # reachability check must never downgrade a same-day publisher identity
        # that an analyst already verified manually.
        if observation_key not in recorded_observations:
            history.append(observation)
            recorded_observations.add(observation_key)
        if candidate and candidate["extension_id"] not in active_ids | candidate_ids:
            candidates.append(candidate)
            candidate_ids.add(candidate["extension_id"])
            new_candidates += 1
    history.sort(key=lambda row: (row["observed_on"], row["provider_id"], row["extension_id"]))
    candidates.sort(key=lambda row: (row["discovered_on"], row["provider_id"], row["extension_id"]))
    write_rows(HISTORY_PATH, HISTORY_FIELDS, history)
    write_rows(CANDIDATE_PATH, CANDIDATE_FIELDS, candidates)
    return len(catalog), new_candidates


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()
    checked, candidates = update_inventory(timeout=args.timeout)
    print(f"Recorded {checked} extension observations; added {candidates} review candidate(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
