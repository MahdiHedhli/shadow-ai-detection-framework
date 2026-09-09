#!/usr/bin/env python3
"""Validate the security and structural invariants of collector observations."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime
from pathlib import Path


EXPECTED_TOP_LEVEL = {
    "schema_version",
    "observation_id",
    "collected_at",
    "collector",
    "device",
    "scope",
    "safety",
    "findings",
}
REQUIRED_FALSE_SAFETY = {
    "content_collected",
    "raw_command_line_collected",
    "environment_values_collected",
    "network_requests_made",
    "full_disk_search_performed",
    "symlinks_followed",
}
ALLOWED_CATEGORIES = {"process", "software", "model_directory", "config_file", "browser_extension"}
ALLOWED_CONFIDENCE = {"low", "medium", "high"}
ALLOWED_SCOPE = {"processes", "known_paths", "browser_extensions", "installed_software"}
SENSITIVE_KEYS = {
    "command_line",
    "raw_command_line",
    "prompt",
    "response",
    "content",
    "file_content",
    "environment_value",
    "api_key",
    "secret",
}


class ObservationError(ValueError):
    """Raised when an observation violates the portable contract."""


def _datetime(value: object, context: str) -> None:
    if not isinstance(value, str):
        raise ObservationError(f"{context} must be a string")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ObservationError(f"{context} must be an ISO 8601 date-time") from exc


def _uuid(value: object, context: str) -> None:
    try:
        uuid.UUID(str(value))
    except (ValueError, AttributeError) as exc:
        raise ObservationError(f"{context} must be a UUID") from exc


def _reject_sensitive_keys(value: object, context: str = "document") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in SENSITIVE_KEYS:
                raise ObservationError(f"{context} contains prohibited key {key!r}")
            _reject_sensitive_keys(child, f"{context}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_sensitive_keys(child, f"{context}[{index}]")


def validate_document(document: object) -> None:
    if not isinstance(document, dict):
        raise ObservationError("document must be an object")
    if set(document) != EXPECTED_TOP_LEVEL:
        raise ObservationError("top-level fields do not match observation schema")
    if document["schema_version"] != "1.0":
        raise ObservationError("unsupported schema_version")
    _uuid(document["observation_id"], "observation_id")
    _datetime(document["collected_at"], "collected_at")

    collector = document["collector"]
    if not isinstance(collector, dict) or set(collector) != {"name", "version", "partial", "errors"}:
        raise ObservationError("collector fields do not match observation schema")
    if any(not isinstance(collector[field], str) or not collector[field] for field in ("name", "version")):
        raise ObservationError("collector name/version must be non-empty strings")
    if not isinstance(collector["partial"], bool) or not isinstance(collector["errors"], list):
        raise ObservationError("collector partial/errors types are invalid")
    if any(not isinstance(item, str) or len(item) > 200 for item in collector["errors"]):
        raise ObservationError("collector errors must be short strings")

    device = document["device"]
    if not isinstance(device, dict) or set(device) != {"hostname", "os_family", "os_version", "architecture"}:
        raise ObservationError("device fields do not match observation schema")
    if device["os_family"] not in {"windows", "macos", "linux", "unknown"}:
        raise ObservationError("unsupported os_family")
    if any(not isinstance(device[field], str) or not device[field] for field in device):
        raise ObservationError("device values must be non-empty strings")

    scope = document["scope"]
    if (
        not isinstance(scope, list)
        or not scope
        or any(item not in ALLOWED_SCOPE for item in scope)
        or len(scope) != len(set(scope))
    ):
        raise ObservationError("scope contains invalid or duplicate values")

    safety = document["safety"]
    if not isinstance(safety, dict) or set(safety) != REQUIRED_FALSE_SAFETY:
        raise ObservationError("safety fields do not match observation schema")
    if any(safety[field] is not False for field in REQUIRED_FALSE_SAFETY):
        raise ObservationError("all safety flags must be false")

    findings = document["findings"]
    if not isinstance(findings, list) or len(findings) > 5000:
        raise ObservationError("findings must be an array of at most 5000 items")
    required = {
        "finding_id", "observed_at", "category", "indicator_id", "provider_id", "capability",
        "confidence", "evidence_level", "subject_user", "attributes",
    }
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict) or set(finding) != required:
            raise ObservationError(f"finding {index} fields do not match observation schema")
        _uuid(finding["finding_id"], f"finding {index}.finding_id")
        _datetime(finding["observed_at"], f"finding {index}.observed_at")
        if finding["category"] not in ALLOWED_CATEGORIES:
            raise ObservationError(f"finding {index} has unsupported category")
        if finding["confidence"] not in ALLOWED_CONFIDENCE:
            raise ObservationError(f"finding {index} has unsupported confidence")
        for field in ("indicator_id", "provider_id", "capability"):
            if not isinstance(finding[field], str) or not finding[field]:
                raise ObservationError(f"finding {index}.{field} must be a non-empty string")
        if finding["subject_user"] is not None and not isinstance(finding["subject_user"], str):
            raise ObservationError(f"finding {index}.subject_user must be a string or null")
        if not isinstance(finding["evidence_level"], int) or not 1 <= finding["evidence_level"] <= 5:
            raise ObservationError(f"finding {index} has invalid evidence_level")
        if not isinstance(finding["attributes"], dict):
            raise ObservationError(f"finding {index} attributes must be an object")
        if len(finding["attributes"]) > 20 or any(
            not isinstance(value, (str, int, float, bool, type(None)))
            for value in finding["attributes"].values()
        ):
            raise ObservationError(f"finding {index} attributes contain unsupported values")
    _reject_sensitive_keys(document)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", help="JSON file; stdin is used when omitted")
    args = parser.parse_args()
    try:
        if args.path:
            document = json.loads(Path(args.path).read_text(encoding="utf-8"))
        else:
            document = json.load(sys.stdin)
        validate_document(document)
    except (OSError, json.JSONDecodeError, ObservationError) as exc:
        print(f"Invalid observation: {exc}", file=sys.stderr)
        return 1
    print("Observation is valid.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
