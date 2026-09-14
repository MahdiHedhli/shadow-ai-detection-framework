#!/usr/bin/env python3
"""Validate source data and build deployable Shadow AI detection artifacts."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import tempfile
from datetime import date
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
CATALOG_DIR = ROOT / "catalog"
SPECS_DIR = ROOT / "detections" / "specs"
TEMPLATES_DIR = ROOT / "templates"
DIST_DIR = ROOT / "dist"

DOMAIN_REQUIRED = {
    "indicator_id",
    "provider_id",
    "provider_name",
    "product_name",
    "indicator_type",
    "indicator",
    "capability",
    "channel",
    "source_url",
    "last_validated",
    "notes",
}
ARTIFACT_REQUIRED = {
    "artifact_id",
    "provider_id",
    "artifact_type",
    "platform",
    "pattern",
    "match_mode",
    "capability",
    "confidence",
    "source_url",
    "last_validated",
    "notes",
}
BROWSER_EXTENSION_REQUIRED = {
    "extension_id",
    "provider_id",
    "browser",
    "extension_name",
    "source_url",
    "last_validated",
    "notes",
}
BROWSER_EXTENSION_NAME_REQUIRED = {
    "pattern",
    "provider_id",
    "confidence",
    "source_url",
    "last_validated",
    "notes",
}
BROWSER_EXTENSION_HISTORY_REQUIRED = {
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
}
SPEC_REQUIRED = {
    "id",
    "title",
    "objective",
    "status",
    "evidence_level",
    "confidence",
    "signal_families",
    "required_fields",
    "limitations",
    "platforms",
}

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,79}$")
SPEC_ID_RE = re.compile(r"^SAI-[0-9]{3}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
CHROMIUM_EXTENSION_ID_RE = re.compile(r"^[a-p]{32}$")
FORMULA_PREFIXES = ("=", "+", "-", "@")
FORBIDDEN_MDE_TERMS = ("SentBytes", "ReceivedBytes", '"FileRead"', '"FileOpened"', '"FileAccessed"')


class ValidationError(ValueError):
    """Raised when repository source data violates a safety or schema rule."""


def read_csv(path: Path, required: set[str]) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or [])
        if fields != required:
            missing = sorted(required - fields)
            extra = sorted(fields - required)
            raise ValidationError(f"{path}: columns differ; missing={missing}, extra={extra}")
        return [{key: (value or "").strip() for key, value in row.items()} for row in reader]


def validate_source_url(value: str, context: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ValidationError(f"{context}: source_url must be an HTTPS URL without credentials")


def validate_date(value: str, context: str) -> None:
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ValidationError(f"{context}: invalid ISO date {value!r}") from exc
    if parsed > date.today():
        raise ValidationError(f"{context}: validation date cannot be in the future")


def reject_spreadsheet_formula(value: str, context: str) -> None:
    if value.startswith(FORMULA_PREFIXES):
        raise ValidationError(f"{context}: value begins with a spreadsheet formula character")


def validate_domains(rows: list[dict[str, str]]) -> None:
    ids: set[str] = set()
    indicators: set[str] = set()
    for row in rows:
        context = row.get("indicator_id") or "domain row"
        if not ID_RE.fullmatch(context):
            raise ValidationError(f"{context}: invalid indicator_id")
        if context in ids:
            raise ValidationError(f"{context}: duplicate indicator_id")
        ids.add(context)

        indicator = row["indicator"]
        reject_spreadsheet_formula(indicator, context)
        if indicator != indicator.lower() or "*" in indicator or not DOMAIN_RE.fullmatch(indicator):
            raise ValidationError(f"{context}: indicator must be a lowercase hostname without wildcards")
        if indicator in indicators:
            raise ValidationError(f"{context}: duplicate indicator {indicator}")
        indicators.add(indicator)

        if row["indicator_type"] not in {"registered_domain", "fqdn"}:
            raise ValidationError(f"{context}: unsupported indicator_type")
        if not ID_RE.fullmatch(row["provider_id"]):
            raise ValidationError(f"{context}: invalid provider_id")
        validate_source_url(row["source_url"], context)
        validate_date(row["last_validated"], context)


def validate_artifacts(rows: list[dict[str, str]]) -> None:
    ids: set[str] = set()
    allowed_types = {"process", "command_line", "model_file", "config_file", "environment_variable_name"}
    allowed_modes = {"exact", "contains", "suffix"}
    for row in rows:
        context = row.get("artifact_id") or "artifact row"
        if not ID_RE.fullmatch(context) or context in ids:
            raise ValidationError(f"{context}: invalid or duplicate artifact_id")
        ids.add(context)
        if row["artifact_type"] not in allowed_types:
            raise ValidationError(f"{context}: unsupported artifact_type")
        if row["platform"] not in {"any", "windows", "macos", "linux"}:
            raise ValidationError(f"{context}: unsupported platform")
        if row["match_mode"] not in allowed_modes:
            raise ValidationError(f"{context}: unsupported match_mode")
        if row["confidence"] not in {"low", "medium", "high"}:
            raise ValidationError(f"{context}: unsupported confidence")
        if not row["pattern"] or len(row["pattern"]) > 200 or any(c in row["pattern"] for c in "\r\n\x00"):
            raise ValidationError(f"{context}: unsafe pattern")
        # Scoped package names legitimately begin with '@'. Allow only the
        # constrained npm-style form; reject every other formula-like prefix.
        if row["pattern"].startswith("@"):
            if row["artifact_type"] != "command_line" or not re.fullmatch(
                r"@[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)?", row["pattern"]
            ):
                raise ValidationError(f"{context}: unsafe @-prefixed pattern")
        else:
            reject_spreadsheet_formula(row["pattern"], context)
        validate_source_url(row["source_url"], context)
        validate_date(row["last_validated"], context)


def validate_browser_extensions(rows: list[dict[str, str]]) -> None:
    ids: set[str] = set()
    for row in rows:
        context = row.get("extension_id") or "browser extension row"
        if not CHROMIUM_EXTENSION_ID_RE.fullmatch(context):
            raise ValidationError(f"{context}: invalid Chromium extension_id")
        if context in ids:
            raise ValidationError(f"{context}: duplicate extension_id")
        ids.add(context)
        if not ID_RE.fullmatch(row["provider_id"]):
            raise ValidationError(f"{context}: invalid provider_id")
        if row["browser"] not in {"chrome", "chromium", "edge", "brave", "chromium-family"}:
            raise ValidationError(f"{context}: unsupported browser")
        if not row["extension_name"] or any(character in row["extension_name"] for character in "\r\n\x00"):
            raise ValidationError(f"{context}: unsafe extension_name")
        reject_spreadsheet_formula(row["extension_name"], context)
        validate_source_url(row["source_url"], context)
        validate_date(row["last_validated"], context)


def validate_browser_extension_names(rows: list[dict[str, str]]) -> None:
    patterns: set[str] = set()
    for row in rows:
        context = row.get("pattern") or "browser extension name row"
        folded = context.casefold()
        if folded in patterns:
            raise ValidationError(f"{context}: duplicate browser extension name pattern")
        patterns.add(folded)
        if len(context) < 3 or len(context) > 100 or any(character in context for character in "\r\n\x00"):
            raise ValidationError(f"{context}: unsafe browser extension name pattern")
        reject_spreadsheet_formula(context, context)
        if not ID_RE.fullmatch(row["provider_id"]):
            raise ValidationError(f"{context}: invalid provider_id")
        if row["confidence"] not in {"low", "medium", "high"}:
            raise ValidationError(f"{context}: unsupported confidence")
        validate_source_url(row["source_url"], context)
        validate_date(row["last_validated"], context)


def validate_browser_extension_history(rows: list[dict[str, str]]) -> None:
    allowed_statuses = {
        "catalog_baseline",
        "verified_official_listing",
        "reachable_id_confirmed",
        "redirected_id_review_required",
        "unreachable",
        "unconfirmed",
    }
    seen: set[tuple[str, str]] = set()
    for row in rows:
        context = f"{row['observed_on']}:{row['extension_id']}"
        validate_date(row["observed_on"], context)
        if not CHROMIUM_EXTENSION_ID_RE.fullmatch(row["extension_id"]):
            raise ValidationError(f"{context}: invalid Chromium extension_id")
        key = (row["observed_on"], row["extension_id"])
        if key in seen:
            raise ValidationError(f"{context}: duplicate daily history observation")
        seen.add(key)
        if row["verification_status"] not in allowed_statuses:
            raise ValidationError(f"{context}: unsupported verification_status")
        validate_source_url(row["source_url"], context)
        if row["observed_url"]:
            validate_source_url(row["observed_url"], context)
        if row["http_status"] and (not row["http_status"].isdigit() or not 100 <= int(row["http_status"]) <= 599):
            raise ValidationError(f"{context}: invalid http_status")


def validate_specs() -> list[dict[str, object]]:
    specs: list[dict[str, object]] = []
    ids: set[str] = set()
    for path in sorted(SPECS_DIR.glob("*.json")):
        with path.open("r", encoding="utf-8") as handle:
            spec = json.load(handle)
        missing = SPEC_REQUIRED - set(spec)
        if missing:
            raise ValidationError(f"{path}: missing fields {sorted(missing)}")
        spec_id = str(spec["id"])
        if not SPEC_ID_RE.fullmatch(spec_id) or spec_id in ids:
            raise ValidationError(f"{path}: invalid or duplicate detection id")
        ids.add(spec_id)
        if spec["status"] not in {"draft", "hunting", "candidate", "production", "retired"}:
            raise ValidationError(f"{path}: unsupported status")
        if spec["confidence"] not in {"low", "medium", "high"}:
            raise ValidationError(f"{path}: unsupported confidence")
        if not isinstance(spec["evidence_level"], int) or not 1 <= spec["evidence_level"] <= 5:
            raise ValidationError(f"{path}: evidence_level must be 1 through 5")
        if not spec["limitations"]:
            raise ValidationError(f"{path}: at least one limitation is required")
        specs.append(spec)
    if not specs:
        raise ValidationError("no detection specifications found")
    return specs


def kql_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def kql_dynamic(name: str, values: list[str]) -> str:
    rendered = ", ".join(kql_quote(value) for value in sorted(set(values), key=str.lower))
    return f"let {name} = dynamic([{rendered}]);"


def build_tokens(
    domains: list[dict[str, str]],
    artifacts: list[dict[str, str]],
    browser_extensions: list[dict[str, str]],
    browser_extension_names: list[dict[str, str]],
) -> dict[str, str]:
    domain_values = [row["indicator"] for row in domains]
    catalog_rows = []
    for row in sorted(domains, key=lambda item: item["indicator"]):
        catalog_rows.append(
            ", ".join(
                kql_quote(row[field])
                for field in ("indicator", "provider_id", "provider_name", "product_name", "capability", "channel")
            )
        )
    catalog_kql = (
        "let ShadowAI_Catalog = datatable("
        "MatchedDomain:string, ProviderId:string, ProviderName:string, ProductName:string, "
        "Capability:string, Channel:string)[\n    "
        + ",\n    ".join(catalog_rows)
        + "\n];\n"
        + kql_dynamic("ShadowAI_Domains", domain_values)
    )

    def patterns(artifact_type: str, match_mode: str | None = None) -> list[str]:
        return [
            row["pattern"]
            for row in artifacts
            if row["artifact_type"] == artifact_type and (match_mode is None or row["match_mode"] == match_mode)
        ]

    model_suffixes = patterns("model_file", "suffix")
    model_predicate = " or ".join(f"tolower(FileName) endswith {kql_quote(value.lower())}" for value in model_suffixes)
    collector_fields = (
        "artifact_id",
        "provider_id",
        "artifact_type",
        "platform",
        "pattern",
        "match_mode",
        "capability",
        "confidence",
    )
    collector_catalog = [
        {field: row[field] for field in collector_fields}
        for row in sorted(artifacts, key=lambda item: item["artifact_id"])
    ]
    browser_catalog = [
        {
            "extension_id": row["extension_id"],
            "provider_id": row["provider_id"],
            "browser": row["browser"],
            "extension_name": row["extension_name"],
        }
        for row in sorted(browser_extensions, key=lambda item: item["extension_id"])
    ]
    browser_name_catalog = [
        {
            "pattern": row["pattern"],
            "provider_id": row["provider_id"],
            "confidence": row["confidence"],
        }
        for row in sorted(browser_extension_names, key=lambda item: (-len(item["pattern"]), item["pattern"].casefold()))
    ]
    domain_collector_catalog = [
        {
            "artifact_id": row["indicator_id"],
            "provider_id": row["provider_id"],
            "capability": row["capability"],
            "confidence": "low",
            "domain": row["indicator"],
            "indicator_type": row["indicator_type"],
        }
        for row in sorted(domains, key=lambda item: item["indicator_id"])
    ]
    return {
        "{{AI_CATALOG_KQL}}": catalog_kql,
        "{{AI_DOMAIN_ARRAY_KQL}}": kql_dynamic("ShadowAI_Domains", domain_values),
        "{{LOCAL_PROCESS_EXACT_KQL}}": kql_dynamic(
            "LocalAI_ProcessExact", [value.lower() for value in patterns("process", "exact")]
        ),
        "{{LOCAL_PROCESS_CONTAINS_KQL}}": kql_dynamic("LocalAI_ProcessContains", patterns("process", "contains")),
        "{{LOCAL_COMMAND_KQL}}": kql_dynamic("LocalAI_CommandPatterns", patterns("command_line", "contains")),
        "{{MODEL_SUFFIX_PREDICATE_KQL}}": model_predicate,
        "{{MCP_COMMAND_KQL}}": kql_dynamic(
            "MCP_CommandPatterns",
            [row["pattern"] for row in artifacts if row["artifact_id"].startswith("cmd-mcp-")],
        ),
        "{{MCP_CONFIG_KQL}}": kql_dynamic(
            "MCP_ConfigFiles",
            [row["pattern"] for row in artifacts if row["artifact_id"].startswith("file-mcp-")],
        ),
        "{{ENDPOINT_CATALOG_JSON}}": json.dumps(collector_catalog, indent=2, sort_keys=True),
        "{{BROWSER_EXTENSION_CATALOG_JSON}}": json.dumps(browser_catalog, indent=2, sort_keys=True),
        "{{BROWSER_EXTENSION_NAME_CATALOG_JSON}}": json.dumps(browser_name_catalog, indent=2, sort_keys=True),
        "{{DOMAIN_CATALOG_JSON}}": json.dumps(domain_collector_catalog, indent=2, sort_keys=True),
    }


def safe_write(relative_path: Path, content: str) -> None:
    if DIST_DIR.is_symlink():
        raise ValidationError("dist directory must not be a symbolic link")
    destination = (DIST_DIR / relative_path).resolve()
    destination.relative_to(DIST_DIR.resolve())
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=destination.parent, delete=False) as handle:
        handle.write(content)
        temp_name = handle.name
    os.replace(temp_name, destination)


def render_templates(tokens: dict[str, str]) -> list[Path]:
    rendered_paths: list[Path] = []
    platforms = {
        "microsoft-defender": "*.kql.tmpl",
        "microsoft-sentinel": "*.kql.tmpl",
        "rmm-macos-linux": "*.tmpl",
        "rmm-windows": "*.tmpl",
    }
    for platform, template_glob in platforms.items():
        for template in sorted((TEMPLATES_DIR / platform).glob(template_glob)):
            content = template.read_text(encoding="utf-8")
            for token, replacement in tokens.items():
                content = content.replace(token, replacement)
            unresolved = re.findall(r"\{\{[A-Z0-9_]+\}\}", content)
            if unresolved:
                raise ValidationError(f"{template}: unresolved tokens {unresolved}")
            if platform == "microsoft-defender":
                for forbidden in FORBIDDEN_MDE_TERMS:
                    if forbidden in content:
                        raise ValidationError(f"{template}: forbidden MDE assumption {forbidden}")
            relative = Path(platform) / template.name.removesuffix(".tmpl")
            safe_write(relative, content)
            rendered_paths.append(relative)
    return rendered_paths


def build_watchlist(domains: list[dict[str, str]]) -> Path:
    relative = Path("watchlists") / "shadow_ai_domains.csv"
    fieldnames = [
        "SearchKey",
        "ProviderId",
        "ProviderName",
        "ProductName",
        "Capability",
        "Channel",
        "IndicatorType",
        "SourceUrl",
        "LastValidated",
    ]
    output = []
    output.append(",".join(fieldnames))
    for row in sorted(domains, key=lambda item: item["indicator"]):
        values = [
            row["indicator"],
            row["provider_id"],
            row["provider_name"],
            row["product_name"],
            row["capability"],
            row["channel"],
            row["indicator_type"],
            row["source_url"],
            row["last_validated"],
        ]
        if any("," in value or '"' in value or "\n" in value for value in values):
            raise ValidationError(f"watchlist row requires CSV quoting: {row['indicator_id']}")
        output.append(",".join(values))
    safe_write(relative, "\n".join(output) + "\n")
    return relative


def build_manifest(paths: list[Path], specs: list[dict[str, object]]) -> None:
    files = []
    for relative in sorted(paths):
        payload = (DIST_DIR / relative).read_bytes()
        files.append({"path": relative.as_posix(), "sha256": hashlib.sha256(payload).hexdigest()})
    manifest = {
        "generated_on": date.today().isoformat(),
        "detection_count": len(specs),
        "files": files,
    }
    safe_write(Path("manifest.json"), json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def main() -> int:
    domains = read_csv(CATALOG_DIR / "providers.csv", DOMAIN_REQUIRED)
    artifacts = read_csv(CATALOG_DIR / "endpoint_artifacts.csv", ARTIFACT_REQUIRED)
    browser_extensions = read_csv(CATALOG_DIR / "browser_extensions.csv", BROWSER_EXTENSION_REQUIRED)
    browser_extension_names = read_csv(
        CATALOG_DIR / "browser_extension_name_patterns.csv", BROWSER_EXTENSION_NAME_REQUIRED
    )
    browser_extension_history = read_csv(
        CATALOG_DIR / "browser_extension_history.csv", BROWSER_EXTENSION_HISTORY_REQUIRED
    )
    validate_domains(domains)
    validate_artifacts(artifacts)
    validate_browser_extensions(browser_extensions)
    validate_browser_extension_names(browser_extension_names)
    validate_browser_extension_history(browser_extension_history)
    specs = validate_specs()
    tokens = build_tokens(domains, artifacts, browser_extensions, browser_extension_names)
    paths = render_templates(tokens)
    paths.append(build_watchlist(domains))
    safe_write(Path("catalog") / "ai_domains.txt", "\n".join(sorted(row["indicator"] for row in domains)) + "\n")
    paths.append(Path("catalog") / "ai_domains.txt")
    safe_write(
        Path("catalog") / "browser_extension_history.csv",
        (CATALOG_DIR / "browser_extension_history.csv").read_text(encoding="utf-8"),
    )
    paths.append(Path("catalog") / "browser_extension_history.csv")
    build_manifest(paths, specs)
    print(
        f"Validated {len(domains)} network indicators, {len(artifacts)} endpoint artifacts, "
        f"{len(browser_extensions)} browser extensions, {len(browser_extension_names)} extension name patterns, "
        f"{len(browser_extension_history)} extension history observations, "
        f"and {len(specs)} detections."
    )
    print(f"Built {len(paths)} artifacts under {DIST_DIR}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
