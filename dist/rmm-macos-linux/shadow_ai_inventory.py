#!/usr/bin/env python3
"""Read-only Shadow AI inventory collector for macOS and Linux.

The collector emits metadata only. It never emits command lines, environment
values, prompts, responses, file contents, or configuration contents.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import socket
import stat
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


COLLECTOR_NAME = "shadow-ai-rmm-macos-linux"
COLLECTOR_VERSION = "0.2.0"
MAX_FINDINGS = 5000
MAX_HOMES = 256
MAX_PROCESS_BYTES = 65536
EXTENSION_ID_RE = re.compile(r"^[a-p]{32}$")
CATALOG = [
  {
    "artifact_id": "cmd-mcp-001",
    "artifact_type": "command_line",
    "capability": "mcp_server",
    "confidence": "high",
    "match_mode": "contains",
    "pattern": "@modelcontextprotocol",
    "platform": "any",
    "provider_id": "mcp"
  },
  {
    "artifact_id": "cmd-mcp-002",
    "artifact_type": "command_line",
    "capability": "mcp_server",
    "confidence": "medium",
    "match_mode": "contains",
    "pattern": "mcp-server",
    "platform": "any",
    "provider_id": "mcp"
  },
  {
    "artifact_id": "cmd-mcp-003",
    "artifact_type": "command_line",
    "capability": "mcp_server",
    "confidence": "high",
    "match_mode": "contains",
    "pattern": "fastmcp",
    "platform": "any",
    "provider_id": "mcp"
  },
  {
    "artifact_id": "env-anthropic-001",
    "artifact_type": "environment_variable_name",
    "capability": "api_credential_name",
    "confidence": "medium",
    "match_mode": "exact",
    "pattern": "ANTHROPIC_API_KEY",
    "platform": "any",
    "provider_id": "anthropic"
  },
  {
    "artifact_id": "env-google-001",
    "artifact_type": "environment_variable_name",
    "capability": "api_credential_name",
    "confidence": "low",
    "match_mode": "exact",
    "pattern": "GOOGLE_API_KEY",
    "platform": "any",
    "provider_id": "google"
  },
  {
    "artifact_id": "env-openai-001",
    "artifact_type": "environment_variable_name",
    "capability": "api_credential_name",
    "confidence": "medium",
    "match_mode": "exact",
    "pattern": "OPENAI_API_KEY",
    "platform": "any",
    "provider_id": "openai"
  },
  {
    "artifact_id": "file-mcp-001",
    "artifact_type": "config_file",
    "capability": "mcp_configuration",
    "confidence": "medium",
    "match_mode": "exact",
    "pattern": "mcp.json",
    "platform": "any",
    "provider_id": "mcp"
  },
  {
    "artifact_id": "file-mcp-002",
    "artifact_type": "config_file",
    "capability": "mcp_configuration",
    "confidence": "high",
    "match_mode": "exact",
    "pattern": "claude_desktop_config.json",
    "platform": "any",
    "provider_id": "mcp"
  },
  {
    "artifact_id": "file-mcp-003",
    "artifact_type": "config_file",
    "capability": "mcp_configuration",
    "confidence": "medium",
    "match_mode": "exact",
    "pattern": ".mcp.json",
    "platform": "any",
    "provider_id": "mcp"
  },
  {
    "artifact_id": "file-model-001",
    "artifact_type": "model_file",
    "capability": "model_weight",
    "confidence": "high",
    "match_mode": "suffix",
    "pattern": ".gguf",
    "platform": "any",
    "provider_id": "generic"
  },
  {
    "artifact_id": "file-model-002",
    "artifact_type": "model_file",
    "capability": "model_weight",
    "confidence": "high",
    "match_mode": "suffix",
    "pattern": ".ggml",
    "platform": "any",
    "provider_id": "generic"
  },
  {
    "artifact_id": "proc-gpt4all-001",
    "artifact_type": "process",
    "capability": "local_model_runtime",
    "confidence": "medium",
    "match_mode": "contains",
    "pattern": "gpt4all",
    "platform": "any",
    "provider_id": "gpt4all"
  },
  {
    "artifact_id": "proc-jan-001",
    "artifact_type": "process",
    "capability": "local_model_runtime",
    "confidence": "medium",
    "match_mode": "exact",
    "pattern": "jan",
    "platform": "any",
    "provider_id": "jan"
  },
  {
    "artifact_id": "proc-kobold-001",
    "artifact_type": "process",
    "capability": "local_model_runtime",
    "confidence": "high",
    "match_mode": "contains",
    "pattern": "koboldcpp",
    "platform": "any",
    "provider_id": "koboldcpp"
  },
  {
    "artifact_id": "proc-llamacpp-001",
    "artifact_type": "process",
    "capability": "local_model_runtime",
    "confidence": "high",
    "match_mode": "exact",
    "pattern": "llama-server",
    "platform": "any",
    "provider_id": "llamacpp"
  },
  {
    "artifact_id": "proc-llamacpp-002",
    "artifact_type": "process",
    "capability": "local_model_runtime",
    "confidence": "high",
    "match_mode": "exact",
    "pattern": "llama-cli",
    "platform": "any",
    "provider_id": "llamacpp"
  },
  {
    "artifact_id": "proc-lmstudio-001",
    "artifact_type": "process",
    "capability": "local_model_runtime",
    "confidence": "high",
    "match_mode": "exact",
    "pattern": "LM Studio.exe",
    "platform": "windows",
    "provider_id": "lmstudio"
  },
  {
    "artifact_id": "proc-localai-001",
    "artifact_type": "process",
    "capability": "local_model_runtime",
    "confidence": "medium",
    "match_mode": "contains",
    "pattern": "local-ai",
    "platform": "any",
    "provider_id": "localai"
  },
  {
    "artifact_id": "proc-ollama-001",
    "artifact_type": "process",
    "capability": "local_model_runtime",
    "confidence": "high",
    "match_mode": "exact",
    "pattern": "ollama",
    "platform": "any",
    "provider_id": "ollama"
  },
  {
    "artifact_id": "proc-vllm-001",
    "artifact_type": "command_line",
    "capability": "local_model_runtime",
    "confidence": "high",
    "match_mode": "contains",
    "pattern": "vllm.entrypoints",
    "platform": "any",
    "provider_id": "vllm"
  }
]
BROWSER_EXTENSION_CATALOG = [
  {
    "browser": "chromium-family",
    "extension_id": "camppjleccjaphfdbohjdohecfnoikec",
    "extension_name": "Merlin AI",
    "provider_id": "merlin"
  },
  {
    "browser": "chromium-family",
    "extension_id": "difoiogjjojoaoomphldepapgpbgkhkb",
    "extension_name": "Sider AI",
    "provider_id": "sider"
  },
  {
    "browser": "chromium-family",
    "extension_id": "iidnbdjijdkbmajdffnidomddglmieko",
    "extension_name": "QuillBot AI Writing Assistant",
    "provider_id": "quillbot"
  },
  {
    "browser": "chromium-family",
    "extension_id": "kbfnbcaeplbcioakkpcpgfkobkghlhen",
    "extension_name": "Grammarly AI Writing Assistant",
    "provider_id": "grammarly"
  }
]


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def os_family() -> str:
    system = platform.system().lower()
    return "macos" if system == "darwin" else system if system in {"linux", "windows"} else "unknown"


def new_document() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "observation_id": str(uuid.uuid4()),
        "collected_at": now(),
        "collector": {"name": COLLECTOR_NAME, "version": COLLECTOR_VERSION, "partial": False, "errors": []},
        "device": {
            "hostname": socket.gethostname() or "unknown",
            "os_family": os_family(),
            "os_version": platform.platform(),
            "architecture": platform.machine(),
        },
        "scope": ["processes", "known_paths", "browser_extensions", "installed_software"],
        "safety": {
            "content_collected": False,
            "raw_command_line_collected": False,
            "environment_values_collected": False,
            "network_requests_made": False,
            "full_disk_search_performed": False,
            "symlinks_followed": False,
        },
        "findings": [],
    }


def record_error(document: dict[str, object], operation: str, exc: BaseException) -> None:
    collector = document["collector"]
    assert isinstance(collector, dict)
    errors = collector["errors"]
    assert isinstance(errors, list)
    collector["partial"] = True
    if len(errors) < 100:
        errors.append(f"{operation}:{type(exc).__name__}"[:200])


def add_finding(
    document: dict[str, object], category: str, indicator: dict[str, str], subject_user: str | None, **attributes: object
) -> None:
    findings = document["findings"]
    assert isinstance(findings, list)
    if len(findings) >= MAX_FINDINGS:
        if len(findings) == MAX_FINDINGS:
            record_error(document, "finding_limit", RuntimeError("limit"))
        return
    findings.append(
        {
            "finding_id": str(uuid.uuid4()),
            "observed_at": now(),
            "category": category,
            "indicator_id": indicator["artifact_id"],
            "provider_id": indicator["provider_id"],
            "capability": indicator["capability"],
            "confidence": indicator["confidence"],
            "evidence_level": 3 if category == "process" else 2,
            "subject_user": subject_user,
            "attributes": attributes,
        }
    )


def platform_artifacts(kind: str) -> list[dict[str, str]]:
    family = os_family()
    return [
        item for item in CATALOG
        if item["artifact_type"] == kind and item["platform"] in {"any", family}
    ]


def matches(value: str, item: dict[str, str]) -> bool:
    candidate = value.casefold()
    pattern = item["pattern"].casefold()
    if item["match_mode"] == "exact":
        return candidate == pattern
    if item["match_mode"] == "contains":
        return pattern in candidate
    return candidate.endswith(pattern)


def safe_exists(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
        return not stat.S_ISLNK(mode)
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return False


def tokenize_path(path: Path, home: Path | None) -> str:
    if home is not None:
        try:
            return "{user_home}/" + path.relative_to(home).as_posix()
        except ValueError:
            pass
    return path.as_posix()


def discover_homes(document: dict[str, object]) -> list[tuple[str, Path]]:
    homes: list[tuple[str, Path]] = []
    root = Path("/Users") if os_family() == "macos" else Path("/home")
    try:
        if safe_exists(root):
            for child in sorted(root.iterdir(), key=lambda item: item.name.casefold())[:MAX_HOMES]:
                if child.name not in {"Shared", "Guest"} and safe_exists(child) and child.is_dir():
                    homes.append((child.name, child))
    except OSError as exc:
        record_error(document, "home_enumeration", exc)
    if os_family() == "linux" and safe_exists(Path("/root")):
        homes.append(("root", Path("/root")))
    return homes


def collect_processes(document: dict[str, object]) -> None:
    process_items = platform_artifacts("process")
    argument_items = platform_artifacts("command_line")
    rows: list[tuple[int, str, str]] = []
    try:
        if os_family() == "linux":
            for entry in Path("/proc").iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    name = (entry / "comm").read_text(encoding="utf-8", errors="replace")[:4096].strip()
                    raw = (entry / "cmdline").read_bytes()[:MAX_PROCESS_BYTES]
                    arguments = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace")
                    rows.append((int(entry.name), name, arguments))
                except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
                    continue
        elif os_family() == "macos":
            result = subprocess.run(
                ["/bin/ps", "-axo", "pid=,comm=,args="],
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
            for line in result.stdout.splitlines():
                parts = line.strip().split(None, 2)
                if len(parts) >= 2 and parts[0].isdigit():
                    rows.append((int(parts[0]), Path(parts[1]).name, parts[2] if len(parts) == 3 else ""))
        else:
            raise RuntimeError("unsupported_platform")
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        record_error(document, "process_inventory", exc)
        return

    seen: set[tuple[int, str]] = set()
    for pid, name, arguments in rows:
        for item in process_items:
            if matches(name, item) and (pid, item["artifact_id"]) not in seen:
                add_finding(document, "process", item, None, pid=pid, process_name=name, match_basis="process_name")
                seen.add((pid, item["artifact_id"]))
        for item in argument_items:
            if matches(arguments, item) and (pid, item["artifact_id"]) not in seen:
                add_finding(document, "process", item, None, pid=pid, process_name=name, match_basis="arguments_local_only")
                seen.add((pid, item["artifact_id"]))


def synthetic(artifact_id: str, provider_id: str, capability: str, confidence: str = "medium") -> dict[str, str]:
    return {
        "artifact_id": artifact_id,
        "provider_id": provider_id,
        "capability": capability,
        "confidence": confidence,
    }


def collect_known_paths(document: dict[str, object], homes: list[tuple[str, Path]]) -> None:
    model_indicator = next(item for item in CATALOG if item["artifact_id"] == "file-model-001")
    mcp_by_name = {
        item["pattern"].casefold(): item for item in CATALOG if item["artifact_type"] == "config_file"
    }
    relative_paths = [
        (Path(".ollama/models"), "model_directory", model_indicator),
        (Path(".cache/lm-studio/models"), "model_directory", model_indicator),
        (Path(".lmstudio/models"), "model_directory", model_indicator),
        (Path(".cursor/mcp.json"), "config_file", mcp_by_name["mcp.json"]),
        (Path(".mcp.json"), "config_file", mcp_by_name[".mcp.json"]),
        (Path(".config/Claude/claude_desktop_config.json"), "config_file", mcp_by_name["claude_desktop_config.json"]),
    ]
    if os_family() == "macos":
        relative_paths.extend(
            [
                (Path("Library/Application Support/Claude/claude_desktop_config.json"), "config_file", mcp_by_name["claude_desktop_config.json"]),
                (Path("Library/Application Support/Cursor/User/globalStorage/mcp.json"), "config_file", mcp_by_name["mcp.json"]),
                (Path("Library/Application Support/LM Studio/models"), "model_directory", model_indicator),
            ]
        )
    for user, home in homes:
        for relative, category, indicator in relative_paths:
            candidate = home / relative
            if safe_exists(candidate):
                add_finding(document, category, indicator, user, location=tokenize_path(candidate, home), presence_only=True)

    software_paths: list[tuple[Path, dict[str, str]]] = []
    if os_family() == "macos":
        software_paths = [
            (Path("/Applications/Ollama.app"), synthetic("software-ollama", "ollama", "local_model_runtime", "high")),
            (Path("/Applications/LM Studio.app"), synthetic("software-lmstudio", "lmstudio", "local_model_runtime", "high")),
            (Path("/Applications/ChatGPT.app"), synthetic("software-chatgpt", "openai", "generative_ai_client")),
            (Path("/Applications/Claude.app"), synthetic("software-claude", "anthropic", "generative_ai_client")),
            (Path("/Applications/Cursor.app"), synthetic("software-cursor", "cursor", "ai_coding_assistant")),
            (Path("/Applications/Windsurf.app"), synthetic("software-windsurf", "windsurf", "ai_coding_assistant")),
        ]
    elif os_family() == "linux":
        for item in platform_artifacts("process"):
            for root in (Path("/usr/bin"), Path("/usr/local/bin")):
                software_paths.append((root / item["pattern"], item))
    for path, indicator in software_paths:
        if safe_exists(path):
            add_finding(document, "software", indicator, None, location=tokenize_path(path, None), presence_only=True)


def collect_browser_extensions(document: dict[str, object], homes: list[tuple[str, Path]]) -> None:
    known_extensions = {item["extension_id"]: item for item in BROWSER_EXTENSION_CATALOG}
    roots_by_family = {
        "macos": [
            ("chrome", Path("Library/Application Support/Google/Chrome")),
            ("edge", Path("Library/Application Support/Microsoft Edge")),
            ("brave", Path("Library/Application Support/BraveSoftware/Brave-Browser")),
        ],
        "linux": [
            ("chrome", Path(".config/google-chrome")),
            ("chromium", Path(".config/chromium")),
            ("edge", Path(".config/microsoft-edge")),
            ("brave", Path(".config/BraveSoftware/Brave-Browser")),
        ],
    }
    for user, home in homes:
        for browser, relative_root in roots_by_family.get(os_family(), []):
            root = home / relative_root
            try:
                if not safe_exists(root):
                    continue
                profiles = [item for item in root.iterdir() if safe_exists(item) and item.is_dir()]
                for profile in sorted(profiles, key=lambda item: item.name.casefold())[:128]:
                    extension_root = profile / "Extensions"
                    if not safe_exists(extension_root):
                        continue
                    for extension in sorted(extension_root.iterdir(), key=lambda item: item.name)[:1000]:
                        catalog_item = known_extensions.get(extension.name)
                        if (
                            catalog_item
                            and catalog_item["browser"] in {browser, "chromium-family"}
                            and EXTENSION_ID_RE.fullmatch(extension.name)
                            and safe_exists(extension)
                            and extension.is_dir()
                        ):
                            indicator = synthetic(
                                "browser-" + extension.name,
                                catalog_item["provider_id"],
                                "ai_browser_extension",
                                "high",
                            )
                            add_finding(
                                document,
                                "browser_extension",
                                indicator,
                                user,
                                browser=browser,
                                profile=profile.name,
                                extension_id=extension.name,
                                extension_name=catalog_item["extension_name"],
                            )
            except OSError as exc:
                record_error(document, f"browser_inventory_{browser}", exc)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="emit an empty conformant document without scanning")
    args = parser.parse_args()
    document = new_document()
    if not args.self_test:
        if os_family() not in {"macos", "linux"}:
            record_error(document, "platform", RuntimeError("unsupported"))
        else:
            homes = discover_homes(document)
            collect_processes(document)
            collect_known_paths(document, homes)
            collect_browser_extensions(document, homes)
    print(json.dumps(document, separators=(",", ":"), sort_keys=True))
    collector = document["collector"]
    assert isinstance(collector, dict)
    return 2 if collector["partial"] else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # fail closed with no endpoint data in the error
        print(json.dumps({"error": f"fatal:{type(exc).__name__}"}, separators=(",", ":")), file=sys.stderr)
        raise SystemExit(1)
