#!/usr/bin/env python3
"""Read-only Shadow AI inventory collector for macOS and Linux.

The collector emits metadata only. Command lines and bounded browser-history
databases are evaluated locally. It never emits raw command lines, URLs, page
titles, environment values, prompts, responses, or configuration contents.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import socket
import sqlite3
import stat
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


COLLECTOR_NAME = "shadow-ai-rmm-macos-linux"
COLLECTOR_VERSION = "0.6.3"
MAX_FINDINGS = 5000
MAX_HOMES = 256
MAX_PROCESS_BYTES = 65536
MAX_HISTORY_BYTES_PER_PROFILE = 268435456
MAX_HISTORY_ROWS_PER_PROFILE = 1000000
MAX_MANIFEST_BYTES = 1048576
MAX_BROWSER_PREFERENCE_BYTES = 16777216
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
    "extension_id": "ejcfepkfckglbgocfkanmcdngdijcgld",
    "extension_name": "ChatGPT search",
    "provider_id": "openai"
  },
  {
    "browser": "chromium-family",
    "extension_id": "fcoeoabgfenejglbffodgkkbkcdhcgfn",
    "extension_name": "Claude",
    "provider_id": "anthropic"
  },
  {
    "browser": "chromium-family",
    "extension_id": "hehggadaopoacecdllhhajmbjkdcmajg",
    "extension_name": "ChatGPT",
    "provider_id": "openai"
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
BROWSER_EXTENSION_NAME_CATALOG = [
  {
    "confidence": "medium",
    "pattern": "Microsoft Copilot",
    "provider_id": "microsoft"
  },
  {
    "confidence": "medium",
    "pattern": "GitHub Copilot",
    "provider_id": "github"
  },
  {
    "confidence": "medium",
    "pattern": "Character.AI",
    "provider_id": "characterai"
  },
  {
    "confidence": "medium",
    "pattern": "Blackbox AI",
    "provider_id": "blackbox"
  },
  {
    "confidence": "medium",
    "pattern": "Compose AI",
    "provider_id": "compose-ai"
  },
  {
    "confidence": "medium",
    "pattern": "Perplexity",
    "provider_id": "perplexity"
  },
  {
    "confidence": "medium",
    "pattern": "Writesonic",
    "provider_id": "writesonic"
  },
  {
    "confidence": "medium",
    "pattern": "ChatSonic",
    "provider_id": "writesonic"
  },
  {
    "confidence": "medium",
    "pattern": "Consensus",
    "provider_id": "consensus"
  },
  {
    "confidence": "medium",
    "pattern": "Grammarly",
    "provider_id": "grammarly"
  },
  {
    "confidence": "medium",
    "pattern": "Amazon Q",
    "provider_id": "amazon"
  },
  {
    "confidence": "medium",
    "pattern": "DeepSeek",
    "provider_id": "deepseek"
  },
  {
    "confidence": "medium",
    "pattern": "QuillBot",
    "provider_id": "quillbot"
  },
  {
    "confidence": "medium",
    "pattern": "SciSpace",
    "provider_id": "scispace"
  },
  {
    "confidence": "medium",
    "pattern": "Windsurf",
    "provider_id": "windsurf"
  },
  {
    "confidence": "medium",
    "pattern": "ChatGPT",
    "provider_id": "openai"
  },
  {
    "confidence": "medium",
    "pattern": "Codeium",
    "provider_id": "codeium"
  },
  {
    "confidence": "medium",
    "pattern": "Mistral",
    "provider_id": "mistral"
  },
  {
    "confidence": "medium",
    "pattern": "Tabnine",
    "provider_id": "tabnine"
  },
  {
    "confidence": "medium",
    "pattern": "Claude",
    "provider_id": "anthropic"
  },
  {
    "confidence": "medium",
    "pattern": "Gemini",
    "provider_id": "google"
  },
  {
    "confidence": "medium",
    "pattern": "Jasper",
    "provider_id": "jasper"
  },
  {
    "confidence": "medium",
    "pattern": "Merlin",
    "provider_id": "merlin"
  },
  {
    "confidence": "medium",
    "pattern": "Monica",
    "provider_id": "monica"
  },
  {
    "confidence": "medium",
    "pattern": "OpenAI",
    "provider_id": "openai"
  },
  {
    "confidence": "medium",
    "pattern": "HARPA",
    "provider_id": "harpa"
  },
  {
    "confidence": "medium",
    "pattern": "MaxAI",
    "provider_id": "maxai"
  },
  {
    "confidence": "medium",
    "pattern": "Phind",
    "provider_id": "phind"
  },
  {
    "confidence": "medium",
    "pattern": "Sider",
    "provider_id": "sider"
  },
  {
    "confidence": "medium",
    "pattern": "Grok",
    "provider_id": "xai"
  }
]
DOMAIN_CATALOG = [
  {
    "artifact_id": "net-anthropic-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "claude.ai",
    "indicator_type": "registered_domain",
    "provider_id": "anthropic"
  },
  {
    "artifact_id": "net-anthropic-002",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "anthropic.com",
    "indicator_type": "registered_domain",
    "provider_id": "anthropic"
  },
  {
    "artifact_id": "net-character-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "character.ai",
    "indicator_type": "registered_domain",
    "provider_id": "characterai"
  },
  {
    "artifact_id": "net-codeium-001",
    "capability": "code_assistant",
    "confidence": "low",
    "domain": "codeium.com",
    "indicator_type": "registered_domain",
    "provider_id": "codeium"
  },
  {
    "artifact_id": "net-cohere-001",
    "capability": "model_provider",
    "confidence": "low",
    "domain": "cohere.com",
    "indicator_type": "registered_domain",
    "provider_id": "cohere"
  },
  {
    "artifact_id": "net-cohere-002",
    "capability": "model_provider",
    "confidence": "low",
    "domain": "cohere.ai",
    "indicator_type": "registered_domain",
    "provider_id": "cohere"
  },
  {
    "artifact_id": "net-cursor-001",
    "capability": "code_assistant",
    "confidence": "low",
    "domain": "cursor.com",
    "indicator_type": "registered_domain",
    "provider_id": "cursor"
  },
  {
    "artifact_id": "net-cursor-002",
    "capability": "code_assistant",
    "confidence": "low",
    "domain": "cursor.sh",
    "indicator_type": "registered_domain",
    "provider_id": "cursor"
  },
  {
    "artifact_id": "net-deepseek-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "deepseek.com",
    "indicator_type": "registered_domain",
    "provider_id": "deepseek"
  },
  {
    "artifact_id": "net-elevenlabs-001",
    "capability": "audio_generation",
    "confidence": "low",
    "domain": "elevenlabs.io",
    "indicator_type": "registered_domain",
    "provider_id": "elevenlabs"
  },
  {
    "artifact_id": "net-github-001",
    "capability": "code_assistant",
    "confidence": "low",
    "domain": "githubcopilot.com",
    "indicator_type": "registered_domain",
    "provider_id": "github"
  },
  {
    "artifact_id": "net-google-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "gemini.google.com",
    "indicator_type": "fqdn",
    "provider_id": "google"
  },
  {
    "artifact_id": "net-google-002",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "aistudio.google.com",
    "indicator_type": "fqdn",
    "provider_id": "google"
  },
  {
    "artifact_id": "net-google-003",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "generativelanguage.googleapis.com",
    "indicator_type": "fqdn",
    "provider_id": "google"
  },
  {
    "artifact_id": "net-groq-001",
    "capability": "model_provider",
    "confidence": "low",
    "domain": "groq.com",
    "indicator_type": "registered_domain",
    "provider_id": "groq"
  },
  {
    "artifact_id": "net-huggingface-001",
    "capability": "model_platform",
    "confidence": "low",
    "domain": "huggingface.co",
    "indicator_type": "registered_domain",
    "provider_id": "huggingface"
  },
  {
    "artifact_id": "net-lmstudio-001",
    "capability": "local_model_tooling",
    "confidence": "low",
    "domain": "lmstudio.ai",
    "indicator_type": "registered_domain",
    "provider_id": "lmstudio"
  },
  {
    "artifact_id": "net-meta-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "meta.ai",
    "indicator_type": "registered_domain",
    "provider_id": "meta"
  },
  {
    "artifact_id": "net-microsoft-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "copilot.microsoft.com",
    "indicator_type": "fqdn",
    "provider_id": "microsoft"
  },
  {
    "artifact_id": "net-midjourney-001",
    "capability": "image_generation",
    "confidence": "low",
    "domain": "midjourney.com",
    "indicator_type": "registered_domain",
    "provider_id": "midjourney"
  },
  {
    "artifact_id": "net-mistral-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "mistral.ai",
    "indicator_type": "registered_domain",
    "provider_id": "mistral"
  },
  {
    "artifact_id": "net-ollama-001",
    "capability": "local_model_tooling",
    "confidence": "low",
    "domain": "ollama.com",
    "indicator_type": "registered_domain",
    "provider_id": "ollama"
  },
  {
    "artifact_id": "net-openai-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "openai.com",
    "indicator_type": "registered_domain",
    "provider_id": "openai"
  },
  {
    "artifact_id": "net-openai-002",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "chatgpt.com",
    "indicator_type": "registered_domain",
    "provider_id": "openai"
  },
  {
    "artifact_id": "net-openai-003",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "oaiusercontent.com",
    "indicator_type": "registered_domain",
    "provider_id": "openai"
  },
  {
    "artifact_id": "net-openrouter-001",
    "capability": "model_gateway",
    "confidence": "low",
    "domain": "openrouter.ai",
    "indicator_type": "registered_domain",
    "provider_id": "openrouter"
  },
  {
    "artifact_id": "net-perplexity-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "perplexity.ai",
    "indicator_type": "registered_domain",
    "provider_id": "perplexity"
  },
  {
    "artifact_id": "net-poe-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "poe.com",
    "indicator_type": "registered_domain",
    "provider_id": "poe"
  },
  {
    "artifact_id": "net-replicate-001",
    "capability": "model_platform",
    "confidence": "low",
    "domain": "replicate.com",
    "indicator_type": "registered_domain",
    "provider_id": "replicate"
  },
  {
    "artifact_id": "net-runway-001",
    "capability": "video_generation",
    "confidence": "low",
    "domain": "runwayml.com",
    "indicator_type": "registered_domain",
    "provider_id": "runway"
  },
  {
    "artifact_id": "net-stability-001",
    "capability": "image_generation",
    "confidence": "low",
    "domain": "stability.ai",
    "indicator_type": "registered_domain",
    "provider_id": "stability"
  },
  {
    "artifact_id": "net-together-001",
    "capability": "model_provider",
    "confidence": "low",
    "domain": "together.ai",
    "indicator_type": "registered_domain",
    "provider_id": "together"
  },
  {
    "artifact_id": "net-together-002",
    "capability": "model_provider",
    "confidence": "low",
    "domain": "together.xyz",
    "indicator_type": "registered_domain",
    "provider_id": "together"
  },
  {
    "artifact_id": "net-windsurf-001",
    "capability": "code_assistant",
    "confidence": "low",
    "domain": "windsurf.com",
    "indicator_type": "registered_domain",
    "provider_id": "windsurf"
  },
  {
    "artifact_id": "net-xai-001",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "x.ai",
    "indicator_type": "registered_domain",
    "provider_id": "xai"
  },
  {
    "artifact_id": "net-xai-002",
    "capability": "generative_ai",
    "confidence": "low",
    "domain": "grok.com",
    "indicator_type": "registered_domain",
    "provider_id": "xai"
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
        "scope": ["processes", "known_paths", "browser_extensions", "browser_history", "installed_software"],
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
            "evidence_level": 3 if category == "process" else 1 if category == "browser_history" else 2,
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


def read_bounded_json(path: Path, max_bytes: int = MAX_MANIFEST_BYTES) -> object | None:
    try:
        if not safe_exists(path) or not path.is_file() or path.stat().st_size > max_bytes:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


def safe_extension_name(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    name = value.strip()
    if not name or len(name) > 200 or any(ord(character) < 32 or ord(character) == 127 for character in name):
        return None
    return name


def resolve_chromium_extension_name(extension: Path) -> str | None:
    try:
        versions = [item for item in extension.iterdir() if safe_exists(item) and item.is_dir()]
    except OSError:
        return None
    for version in sorted(versions, key=lambda item: item.name, reverse=True)[:8]:
        manifest = read_bounded_json(version / "manifest.json")
        if not isinstance(manifest, dict):
            continue
        name = safe_extension_name(manifest.get("name"))
        if name is None:
            continue
        message_match = re.fullmatch(r"__MSG_([A-Za-z0-9_@]+)__", name)
        if message_match:
            locale = safe_extension_name(manifest.get("default_locale"))
            if locale is None or not re.fullmatch(r"[A-Za-z0-9_-]{2,20}", locale):
                continue
            messages = read_bounded_json(version / "_locales" / locale / "messages.json")
            if not isinstance(messages, dict):
                continue
            message = messages.get(message_match.group(1))
            if not isinstance(message, dict):
                continue
            name = safe_extension_name(message.get("message"))
        if name is not None:
            return name
    return None


def extension_name_classification(extension_name: str | None) -> dict[str, str] | None:
    if extension_name is None:
        return None
    folded = extension_name.casefold()
    return next(
        (item for item in BROWSER_EXTENSION_NAME_CATALOG if item["pattern"].casefold() in folded),
        None,
    )


def resolve_manifest_localized_value(value: object, manifest: dict[str, object], version: Path) -> str | None:
    safe_value = safe_extension_name(value)
    if safe_value is None:
        return None
    message_match = re.fullmatch(r"__MSG_([A-Za-z0-9_@]+)__", safe_value)
    if message_match is None:
        return safe_value
    locale = safe_extension_name(manifest.get("default_locale"))
    if locale is None or not re.fullmatch(r"[A-Za-z0-9_-]{2,20}", locale):
        return None
    messages = read_bounded_json(version / "_locales" / locale / "messages.json")
    if not isinstance(messages, dict):
        return None
    message = messages.get(message_match.group(1))
    if not isinstance(message, dict):
        return None
    return safe_extension_name(message.get("message"))


def manifest_text_classification(extension: Path) -> dict[str, str] | None:
    """Classify locally from manifest text while emitting no description content."""
    try:
        versions = [item for item in extension.iterdir() if safe_exists(item) and item.is_dir()]
    except OSError:
        return None
    for version in sorted(versions, key=lambda item: item.name, reverse=True)[:8]:
        manifest = read_bounded_json(version / "manifest.json")
        if not isinstance(manifest, dict):
            continue
        text_values = [
            resolved
            for key in ("name", "short_name", "description")
            if (resolved := resolve_manifest_localized_value(manifest.get(key), manifest, version)) is not None
        ]
        for action_key in ("action", "browser_action", "page_action"):
            action = manifest.get(action_key)
            if not isinstance(action, dict):
                continue
            resolved = resolve_manifest_localized_value(action.get("default_title"), manifest, version)
            if resolved is not None:
                text_values.append(resolved)
        for value in text_values:
            named = extension_name_classification(value)
            if named:
                return named
        combined = " ".join(text_values)
        if re.search(
            r"(?i)\b(?:gpt(?:-?[0-9]+)?|llm|large language model|generative ai|ai assistant|ai-powered|artificial intelligence)\b",
            combined,
        ):
            return {"provider_id": "generic", "confidence": "low"}
    return None


def manifest_domain_classification(extension: Path) -> dict[str, str] | None:
    """Classify locally from URL access declarations without emitting the manifest."""
    try:
        versions = [item for item in extension.iterdir() if safe_exists(item) and item.is_dir()]
    except OSError:
        return None
    for version in sorted(versions, key=lambda item: item.name, reverse=True)[:8]:
        manifest = read_bounded_json(version / "manifest.json")
        if not isinstance(manifest, dict):
            continue
        access_values: list[str] = []
        for key in ("permissions", "host_permissions", "optional_host_permissions"):
            value = manifest.get(key)
            if isinstance(value, list):
                access_values.extend(item for item in value if isinstance(item, str))
        content_scripts = manifest.get("content_scripts")
        if isinstance(content_scripts, list):
            for script in content_scripts:
                if not isinstance(script, dict):
                    continue
                matches = script.get("matches")
                if isinstance(matches, list):
                    access_values.extend(item for item in matches if isinstance(item, str))
        externally_connectable = manifest.get("externally_connectable")
        if isinstance(externally_connectable, dict):
            matches = externally_connectable.get("matches")
            if isinstance(matches, list):
                access_values.extend(item for item in matches if isinstance(item, str))
        for indicator in DOMAIN_CATALOG:
            escaped = re.escape(indicator["domain"])
            host = rf"(?:[a-z0-9-]+\.)*{escaped}" if indicator["indicator_type"] == "registered_domain" else escaped
            pattern = re.compile(rf"(?i)(?:^|[/:*.]){host}(?:[/:*]|$)")
            if any(pattern.search(value) for value in access_values):
                return indicator
    return None


def add_extension_inventory_summary(
    document: dict[str, object],
    browser: str,
    profile: str,
    user: str,
    installed_count: int,
    classified_count: int,
) -> None:
    if installed_count <= 0:
        return
    add_finding(
        document,
        "browser_extension",
        synthetic("browser-extension-inventory", "generic", "browser_extension_inventory", "low"),
        user,
        browser=browser,
        profile=profile,
        installed_extension_count=installed_count,
        classified_extension_count=classified_count,
        reporting_scope="count_only",
        presence_only=True,
    )


def preference_manifest_classification(manifest: object) -> dict[str, str | None] | None:
    if not isinstance(manifest, dict):
        return None
    text_values: list[str] = []
    for property_name in ("name", "short_name", "description"):
        value = safe_extension_name(manifest.get(property_name))
        if value and not re.fullmatch(r"__MSG_[A-Za-z0-9_@]+__", value):
            text_values.append(value)
    for action_name in ("action", "browser_action", "page_action"):
        action = manifest.get(action_name)
        value = safe_extension_name(action.get("default_title")) if isinstance(action, dict) else None
        if value and not re.fullmatch(r"__MSG_[A-Za-z0-9_@]+__", value):
            text_values.append(value)
    for value in text_values:
        named = extension_name_classification(value)
        if named:
            return {
                "provider_id": named["provider_id"],
                "confidence": named["confidence"],
                "name": value,
                "matched_domain": None,
                "basis": "browser_preferences_manifest_name_local_only",
            }
    if re.search(
        r"(?i)\b(?:gpt(?:-?[0-9]+)?|llm|large language model|generative ai|ai assistant|ai-powered|artificial intelligence)\b",
        " ".join(text_values),
    ):
        return {
            "provider_id": "generic",
            "confidence": "low",
            "name": None,
            "matched_domain": None,
            "basis": "browser_preferences_manifest_text_local_only",
        }
    access_values: list[str] = []
    for property_name in ("permissions", "host_permissions", "optional_host_permissions"):
        values = manifest.get(property_name)
        if isinstance(values, list):
            access_values.extend(value for value in values if isinstance(value, str))
    content_scripts = manifest.get("content_scripts")
    if isinstance(content_scripts, list):
        for content_script in content_scripts:
            matches = content_script.get("matches") if isinstance(content_script, dict) else None
            if isinstance(matches, list):
                access_values.extend(value for value in matches if isinstance(value, str))
    for indicator in DOMAIN_CATALOG:
        escaped = re.escape(indicator["domain"])
        host = rf"(?:[a-z0-9-]+\.)*{escaped}" if indicator["indicator_type"] == "registered_domain" else escaped
        pattern = re.compile(rf"(?i)(?:^|[/:*.]){host}(?:[/:*]|$)")
        if any(pattern.search(value) for value in access_values):
            return {
                "provider_id": indicator["provider_id"],
                "confidence": "medium",
                "name": None,
                "matched_domain": indicator["domain"],
                "basis": "browser_preferences_manifest_domain_local_only",
            }
    return None


def preference_extensions(profile: Path, maximum_entries: int = 1000) -> dict[str, object]:
    matches: dict[str, object] = {}
    for preference_name in ("Preferences", "Secure Preferences"):
        document = read_bounded_json(profile / preference_name, MAX_BROWSER_PREFERENCE_BYTES)
        if not isinstance(document, dict):
            continue
        extensions = document.get("extensions")
        settings = extensions.get("settings") if isinstance(extensions, dict) else None
        if not isinstance(settings, dict):
            continue
        for extension_id, entry in list(settings.items())[:maximum_entries]:
            if not EXTENSION_ID_RE.fullmatch(extension_id) or not isinstance(entry, dict):
                continue
            manifest = entry.get("manifest")
            if extension_id not in matches or isinstance(manifest, dict):
                matches[extension_id] = manifest
    return matches


def collect_chromium_extension_profile(
    document: dict[str, object],
    browser: str,
    profile: Path,
    user: str,
    known_extensions: dict[str, dict[str, str]],
) -> None:
    extension_root = profile / "Extensions"
    extension_paths: dict[str, Path] = {}
    if safe_exists(extension_root):
        extension_paths = {
            extension.name: extension
            for extension in sorted(extension_root.iterdir(), key=lambda item: item.name)[:1000]
            if EXTENSION_ID_RE.fullmatch(extension.name) and safe_exists(extension) and extension.is_dir()
        }
    indexed_extensions = preference_extensions(profile)
    extension_ids = set(extension_paths) | set(indexed_extensions)
    if not extension_ids:
        return
    installed_count = 0
    classified_count = 0
    for extension_id in sorted(extension_ids):
        installed_count += 1
        extension = extension_paths.get(extension_id)
        catalog_item = known_extensions.get(extension_id)
        extension_name: str | None = None
        provider_id: str | None = None
        confidence = "medium"
        classification_basis = "manifest_name_local_only"
        if catalog_item and catalog_item["browser"] in {browser, "chromium-family"}:
            extension_name = catalog_item["extension_name"]
            provider_id = catalog_item["provider_id"]
            confidence = "high" if extension is not None else "medium"
            classification_basis = "catalog_id" if extension is not None else "browser_preferences_catalog_id"
        else:
            if extension is None:
                preference_classification = preference_manifest_classification(indexed_extensions.get(extension_id))
                if preference_classification:
                    attributes: dict[str, object] = {
                        "browser": browser,
                        "profile": profile.name,
                        "extension_id": extension_id,
                        "classification_basis": preference_classification["basis"],
                        "presence_only": True,
                    }
                    if preference_classification["name"] is not None:
                        attributes["extension_name"] = preference_classification["name"]
                    if preference_classification["matched_domain"] is not None:
                        attributes["matched_domain"] = preference_classification["matched_domain"]
                    add_finding(
                        document,
                        "browser_extension",
                        synthetic(
                            "browser-" + extension_id,
                            str(preference_classification["provider_id"]),
                            "ai_browser_extension",
                            str(preference_classification["confidence"]),
                        ),
                        user,
                        **attributes,
                    )
                    classified_count += 1
                continue
            extension_name = resolve_chromium_extension_name(extension)
            classification = extension_name_classification(extension_name)
            if classification:
                provider_id = classification["provider_id"]
                confidence = classification["confidence"]
        matched_domain: str | None = None
        if provider_id is None:
            text_classification = manifest_text_classification(extension)
            if text_classification:
                provider_id = text_classification["provider_id"]
                confidence = text_classification["confidence"]
                classification_basis = "manifest_text_local_only"
        if provider_id is None:
            domain_classification = manifest_domain_classification(extension)
            if domain_classification:
                provider_id = domain_classification["provider_id"]
                confidence = "medium"
                classification_basis = "manifest_domain_local_only"
                matched_domain = domain_classification["domain"]
        if provider_id is None:
            continue
        attributes: dict[str, object] = {
            "browser": browser,
            "profile": profile.name,
            "extension_id": extension_id,
            "classification_basis": classification_basis,
            "presence_only": True,
        }
        if extension_name is not None:
            attributes["extension_name"] = extension_name
        if matched_domain is not None:
            attributes["matched_domain"] = matched_domain
        add_finding(
            document,
            "browser_extension",
            synthetic("browser-" + extension_id, provider_id, "ai_browser_extension", confidence),
            user,
            **attributes,
        )
        classified_count += 1
    add_extension_inventory_summary(
        document, browser, profile.name, user, installed_count, classified_count
    )


def collect_firefox_extension_profile(
    document: dict[str, object], profile: Path, user: str
) -> None:
    extension_document = read_bounded_json(profile / "extensions.json")
    if not isinstance(extension_document, dict):
        return
    addons = extension_document.get("addons")
    if not isinstance(addons, list):
        return
    installed_count = 0
    classified_count = 0
    for addon in addons[:1000]:
        if not isinstance(addon, dict) or str(addon.get("type", "")).casefold() != "extension":
            continue
        if addon.get("isSystem") is True:
            continue
        installed_count += 1
        extension_name = safe_extension_name(addon.get("name"))
        default_locale = addon.get("defaultLocale")
        if isinstance(default_locale, dict):
            extension_name = safe_extension_name(default_locale.get("name")) or extension_name
        classification = extension_name_classification(extension_name)
        if classification is None or extension_name is None:
            continue
        add_finding(
            document,
            "browser_extension",
            synthetic(
                "browser-firefox-name",
                classification["provider_id"],
                "ai_browser_extension",
                classification["confidence"],
            ),
            user,
            browser="firefox",
            profile=profile.name,
            extension_id=safe_extension_name(addon.get("id")),
            extension_name=extension_name,
            classification_basis="extensions_json_name_local_only",
            presence_only=True,
        )
        classified_count += 1
    add_extension_inventory_summary(
        document, "firefox", profile.name, user, installed_count, classified_count
    )


def collect_browser_extensions(document: dict[str, object], homes: list[tuple[str, Path]]) -> None:
    known_extensions = {item["extension_id"]: item for item in BROWSER_EXTENSION_CATALOG}
    roots_by_family = {
        "macos": [
            ("chrome", Path("Library/Application Support/Google/Chrome"), False),
            ("chrome-beta", Path("Library/Application Support/Google/Chrome Beta"), False),
            ("chrome-canary", Path("Library/Application Support/Google/Chrome Canary"), False),
            ("edge", Path("Library/Application Support/Microsoft Edge"), False),
            ("edge-beta", Path("Library/Application Support/Microsoft Edge Beta"), False),
            ("edge-dev", Path("Library/Application Support/Microsoft Edge Dev"), False),
            ("edge-canary", Path("Library/Application Support/Microsoft Edge Canary"), False),
            ("brave", Path("Library/Application Support/BraveSoftware/Brave-Browser"), False),
            ("chromium", Path("Library/Application Support/Chromium"), False),
            ("vivaldi", Path("Library/Application Support/Vivaldi"), False),
            ("arc", Path("Library/Application Support/Arc/User Data"), False),
            ("opera", Path("Library/Application Support/com.operasoftware.Opera"), True),
        ],
        "linux": [
            ("chrome", Path(".config/google-chrome"), False),
            ("chrome-beta", Path(".config/google-chrome-beta"), False),
            ("chrome-dev", Path(".config/google-chrome-unstable"), False),
            ("chromium", Path(".config/chromium"), False),
            ("edge", Path(".config/microsoft-edge"), False),
            ("edge-beta", Path(".config/microsoft-edge-beta"), False),
            ("edge-dev", Path(".config/microsoft-edge-dev"), False),
            ("brave", Path(".config/BraveSoftware/Brave-Browser"), False),
            ("vivaldi", Path(".config/vivaldi"), False),
            ("opera", Path(".config/opera"), True),
        ],
    }
    firefox_roots = {
        "macos": Path("Library/Application Support/Firefox/Profiles"),
        "linux": Path(".mozilla/firefox"),
    }
    for user, home in homes:
        for browser, relative_root, root_is_profile in roots_by_family.get(os_family(), []):
            root = home / relative_root
            try:
                if not safe_exists(root):
                    continue
                profiles = [root] if root_is_profile else [
                    item for item in root.iterdir() if safe_exists(item) and item.is_dir()
                ]
                for profile in sorted(profiles, key=lambda item: item.name.casefold())[:128]:
                    collect_chromium_extension_profile(
                        document, browser, profile, user, known_extensions
                    )
            except OSError as exc:
                record_error(document, f"browser_inventory_{browser}", exc)
        firefox_root = home / firefox_roots[os_family()]
        try:
            if safe_exists(firefox_root):
                profiles = [item for item in firefox_root.iterdir() if safe_exists(item) and item.is_dir()]
                for profile in sorted(profiles, key=lambda item: item.name.casefold())[:128]:
                    collect_firefox_extension_profile(document, profile, user)
        except OSError as exc:
            record_error(document, "browser_inventory_firefox", exc)


def history_indicator(hostname: str) -> dict[str, str] | None:
    host = hostname.casefold().rstrip(".")
    for item in DOMAIN_CATALOG:
        domain = item["domain"].casefold()
        if item["indicator_type"] == "fqdn":
            matched = host == domain
        else:
            matched = host == domain or host.endswith("." + domain)
        if matched:
            return item
    return None


def collect_history_database(
    document: dict[str, object],
    path: Path,
    browser: str,
    profile: str,
    user: str,
) -> None:
    if path.stat().st_size > MAX_HISTORY_BYTES_PER_PROFILE:
        record_error(document, f"browser_history_{browser}", ValueError("history_size_limit"))
        return
    found: dict[str, dict[str, str]] = {}
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)
        cursor = connection.execute(
            "SELECT url FROM urls WHERE url IS NOT NULL LIMIT ?",
            (MAX_HISTORY_ROWS_PER_PROFILE,),
        )
        for (raw_url,) in cursor:
            if not isinstance(raw_url, str):
                continue
            indicator = history_indicator(urlsplit(raw_url).hostname or "")
            if indicator is not None:
                found[indicator["artifact_id"]] = indicator
    except (OSError, sqlite3.Error, ValueError) as exc:
        record_error(document, f"browser_history_{browser}", exc)
        return
    finally:
        if connection is not None:
            connection.close()
    for indicator in found.values():
        add_finding(
            document,
            "browser_history",
            indicator,
            user,
            browser=browser,
            profile=profile,
            matched_domain=indicator["domain"],
            match_basis="history_database_hostname_match_local_only",
            presence_only=True,
        )


def collect_browser_history(document: dict[str, object], homes: list[tuple[str, Path]]) -> None:
    chromium_roots = {
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
    firefox_roots = {
        "macos": Path("Library/Application Support/Firefox/Profiles"),
        "linux": Path(".mozilla/firefox"),
    }
    for user, home in homes:
        for browser, relative_root in chromium_roots.get(os_family(), []):
            root = home / relative_root
            try:
                if not safe_exists(root):
                    continue
                profiles = [item for item in root.iterdir() if safe_exists(item) and item.is_dir()]
                for browser_profile in sorted(profiles, key=lambda item: item.name.casefold())[:128]:
                    history_path = browser_profile / "History"
                    if safe_exists(history_path):
                        collect_history_database(document, history_path, browser, browser_profile.name, user)
            except OSError as exc:
                record_error(document, f"browser_history_{browser}", exc)
        firefox_root = home / firefox_roots[os_family()]
        try:
            if safe_exists(firefox_root):
                profiles = [item for item in firefox_root.iterdir() if safe_exists(item) and item.is_dir()]
                for browser_profile in sorted(profiles, key=lambda item: item.name.casefold())[:128]:
                    history_path = browser_profile / "places.sqlite"
                    if safe_exists(history_path):
                        collect_history_database(document, history_path, "firefox", browser_profile.name, user)
        except OSError as exc:
            record_error(document, "browser_history_firefox", exc)


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
            collect_browser_history(document, homes)
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
