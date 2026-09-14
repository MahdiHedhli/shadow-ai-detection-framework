from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD_PATH = ROOT / "tools" / "build.py"
SPEC = importlib.util.spec_from_file_location("shadow_ai_build", BUILD_PATH)
assert SPEC and SPEC.loader
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)

OBSERVATION_VALIDATOR_PATH = ROOT / "tools" / "validate_observation.py"
OBSERVATION_SPEC = importlib.util.spec_from_file_location("shadow_ai_observation", OBSERVATION_VALIDATOR_PATH)
assert OBSERVATION_SPEC and OBSERVATION_SPEC.loader
observation = importlib.util.module_from_spec(OBSERVATION_SPEC)
OBSERVATION_SPEC.loader.exec_module(observation)


class RepositoryTests(unittest.TestCase):
    def test_source_catalogs_validate(self) -> None:
        domains = build.read_csv(ROOT / "catalog" / "providers.csv", build.DOMAIN_REQUIRED)
        artifacts = build.read_csv(ROOT / "catalog" / "endpoint_artifacts.csv", build.ARTIFACT_REQUIRED)
        browser_extensions = build.read_csv(
            ROOT / "catalog" / "browser_extensions.csv", build.BROWSER_EXTENSION_REQUIRED
        )
        browser_extension_names = build.read_csv(
            ROOT / "catalog" / "browser_extension_name_patterns.csv", build.BROWSER_EXTENSION_NAME_REQUIRED
        )
        build.validate_domains(domains)
        build.validate_artifacts(artifacts)
        build.validate_browser_extensions(browser_extensions)
        build.validate_browser_extension_names(browser_extension_names)
        self.assertGreaterEqual(len(domains), 25)
        self.assertGreaterEqual(len(artifacts), 15)
        self.assertGreaterEqual(len(browser_extensions), 4)
        self.assertGreaterEqual(len(browser_extension_names), 25)
        extension_ids = {row["extension_id"]: row for row in browser_extensions}
        self.assertEqual(extension_ids["fcoeoabgfenejglbffodgkkbkcdhcgfn"]["provider_id"], "anthropic")
        self.assertEqual(extension_ids["ejcfepkfckglbgocfkanmcdngdijcgld"]["provider_id"], "openai")
        self.assertEqual(extension_ids["fcoeoabgfenejglbffodgkkbkcdhcgfn"]["browser"], "chromium-family")
        self.assertEqual(extension_ids["ejcfepkfckglbgocfkanmcdngdijcgld"]["browser"], "chromium-family")

    def test_browser_extension_name_patterns_are_specific(self) -> None:
        rows = build.read_csv(
            ROOT / "catalog" / "browser_extension_name_patterns.csv", build.BROWSER_EXTENSION_NAME_REQUIRED
        )
        self.assertNotIn("ai", {row["pattern"].casefold() for row in rows})
        with self.assertRaises(build.ValidationError):
            build.validate_browser_extension_names([rows[0], dict(rows[0])])

    def test_detection_specs_validate(self) -> None:
        specs = build.validate_specs()
        self.assertGreaterEqual(len(specs), 7)
        self.assertTrue(all(spec["status"] == "hunting" for spec in specs))

    def test_no_invalid_mde_assumptions_in_templates_or_dist(self) -> None:
        paths = list((ROOT / "templates" / "microsoft-defender").glob("*.kql.tmpl"))
        paths.extend((ROOT / "dist" / "microsoft-defender").glob("*.kql"))
        self.assertTrue(paths)
        for path in paths:
            content = path.read_text(encoding="utf-8")
            for forbidden in build.FORBIDDEN_MDE_TERMS:
                self.assertNotIn(forbidden, content, f"{path} contains {forbidden}")
            self.assertIsNone(
                re.search(r"make_set\(\s*(?:Initiating)?ProcessCommandLine", content),
                f"{path} stores an unredacted command line",
            )

    def test_formula_injection_is_rejected(self) -> None:
        with self.assertRaises(build.ValidationError):
            build.reject_spreadsheet_formula("=HYPERLINK(\"https://example.invalid\")", "test")

    def test_future_validation_date_is_rejected(self) -> None:
        with self.assertRaises(build.ValidationError):
            build.validate_date("2999-01-01", "test")

    def test_manifest_hashes_match(self) -> None:
        manifest_path = ROOT / "dist" / "manifest.json"
        self.assertTrue(manifest_path.exists(), "run python3 tools/build.py first")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for item in manifest["files"]:
            path = ROOT / "dist" / item["path"]
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(item["sha256"], digest, item["path"])

    def test_safe_write_rejects_parent_traversal(self) -> None:
        with self.assertRaises(ValueError):
            build.safe_write(Path("..") / "outside.txt", "unsafe")

    def test_observation_schema_is_valid_json(self) -> None:
        schema = json.loads((ROOT / "schema" / "observation.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["schema_version"]["const"], "1.0")
        safety = schema["properties"]["safety"]["properties"]
        self.assertTrue(safety)
        self.assertTrue(all(value.get("const") is False for value in safety.values()))

    def test_python_collector_self_test(self) -> None:
        collector = ROOT / "dist" / "rmm-macos-linux" / "shadow_ai_inventory.py"
        result = subprocess.run(
            ["python3", str(collector), "--self-test"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        document = json.loads(result.stdout)
        observation.validate_document(document)
        self.assertEqual(document["findings"], [])
        self.assertFalse(document["collector"]["partial"])

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is not installed")
    def test_powershell_collector_self_test(self) -> None:
        collector = ROOT / "dist" / "rmm-windows" / "ShadowAIInventory.ps1"
        result = subprocess.run(
            ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(collector), "-SelfTest"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        document = json.loads(result.stdout)
        observation.validate_document(document)
        self.assertEqual(document["findings"], [])
        self.assertFalse(document["collector"]["partial"])

    def test_collectors_have_no_remote_or_recursive_execution_primitives(self) -> None:
        paths = [
            ROOT / "templates" / "rmm-macos-linux" / "shadow_ai_inventory.py.tmpl",
            ROOT / "templates" / "rmm-windows" / "ShadowAIInventory.ps1.tmpl",
        ]
        forbidden = (
            "Invoke-Expression",
            "Invoke-WebRequest",
            "DownloadString",
            "Start-BitsTransfer",
            "-Recurse",
            "os.walk(",
            ".rglob(",
            "shell=True",
        )
        for path in paths:
            content = path.read_text(encoding="utf-8")
            for value in forbidden:
                self.assertNotIn(value, content, f"{path} contains unsafe primitive {value}")

    def test_windows_software_inventory_tolerates_sparse_registry_entries(self) -> None:
        paths = [
            ROOT / "templates" / "rmm-windows" / "ShadowAIInventory.ps1.tmpl",
            ROOT / "dist" / "rmm-windows" / "ShadowAIInventory.ps1",
        ]
        for path in paths:
            content = path.read_text(encoding="utf-8")
            self.assertIn("PSObject.Properties[$Name]", content, str(path))
            self.assertNotIn("$software.DisplayName", content, str(path))
            self.assertNotIn("$software.DisplayVersion", content, str(path))

    def test_windows_software_inventory_covers_user_hives_appx_and_claude_legacy_path(self) -> None:
        paths = [
            ROOT / "templates" / "rmm-windows" / "ShadowAIInventory.ps1.tmpl",
            ROOT / "dist" / "rmm-windows" / "ShadowAIInventory.ps1",
        ]
        for path in paths:
            content = path.read_text(encoding="utf-8")
            self.assertIn("Registry::HKEY_USERS", content, str(path))
            self.assertIn("Get-AppxPackage -AllUsers", content, str(path))
            self.assertIn("AppData\\Local\\AnthropicClaude", content, str(path))
            self.assertNotIn("reg.exe load", content.lower(), str(path))
            self.assertNotIn("reg load", content.lower(), str(path))

    def test_windows_empty_profile_inventory_is_partial_not_fatal(self) -> None:
        paths = [
            ROOT / "templates" / "rmm-windows" / "ShadowAIInventory.ps1.tmpl",
            ROOT / "dist" / "rmm-windows" / "ShadowAIInventory.ps1",
        ]
        for path in paths:
            content = path.read_text(encoding="utf-8")
            self.assertEqual(content.count("[AllowEmptyCollection()][object[]]$Profiles"), 6, str(path))
            self.assertIn("profile_inventory_empty", content, str(path))

    def test_windows_known_paths_use_deterministic_indicators(self) -> None:
        paths = [
            ROOT / "templates" / "rmm-windows" / "ShadowAIInventory.ps1.tmpl",
            ROOT / "dist" / "rmm-windows" / "ShadowAIInventory.ps1",
        ]
        for path in paths:
            content = path.read_text(encoding="utf-8")
            self.assertIn(
                "New-SyntheticIndicator 'file-model-001' 'generic' 'model_weight' 'high'", content, str(path)
            )
            self.assertIn(
                "New-SyntheticIndicator 'file-mcp-001' 'mcp' 'mcp_configuration' 'medium'", content, str(path)
            )
            self.assertNotIn("$mcp['mcp.json']", content, str(path))
            self.assertNotIn(
                "$Catalog | Where-Object { $_.artifact_id -eq 'file-model-001' }", content, str(path)
            )

    def test_windows_fatal_diagnostics_are_bounded_and_content_free(self) -> None:
        paths = [
            ROOT / "templates" / "rmm-windows" / "ShadowAIInventory.ps1.tmpl",
            ROOT / "dist" / "rmm-windows" / "ShadowAIInventory.ps1",
        ]
        for path in paths:
            content = path.read_text(encoding="utf-8")
            self.assertIn("error_id = [string]$fatalRecord.FullyQualifiedErrorId", content, str(path))
            self.assertIn("parameter = $fatalParameter", content, str(path))
            self.assertIn("line = [int]$fatalRecord.InvocationInfo.ScriptLineNumber", content, str(path))
            self.assertNotIn("$fatalRecord.Exception.Message", content, str(path))

    def test_collectors_cover_all_local_profiles_without_emitting_raw_history(self) -> None:
        windows_paths = [
            ROOT / "templates" / "rmm-windows" / "ShadowAIInventory.ps1.tmpl",
            ROOT / "dist" / "rmm-windows" / "ShadowAIInventory.ps1",
        ]
        for path in windows_paths:
            content = path.read_text(encoding="utf-8")
            self.assertIn("Win32_UserProfile", content, str(path))
            self.assertIn("Collect-BrowserHistory -Profiles $profiles", content, str(path))
            self.assertIn("Collect-BrowserExtensions -Profiles $profiles", content, str(path))
            self.assertIn("Collect-KnownPaths -Profiles $profiles", content, str(path))
            self.assertIn("matched_domain", content, str(path))
            self.assertNotIn("raw_url =", content, str(path))
            self.assertNotIn("page_title =", content, str(path))

    def test_collectors_classify_extension_manifests_locally(self) -> None:
        paths = [
            ROOT / "templates" / "rmm-macos-linux" / "shadow_ai_inventory.py.tmpl",
            ROOT / "templates" / "rmm-windows" / "ShadowAIInventory.ps1.tmpl",
        ]
        for path in paths:
            content = path.read_text(encoding="utf-8")
            self.assertIn("BROWSER_EXTENSION_NAME_CATALOG_JSON", content, str(path))
            self.assertIn("manifest_name_local_only", content, str(path))
            normalized = content.casefold().replace("_", "")
            self.assertIn("maxmanifest", normalized, str(path))
            self.assertNotIn("extension_description", content, str(path))
            self.assertNotIn("extension_permissions", content, str(path))

    def test_collectors_emit_privacy_safe_extension_coverage(self) -> None:
        paths = [
            ROOT / "templates" / "rmm-macos-linux" / "shadow_ai_inventory.py.tmpl",
            ROOT / "templates" / "rmm-windows" / "ShadowAIInventory.ps1.tmpl",
        ]
        for path in paths:
            content = path.read_text(encoding="utf-8").casefold()
            self.assertIn("installed_extension_count", content, str(path))
            self.assertIn("classified_extension_count", content, str(path))
            self.assertIn("count_only", content, str(path))
            for browser in ("firefox", "vivaldi", "arc", "opera"):
                self.assertIn(browser, content, str(path))

    def test_python_extension_manifest_name_classification(self) -> None:
        collector = ROOT / "dist" / "rmm-macos-linux" / "shadow_ai_inventory.py"
        spec = importlib.util.spec_from_file_location("shadow_ai_extension_collector", collector)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            literal_version = root / "literal" / "1.0.0"
            literal_version.mkdir(parents=True)
            (literal_version / "manifest.json").write_text('{"name":"Claude in the browser"}', encoding="utf-8")
            self.assertEqual(module.resolve_chromium_extension_name(root / "literal"), "Claude in the browser")
            self.assertEqual(
                module.extension_name_classification("Claude in the browser")["provider_id"], "anthropic"
            )

            localized_version = root / "localized" / "2.0.0"
            locale = localized_version / "_locales" / "en"
            locale.mkdir(parents=True)
            (localized_version / "manifest.json").write_text(
                '{"name":"__MSG_appName__","default_locale":"en"}', encoding="utf-8"
            )
            (locale / "messages.json").write_text(
                '{"appName":{"message":"Perplexity Assistant"}}', encoding="utf-8"
            )
            self.assertEqual(module.resolve_chromium_extension_name(root / "localized"), "Perplexity Assistant")
            self.assertIsNone(module.extension_name_classification("Ordinary bookmark helper"))

    def test_python_extension_inventory_counts_do_not_disclose_unclassified_names(self) -> None:
        collector = ROOT / "dist" / "rmm-macos-linux" / "shadow_ai_inventory.py"
        spec = importlib.util.spec_from_file_location("shadow_ai_extension_inventory", collector)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "Default"
            extension = profile / "Extensions" / ("a" * 32) / "1.0.0"
            extension.mkdir(parents=True)
            (extension / "manifest.json").write_text(
                '{"name":"Ordinary bookmark helper"}', encoding="utf-8"
            )
            document = module.new_document()
            module.collect_chromium_extension_profile(document, "chrome", profile, "tester", {})
            findings = document["findings"]
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["capability"], "browser_extension_inventory")
            self.assertEqual(findings[0]["attributes"]["installed_extension_count"], 1)
            self.assertEqual(findings[0]["attributes"]["classified_extension_count"], 0)
            serialized = json.dumps(document)
            self.assertNotIn("Ordinary bookmark helper", serialized)
            self.assertNotIn("a" * 32, serialized)

    def test_python_firefox_extension_inventory_and_classification(self) -> None:
        collector = ROOT / "dist" / "rmm-macos-linux" / "shadow_ai_inventory.py"
        spec = importlib.util.spec_from_file_location("shadow_ai_firefox_inventory", collector)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile.default"
            profile.mkdir(parents=True)
            (profile / "extensions.json").write_text(
                json.dumps(
                    {
                        "addons": [
                            {"id": "claude@example.invalid", "type": "extension", "isSystem": False,
                             "defaultLocale": {"name": "Claude in Firefox"}},
                            {"id": "builtin@example.invalid", "type": "extension", "isSystem": True,
                             "defaultLocale": {"name": "Claude Builtin"}},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            document = module.new_document()
            module.collect_firefox_extension_profile(document, profile, "tester")
            findings = document["findings"]
            self.assertEqual(len(findings), 2)
            classified = next(item for item in findings if item["capability"] == "ai_browser_extension")
            inventory = next(item for item in findings if item["capability"] == "browser_extension_inventory")
            self.assertEqual(classified["provider_id"], "anthropic")
            self.assertEqual(inventory["attributes"]["installed_extension_count"], 1)
            self.assertEqual(inventory["attributes"]["classified_extension_count"], 1)

    def test_python_history_matching_respects_hostname_boundaries(self) -> None:
        collector = ROOT / "dist" / "rmm-macos-linux" / "shadow_ai_inventory.py"
        spec = importlib.util.spec_from_file_location("shadow_ai_collector", collector)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.history_indicator("claude.ai")["provider_id"], "anthropic")
        self.assertEqual(module.history_indicator("team.claude.ai")["provider_id"], "anthropic")
        self.assertIsNone(module.history_indicator("notclaude.ai"))
        self.assertIsNone(module.history_indicator("claude.ai.example.invalid"))

    def test_sensitive_observation_key_is_rejected(self) -> None:
        collector = ROOT / "dist" / "rmm-macos-linux" / "shadow_ai_inventory.py"
        result = subprocess.run(
            ["python3", str(collector), "--self-test"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        document = json.loads(result.stdout)
        document["findings"].append(
            {
                "finding_id": "657d09c4-d63e-4c3c-837d-1e13d70b8424",
                "observed_at": "2026-09-02T00:00:00Z",
                "category": "process",
                "indicator_id": "test-indicator",
                "provider_id": "test-provider",
                "capability": "test",
                "confidence": "low",
                "evidence_level": 1,
                "subject_user": None,
                "attributes": {"command_line": "must not be accepted"},
            }
        )
        with self.assertRaises(observation.ObservationError):
            observation.validate_document(document)

        document["findings"][-1]["attributes"] = {"history_url": "https://example.invalid"}
        with self.assertRaises(observation.ObservationError):
            observation.validate_document(document)


if __name__ == "__main__":
    unittest.main()
