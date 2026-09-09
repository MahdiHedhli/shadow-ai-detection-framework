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
        build.validate_domains(domains)
        build.validate_artifacts(artifacts)
        build.validate_browser_extensions(browser_extensions)
        self.assertGreaterEqual(len(domains), 25)
        self.assertGreaterEqual(len(artifacts), 15)
        self.assertGreaterEqual(len(browser_extensions), 4)

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


if __name__ == "__main__":
    unittest.main()
