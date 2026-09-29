from __future__ import annotations

import json
import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "dist" / "rmm-macos-linux" / "shadow_ai_inventory.pl"
BUNDLE_BUILDER_PATH = ROOT / "tools" / "build_perl_rmm_bundle.py"
BUNDLE_SPEC = importlib.util.spec_from_file_location("shadow_ai_perl_bundle", BUNDLE_BUILDER_PATH)
assert BUNDLE_SPEC and BUNDLE_SPEC.loader
bundle_builder = importlib.util.module_from_spec(BUNDLE_SPEC)
BUNDLE_SPEC.loader.exec_module(bundle_builder)
VALIDATOR = ROOT / "tools" / "validate_observation.py"
sys.path.insert(0, str(ROOT / "tools"))
import rmm_output


class MacOSPerlCollectorTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("perl"), "Perl is unavailable")
    def test_self_test_emits_empty_schema_shaped_document(self) -> None:
        result = subprocess.run(
            ["perl", str(COLLECTOR), "--self-test"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        document = json.loads(result.stdout)
        self.assertEqual(document["schema_version"], "1.0")
        self.assertEqual(document["collector"]["name"], "shadow-ai-rmm-macos-native")
        self.assertEqual(document["findings"], [])
        self.assertEqual(
            document["scope"],
            ["processes", "known_paths", "browser_extensions", "browser_history"],
        )
        self.assertFalse(document["safety"]["raw_command_line_collected"])
        self.assertFalse(document["safety"]["content_collected"])
        self.assertFalse(document["safety"]["network_requests_made"])

    @unittest.skipUnless(shutil.which("perl"), "Perl is unavailable")
    def test_collector_compiles_without_scanning_endpoint_data(self) -> None:
        result = subprocess.run(
            ["perl", "-c", str(COLLECTOR)],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertIn("syntax OK", result.stderr)

    @unittest.skipUnless(shutil.which("perl"), "Perl is unavailable")
    def test_large_perl_output_uses_bounded_gzip_envelope(self) -> None:
        source = COLLECTOR.read_text(encoding="utf-8")
        target = "$doc->{collector}->{partial} = $partial;\n"
        self.assertIn(target, source)
        source = source.replace(target, target + "$doc->{device}->{os_version} = 'x' x 20000;\n", 1)
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "large-self-test.pl"
            path.write_text(source, encoding="utf-8")
            result = subprocess.run(
                ["perl", str(path), "--self-test"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
        self.assertTrue(result.stdout.startswith(rmm_output.PREFIX))
        document = json.loads(rmm_output.decode_output(result.stdout.strip()))
        self.assertEqual(document["device"]["os_version"], "x" * 20000)

    @unittest.skipUnless(shutil.which("bash") and shutil.which("perl"), "Bash or Perl is unavailable")
    def test_rmm_bash_bundle_emits_valid_self_test_observation(self) -> None:
        bundle = bundle_builder.make_bundle(COLLECTOR.read_text(encoding="utf-8"), self_test=True)
        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_path = Path(temp_dir) / "shadow-ai-rmm-bundle.sh"
            bundle_path.write_text(bundle, encoding="utf-8")
            result = subprocess.run(
                ["bash", str(bundle_path), "--self-test"],
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
            document = json.loads(result.stdout)
            self.assertEqual(document["findings"], [])
            self.assertFalse(document["collector"]["partial"])
            validation = subprocess.run(
                ["python3", str(VALIDATOR)],
                input=result.stdout,
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertIn("valid", validation.stderr.casefold())

    def test_bundle_refuses_heredoc_delimiter_collision(self) -> None:
        source = "#!/usr/bin/perl\n" + bundle_builder.DELIMITER + "\n"
        with self.assertRaises(bundle_builder.BundleError):
            bundle_builder.make_bundle(source)

    def test_regular_rmm_bundle_does_not_force_self_test(self) -> None:
        bundle = bundle_builder.make_bundle(COLLECTOR.read_text(encoding="utf-8"))
        self.assertIn('/usr/bin/perl "$tmp_script" "$@"', bundle)
        self.assertNotIn('"$@" --self-test', bundle)


if __name__ == "__main__":
    unittest.main()
