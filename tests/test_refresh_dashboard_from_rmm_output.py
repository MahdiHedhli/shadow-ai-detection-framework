from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))
import refresh_dashboard_from_rmm_output
from test_report import observation


class RefreshFromSavedOutputTests(unittest.TestCase):
    def setup_tree(self, root: Path) -> tuple[Path, Path, Path, Path, Path]:
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps({
            "schema_version": "1.0",
            "clients": [{
                "client_id": "client-a", "client_label": "Pilot Client",
                "rmm_company_unique_id": "company-001", "observations": "archive/observations",
            }],
        }), encoding="utf-8")
        staging, feeds, html = root / "staging", root / "feeds", root / "html"
        for directory in (staging, feeds, html):
            directory.mkdir(mode=0o700)
        source = root / "single-run.json"
        document = observation("TEST-HOST", "anthropic", "browser_extension", {"display_name": "Claude"})
        document["collector"] = {"name": "shadow-ai-rmm-windows", "version": "0.6.6", "partial": False, "errors": []}
        source.write_text(json.dumps(document), encoding="utf-8")
        source.chmod(0o600)
        return source, manifest, staging, feeds, html

    def test_single_saved_run_refreshes_only_the_explicit_manifest_client(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            if os.name == "posix":
                root_path = Path(temporary)
                root_path.chmod(0o700)
            source, manifest, staging, feeds, html = self.setup_tree(root)
            before = source.read_bytes()
            result = refresh_dashboard_from_rmm_output.refresh_from_output(
                source, manifest, "Pilot Client", "Shadow AI Inventory - Windows v0.6.6",
                staging, feeds, html / "dashboard.html",
            )
            added, existing, finding_count, scan_count, finding_path, scan_path, dashboard_path, *_ = result
            self.assertEqual((added, existing, finding_count, scan_count), (1, 0, 1, 1))
            self.assertTrue(finding_path.exists() and scan_path.exists() and dashboard_path.exists())
            self.assertNotIn("TEST-HOST", dashboard_path.read_text(encoding="utf-8"))
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual(list(staging.iterdir()), [])

    def test_rejects_wrong_client_and_symlink_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            if os.name == "posix":
                Path(temporary).chmod(0o700)
            source, manifest, staging, feeds, html = self.setup_tree(root)
            kwargs = (source, manifest, "Unknown Client", "Shadow AI Inventory - Windows", staging, feeds, html / "dashboard.html")
            with self.assertRaisesRegex(refresh_dashboard_from_rmm_output.OutputError, "match exactly one"):
                refresh_dashboard_from_rmm_output.refresh_from_output(*kwargs)
            link = root / "linked-output.json"
            link.symlink_to(source)
            with self.assertRaisesRegex(refresh_dashboard_from_rmm_output.OutputError, "symbolic link"):
                refresh_dashboard_from_rmm_output.read_private_output(link)

    def test_rejects_task_platform_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            if os.name == "posix":
                Path(temporary).chmod(0o700)
            source, _, _, _, _ = self.setup_tree(root)
            document = json.loads(source.read_text(encoding="utf-8"))
            with self.assertRaisesRegex(refresh_dashboard_from_rmm_output.OutputError, "platform"):
                refresh_dashboard_from_rmm_output.validate_scope(
                    document, "Pilot Client", "Shadow AI Inventory - macOS (Perl) v0.1.0"
                )


if __name__ == "__main__":
    unittest.main()
