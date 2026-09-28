from __future__ import annotations

import csv
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))
import refresh_dashboard
from test_report import observation


TASK = "Shadow AI Inventory - Windows"


class RefreshDashboardTests(unittest.TestCase):
    def test_refresh_archives_and_builds_both_feeds_and_private_dashboard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "clients.json"
            manifest.write_text(json.dumps({
                "schema_version": "1.0",
                "clients": [{
                    "client_id": "client-a",
                    "client_label": "Client A",
                    "rmm_company_unique_id": "company-001",
                    "observations": "client-a/observations",
                }],
            }), encoding="utf-8")

            document = observation(
                "PRIVATE-TEST-HOST",
                "anthropic",
                "browser_extension",
                {"extension_name": "Claude", "extension_id": "private-extension-id"},
            )
            export = root / "task-export.csv"
            with export.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["company_unique_id", "task_name", "execution_output"])
                writer.writeheader()
                writer.writerow({
                    "company_unique_id": "company-001",
                    "task_name": TASK,
                    "execution_output": json.dumps(document),
                })

            feeds_dir = root / "feeds"
            feeds_dir.mkdir(mode=0o700)
            html_dir = root / "html"
            html_dir.mkdir(mode=0o700)
            outputs = refresh_dashboard.refresh(
                export,
                manifest,
                TASK,
                feeds_dir,
                html_dir / "technician-dashboard.html",
            )

            added, skipped, finding_count, scan_count, findings_path, scans_path, dashboard_path = outputs
            self.assertEqual((added, skipped, finding_count, scan_count), (1, 0, 1, 1))
            self.assertTrue(findings_path.exists())
            self.assertTrue(scans_path.exists())
            self.assertTrue(dashboard_path.exists())

            findings_text = findings_path.read_text(encoding="utf-8")
            scans_text = scans_path.read_text(encoding="utf-8")
            dashboard_text = dashboard_path.read_text(encoding="utf-8")
            self.assertIn("client-a", findings_text)
            self.assertIn("anthropic", findings_text)
            self.assertIn("Claude", findings_text)
            self.assertIn("complete", scans_text)
            self.assertIn("Export selected client CSV", dashboard_text)
            self.assertIn("Client comparison", dashboard_text)
            self.assertIn('data-client-sort="finding_observations"', dashboard_text)
            self.assertIn('data-client-sort="client_label"', dashboard_text)
            self.assertIn("renderClientComparison(all,scans)", dashboard_text)
            for content in (findings_text, scans_text, dashboard_text):
                self.assertNotIn("PRIVATE-TEST-HOST", content)
            if os.name == "posix":
                for path in (findings_path, scans_path, dashboard_path):
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                for directory in (feeds_dir, html_dir, root / "client-a/observations"):
                    self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

    def test_refresh_refuses_overwrite_without_explicit_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "clients.json"
            manifest.write_text(json.dumps({
                "schema_version": "1.0",
                "clients": [{
                    "client_id": "client-a",
                    "client_label": "Client A",
                    "rmm_company_unique_id": "company-001",
                    "observations": "client-a/observations",
                }],
            }), encoding="utf-8")
            document = observation("PRIVATE-HOST", "anthropic", "software", {"display_name": "Claude"})
            export = root / "task-export.csv"
            with export.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["company_unique_id", "task_name", "execution_output"])
                writer.writeheader()
                writer.writerow({
                    "company_unique_id": "company-001",
                    "task_name": TASK,
                    "execution_output": json.dumps(document),
                })
            feeds_dir = root / "feeds"
            feeds_dir.mkdir(mode=0o700)
            html_dir = root / "html"
            html_dir.mkdir(mode=0o700)
            dashboard_path = html_dir / "technician-dashboard.html"
            refresh_dashboard.refresh(export, manifest, TASK, feeds_dir, dashboard_path)
            original = dashboard_path.read_bytes()

            with self.assertRaisesRegex(refresh_dashboard.build_dashboard_feed.FeedError, "already exist"):
                refresh_dashboard.refresh(export, manifest, TASK, feeds_dir, dashboard_path)
            self.assertEqual(dashboard_path.read_bytes(), original)

    def test_existing_dashboard_is_detected_before_archiving_observations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "clients.json"
            manifest.write_text(json.dumps({
                "schema_version": "1.0",
                "clients": [{
                    "client_id": "client-a",
                    "client_label": "Client A",
                    "rmm_company_unique_id": "company-001",
                    "observations": "client-a/observations",
                }],
            }), encoding="utf-8")
            document = observation("PRIVATE-HOST", "anthropic", "software", {"display_name": "Claude"})
            export = root / "task-export.csv"
            with export.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["company_unique_id", "task_name", "execution_output"])
                writer.writeheader()
                writer.writerow({
                    "company_unique_id": "company-001",
                    "task_name": TASK,
                    "execution_output": json.dumps(document),
                })
            feeds_dir = root / "feeds"
            feeds_dir.mkdir(mode=0o700)
            html_dir = root / "html"
            html_dir.mkdir(mode=0o700)
            dashboard_path = html_dir / "technician-dashboard.html"
            dashboard_path.write_text("existing", encoding="utf-8")

            with self.assertRaisesRegex(refresh_dashboard.build_dashboard_feed.FeedError, "already exist"):
                refresh_dashboard.refresh(export, manifest, TASK, feeds_dir, dashboard_path)
            self.assertFalse((root / "client-a/observations").exists())
            self.assertFalse((feeds_dir / "shadow-ai-findings.csv").exists())
            self.assertEqual(dashboard_path.read_text(encoding="utf-8"), "existing")


if __name__ == "__main__":
    unittest.main()
