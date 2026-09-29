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
import refresh_dashboard_from_rmm_export
import discover_rmm_clients
from test_report import observation


TASK = "Shadow AI Inventory - Windows"


class RefreshDashboardTests(unittest.TestCase):
    def test_first_run_discovery_feeds_latest_state_dashboard_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            export = root / "broad-export.csv"
            document = observation("PRIVATE-PILOT-HOST", "anthropic", "browser_extension", {
                "extension_name": "Claude",
                "extension_id": "private-test-id",
            })
            with export.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["company_unique_id", "company_name", "task_name", "execution_output", "other"],
                )
                writer.writeheader()
                writer.writerow({
                    "company_unique_id": "unrelated-company",
                    "company_name": "Unrelated Client",
                    "task_name": "Other automation",
                    "execution_output": "UNRELATED_SECRET_DO_NOT_COPY",
                    "other": "private",
                })
                writer.writerow({
                    "company_unique_id": "company-001",
                    "company_name": "Pilot Client",
                    "task_name": TASK,
                    "execution_output": json.dumps(document),
                    "other": "not-copied",
                })
            source_before = export.read_bytes()
            manifest = root / "dashboard-clients.json"
            self.assertEqual(discover_rmm_clients.write_manifest(export, TASK, manifest), 1)

            staging = root / "staging"
            staging.mkdir(mode=0o700)
            feeds = root / "feeds"
            feeds.mkdir(mode=0o700)
            html = root / "html"
            html.mkdir(mode=0o700)
            result = refresh_dashboard_from_rmm_export.refresh_from_export(
                export,
                manifest,
                TASK,
                staging,
                feeds,
                html / "internal.html",
            )

            added, already_present, finding_count, scan_count, findings, scans, dashboard, filtered, unrelated, incomplete = result
            self.assertEqual((added, already_present, finding_count, scan_count, filtered, unrelated, incomplete), (1, 0, 1, 1, 1, 1, 0))
            self.assertTrue(findings.exists())
            self.assertTrue(scans.exists())
            self.assertIn("Pilot Client", dashboard.read_text(encoding="utf-8"))
            self.assertNotIn("PRIVATE-PILOT-HOST", dashboard.read_text(encoding="utf-8"))
            self.assertNotIn("UNRELATED_SECRET_DO_NOT_COPY", findings.read_text(encoding="utf-8"))
            self.assertEqual(export.read_bytes(), source_before)
            self.assertEqual(list(staging.iterdir()), [])

    def test_one_command_refresh_filters_broad_source_and_removes_transient_copy(self) -> None:
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
            document = observation("PRIVATE-TEST-HOST", "anthropic", "browser_extension", {"extension_name": "Claude"})
            export = root / "broad-export.csv"
            with export.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["company_unique_id", "task_name", "execution_output", "other"],
                )
                writer.writeheader()
                writer.writerow({
                    "company_unique_id": "unmapped-private-company",
                    "task_name": "Unrelated task",
                    "execution_output": "UNRELATED_PRIVATE_OUTPUT_DO_NOT_COPY",
                    "other": "sensitive",
                })
                writer.writerow({
                    "company_unique_id": "company-001",
                    "task_name": TASK,
                    "execution_output": json.dumps(document),
                    "other": "not-copied",
                })
            source_before = export.read_bytes()
            staging = root / "staging"
            staging.mkdir(mode=0o700)
            feeds = root / "feeds"
            feeds.mkdir(mode=0o700)
            html_dir = root / "html"
            html_dir.mkdir(mode=0o700)

            result = refresh_dashboard_from_rmm_export.refresh_from_export(
                export,
                manifest,
                TASK,
                staging,
                feeds,
                html_dir / "dashboard.html",
            )

            added, skipped, finding_count, scan_count, findings, scans, dashboard, filtered, unrelated, incomplete = result
            self.assertEqual((added, skipped, finding_count, scan_count, filtered, unrelated, incomplete), (1, 0, 1, 1, 1, 1, 0))
            self.assertTrue(findings.exists())
            self.assertTrue(scans.exists())
            self.assertTrue(dashboard.exists())
            self.assertEqual(export.read_bytes(), source_before)
            self.assertEqual(list(staging.iterdir()), [])
            for path in (findings, scans, dashboard):
                content = path.read_text(encoding="utf-8")
                self.assertNotIn("UNRELATED_PRIVATE_OUTPUT_DO_NOT_COPY", content)
                self.assertNotIn("PRIVATE-TEST-HOST", content)

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
            self.assertIn("Export client CSV", dashboard_text)
            self.assertIn("Client comparison", dashboard_text)
            self.assertIn('data-client-sort="finding_observations"', dashboard_text)
            self.assertIn('data-client-sort="client_label"', dashboard_text)
            self.assertIn("renderClientComparison(all,scans)", dashboard_text)
            for content in (findings_text, scans_text, dashboard_text):
                self.assertNotIn("PRIVATE-TEST-HOST", content)
            if os.name == "posix":
                for path in (findings_path, scans_path, dashboard_path):
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                for directory in (feeds_dir, html_dir, root / "client-a", root / "client-a/observations"):
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
