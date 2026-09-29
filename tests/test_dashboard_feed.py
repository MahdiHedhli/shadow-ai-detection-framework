from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))
FEED_PATH = ROOT / "tools" / "build_dashboard_feed.py"
SPEC = importlib.util.spec_from_file_location("shadow_ai_dashboard_feed", FEED_PATH)
assert SPEC and SPEC.loader
feed = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(feed)
from test_report import observation


class DashboardFeedTests(unittest.TestCase):
    def test_manifest_paths_must_stay_outside_public_repository(self) -> None:
        with self.assertRaises(feed.FeedError):
            feed.outside_public_repo(ROOT / "private-client-data" / "manifest.json", "client manifest")

    def test_manifest_rejects_overlapping_client_archives(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            manifest = base / "dashboard-clients.json"
            manifest.write_text(json.dumps({
                "schema_version": "1.0",
                "clients": [
                    {"client_id": "client-a", "client_label": "Client A", "observations": "client-a"},
                    {"client_id": "client-b", "client_label": "Client B", "observations": "client-a/client-b"},
                ],
            }), encoding="utf-8")
            with self.assertRaisesRegex(feed.FeedError, "must not overlap"):
                feed.load_manifest(manifest)

    def test_manifest_rejects_review_file_inside_any_observation_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            manifest = base / "dashboard-clients.json"
            manifest.write_text(json.dumps({
                "schema_version": "1.0",
                "clients": [
                    {"client_id": "client-a", "client_label": "Client A", "observations": "client-a"},
                    {"client_id": "client-b", "client_label": "Client B", "observations": "client-b", "reviews": "client-a/reviews.json"},
                ],
            }), encoding="utf-8")
            with self.assertRaisesRegex(feed.FeedError, "outside every client observation archive"):
                feed.load_manifest(manifest)

    def test_csv_formula_prefix_is_neutralized(self) -> None:
        self.assertEqual(feed.csv_value("=HYPERLINK(\"https://bad\")"), "'=HYPERLINK(\"https://bad\")")
        self.assertEqual(feed.csv_value(" Anthropic"), " Anthropic")
        self.assertEqual(feed.csv_value(3), 3)

    def test_feed_omits_endpoint_user_and_review_identity(self) -> None:
        document = observation(
            "PRIVATE-HOSTNAME",
            "anthropic",
            "browser_extension",
            {
                "browser": "chrome",
                "extension_name": "Claude",
                "extension_id": "a" * 32,
                "matched_domain": "claude.ai",
            },
        )
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "observations"
            archive.mkdir()
            (archive / "observation.json").write_text(json.dumps(document), encoding="utf-8")
            provider_names, products = feed.build_report.load_provider_names()
            finding_rows, scan_rows = feed.load_client_data(
                {
                    "client_id": "client-a",
                    "client_label": "Client A",
                    "observations": archive,
                    "reviews": None,
                },
                None,
                provider_names,
                products,
            )
            findings_csv = feed.make_csv(finding_rows, feed.FINDING_FIELDS)
            scans_csv = feed.make_csv(scan_rows, feed.SCAN_FIELDS)

        all_csv = findings_csv + scans_csv
        self.assertIn("Client A", findings_csv)
        self.assertIn("Claude", findings_csv)
        self.assertIn("open", findings_csv)
        self.assertNotIn("PRIVATE-HOSTNAME", all_csv)
        self.assertNotIn("local-test-user", all_csv)
        self.assertNotIn("reviewer", all_csv)
        self.assertNotIn("reason", all_csv)
        self.assertEqual(len(finding_rows), 1)
        self.assertEqual(len(scan_rows), 1)

    def test_empty_client_archive_is_explicit_not_a_clean_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "observations"
            archive.mkdir()
            provider_names, products = feed.build_report.load_provider_names()
            findings, scans = feed.load_client_data(
                {
                    "client_id": "client-b",
                    "client_label": "Client B",
                    "observations": archive,
                    "reviews": None,
                },
                "2026-09",
                provider_names,
                products,
            )
        self.assertEqual(findings, [])
        self.assertEqual(scans[0]["scan_status"], "no_observations")
        self.assertEqual(scans[0]["finding_observations"], 0)

    def test_review_metadata_is_reduced_to_status_and_date(self) -> None:
        document = observation("TEST-ENDPOINT", "anthropic", "browser_extension", {"extension_name": "Claude"})
        finding_key = feed.build_report.stable_finding_key(document, document["findings"][0])
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            archive = base / "observations"
            archive.mkdir()
            (archive / "observation.json").write_text(json.dumps(document), encoding="utf-8")
            review_path = base / "reviews.json"
            review_path.write_text(
                json.dumps({
                    "schema_version": "1.0",
                    "decisions": [{
                        "finding_key": finding_key,
                        "status": "justified",
                        "reviewer": "PRIVATE REVIEWER",
                        "reason": "PRIVATE CLIENT REASON",
                        "reviewed_at": "2026-09-20T10:00:00Z",
                    }],
                }),
                encoding="utf-8",
            )
            providers, products = feed.build_report.load_provider_names()
            findings, _ = feed.load_client_data(
                {
                    "client_id": "client-a",
                    "client_label": "Client A",
                    "observations": archive,
                    "reviews": review_path,
                },
                None,
                providers,
                products,
            )
            rendered = feed.make_csv(findings, feed.FINDING_FIELDS)
        self.assertEqual(findings[0]["review_status"], "justified")
        self.assertEqual(findings[0]["confidence_rank"], 3)
        self.assertEqual(findings[0]["reviewed_at"], "2026-09-20T10:00:00Z")
        self.assertNotIn("PRIVATE REVIEWER", rendered)
        self.assertNotIn("PRIVATE CLIENT REASON", rendered)

    def test_private_outputs_use_restrictive_permissions_and_refuse_implicit_replace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "private-feed"
            destination.mkdir(mode=0o700)
            paths = feed.write_outputs(destination, "a\n", "b\n", overwrite=False)
            self.assertTrue(all(path.exists() for path in paths))
            if sys.platform != "win32":
                self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in paths))
            with self.assertRaises(feed.FeedError):
                feed.write_outputs(destination, "new\n", "new\n", overwrite=False)

    def test_observation_validation_and_unique_rows(self) -> None:
        document = observation("TEST-ENDPOINT", "openai", "software", {"display_name": "ChatGPT"})
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "observations"
            archive.mkdir()
            (archive / "observation.json").write_text(json.dumps(document), encoding="utf-8")
            providers, products = feed.build_report.load_provider_names()
            rows, _ = feed.load_client_data(
                {
                    "client_id": "client-c",
                    "client_label": "Client C",
                    "observations": archive,
                    "reviews": None,
                },
                None,
                providers,
                products,
            )
        self.assertEqual(rows[0]["finding_id"], document["findings"][0]["finding_id"])
        self.assertEqual(len(rows[0]["finding_key"]), 64)

    def test_brightgauge_feed_uses_latest_scan_per_endpoint_without_backfilling(self) -> None:
        older = observation("TEST-ENDPOINT", "anthropic", "browser_extension", {"extension_name": "Claude"})
        older["collected_at"] = "2026-09-15T12:00:00.000Z"
        older["findings"][0]["observed_at"] = older["collected_at"]

        latest_clean = observation("TEST-ENDPOINT", "openai", "browser_extension", {})
        latest_clean["collected_at"] = "2026-09-25T12:00:00.000Z"
        latest_clean["findings"] = []

        other_endpoint = observation("OTHER-ENDPOINT", "openai", "software", {"display_name": "ChatGPT"})
        other_endpoint["collected_at"] = "2026-09-20T12:00:00.000Z"
        other_endpoint["findings"][0]["observed_at"] = other_endpoint["collected_at"]

        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "observations"
            archive.mkdir()
            for document in (older, latest_clean, other_endpoint):
                (archive / f"{document['observation_id']}.json").write_text(
                    json.dumps(document), encoding="utf-8"
                )
            providers, products = feed.build_report.load_provider_names()
            findings, scans = feed.load_client_data(
                {
                    "client_id": "client-a",
                    "client_label": "Client A",
                    "observations": archive,
                    "reviews": None,
                },
                None,
                providers,
                products,
            )
            findings_csv = feed.make_csv(findings, feed.FINDING_FIELDS)
            scans_csv = feed.make_csv(scans, feed.SCAN_FIELDS)

        self.assertEqual(len(scans), 2)
        self.assertEqual({row["finding_observations"] for row in scans}, {0, 1})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["provider_id"], "openai")
        self.assertIn("ChatGPT", findings_csv)
        self.assertNotIn("Claude", findings_csv)
        self.assertNotIn("TEST-ENDPOINT", findings_csv + scans_csv)
        self.assertNotIn("OTHER-ENDPOINT", findings_csv + scans_csv)


if __name__ == "__main__":
    unittest.main()
