from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
REPORT_PATH = ROOT / "tools" / "build_report.py"
SPEC = importlib.util.spec_from_file_location("shadow_ai_report", REPORT_PATH)
assert SPEC and SPEC.loader
report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report)


def observation(hostname: str, provider_id: str, category: str, attributes: dict[str, object]) -> dict[str, object]:
    timestamp = "2026-09-15T12:00:00.000Z"
    return {
        "schema_version": "1.0",
        "observation_id": str(uuid.uuid4()),
        "collected_at": timestamp,
        "collector": {"name": "synthetic-test", "version": "0.0", "partial": False, "errors": []},
        "device": {"hostname": hostname, "os_family": "windows", "os_version": "test", "architecture": "x64"},
        "scope": ["browser_extensions", "browser_history"],
        "safety": {
            "content_collected": False,
            "raw_command_line_collected": False,
            "environment_values_collected": False,
            "network_requests_made": False,
            "full_disk_search_performed": False,
            "symlinks_followed": False,
        },
        "findings": [
            {
                "finding_id": str(uuid.uuid4()),
                "observed_at": timestamp,
                "category": category,
                "indicator_id": "browser-test-001",
                "provider_id": provider_id,
                "capability": "ai_browser_extension",
                "confidence": "high",
                "evidence_level": 2,
                "subject_user": "local-test-user",
                "attributes": attributes,
            }
        ],
    }


class ReportTests(unittest.TestCase):
    def test_report_output_cannot_be_written_inside_public_repo(self) -> None:
        with self.assertRaises(report.ReportError):
            report.ensure_private_output(ROOT / "client-reports" / "test.html")

    def test_report_omits_local_users_and_escapes_script_injection(self) -> None:
        document = observation(
            "TEST-ENDPOINT",
            "anthropic",
            "browser_extension",
            {"browser": "chrome", "extension_name": "Claude", "extension_id": "a" * 32, "presence_only": True},
        )
        report.validate_observation.validate_document(document)
        providers = {"anthropic": {"name": "Anthropic", "products": ["Claude"]}}
        rows = report.build_rows([document], providers, {}, {}, include_local_users=False)
        rendered = report.make_html([document], rows, "Client </script><script>alert(1)</script>", None, {}, False)
        self.assertNotIn("local-test-user", rendered)
        self.assertNotIn("</script><script>alert(1)", rendered)
        self.assertIn("\\u003c/script\\u003e", rendered)
        self.assertIn("providerFilter", rendered)
        self.assertIn("Hide acknowledged / justified", rendered)

    def test_report_includes_opted_in_local_user(self) -> None:
        document = observation("TEST-ENDPOINT", "anthropic", "browser_history", {"matched_domain": "claude.ai"})
        providers = {"anthropic": {"name": "Anthropic", "products": ["Claude"]}}
        rows = report.build_rows([document], providers, {}, {}, include_local_users=True)
        self.assertEqual(rows[0]["local_user"], "local-test-user")

    def test_report_does_not_copy_unmatched_review_sidecar_entries(self) -> None:
        document = observation("TEST-ENDPOINT", "anthropic", "browser_extension", {"extension_name": "Claude"})
        providers = {"anthropic": {"name": "Anthropic", "products": ["Claude"]}}
        unrelated_key = "b" * 64
        decisions = {
            unrelated_key: {
                "status": "justified",
                "reviewer": "PRIVATE REVIEWER",
                "reason": "PRIVATE OTHER CLIENT REASON",
                "reviewed_at": "2026-09-20T10:00:00Z",
            }
        }
        rows = report.build_rows([document], providers, {}, decisions, include_local_users=False)
        rendered = report.make_html([document], rows, "Synthetic test", None, decisions, False)
        self.assertNotIn("PRIVATE REVIEWER", rendered)
        self.assertNotIn("PRIVATE OTHER CLIENT REASON", rendered)

    def test_review_decisions_attach_and_stable_key_ignores_version(self) -> None:
        before = observation("TEST-ENDPOINT", "openai", "software", {"display_name": "ChatGPT", "version": "1.0"})
        after = json.loads(json.dumps(before))
        after["findings"][0]["attributes"]["version"] = "2.0"
        self.assertEqual(
            report.stable_finding_key(before, before["findings"][0]),
            report.stable_finding_key(after, after["findings"][0]),
        )
        key = report.stable_finding_key(before, before["findings"][0])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "reviews.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "decisions": [
                            {
                                "finding_key": key,
                                "status": "justified",
                                "reviewer": "Client admin",
                                "reason": "Approved personal AI use",
                                "reviewed_at": "2026-09-20T10:00:00Z",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            decisions = report.load_reviews(path)
        self.assertEqual(decisions[key]["status"], "justified")

    def test_observation_period_filter_and_duplicate_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "observation.json"
            document = observation("TEST-ENDPOINT", "anthropic", "browser_extension", {"extension_name": "Claude"})
            path.write_text(json.dumps(document), encoding="utf-8")
            found = report.load_observations([path, path], "2026-09")
            self.assertEqual(len(found), 1)
            with self.assertRaises(report.ReportError):
                report.load_observations([path], "2026-08")


if __name__ == "__main__":
    unittest.main()
