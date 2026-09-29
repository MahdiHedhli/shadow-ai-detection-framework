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
import build_internal_dashboard as dashboard
from test_report import observation


class InternalDashboardTests(unittest.TestCase):
    def make_private_inputs(self, root: Path) -> Path:
        clients = []
        for index, client_id in enumerate(("client-a", "client-b")):
            archive = root / client_id / "observations"
            archive.mkdir(parents=True)
            document = observation(
                f"PRIVATE-HOST-{client_id}",
                "anthropic" if index == 0 else "openai",
                "browser_extension",
                {
                    "browser": "chrome",
                    "extension_name": "Claude" if index == 0 else "ChatGPT",
                    "extension_id": f"{index + 1:032x}",
                    "matched_domain": "claude.ai" if index == 0 else "chatgpt.com",
                },
            )
            (archive / "scan.json").write_text(json.dumps(document), encoding="utf-8")
            clients.append({
                "client_id": client_id,
                "client_label": f"Client {index + 1}",
                "observations": f"{client_id}/observations",
            })
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps({"schema_version": "1.0", "clients": clients}), encoding="utf-8")
        return manifest

    def test_payload_preserves_client_scope_and_omits_endpoint_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = self.make_private_inputs(Path(temporary))
            payload = dashboard.build_payload(manifest, None)

        self.assertEqual(len(payload["clients"]), 2)
        self.assertEqual(len(payload["findings"]), 2)
        self.assertEqual({row["client_id"] for row in payload["findings"]}, {"client-a", "client-b"})
        self.assertEqual(len(payload["scans"]), 2)
        page = dashboard.make_html(payload)
        self.assertNotIn("PRIVATE-HOST-", page)
        self.assertNotIn("local-test-user", page)
        self.assertIn('r.client_id!==client', page)
        self.assertIn("latest scan per endpoint", page)
        self.assertTrue(all("_endpoint_key" not in row and "_observation_id" not in row for row in payload["scans"]))

    def test_incomplete_source_note_is_visible_and_rendered_as_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = self.make_private_inputs(Path(temporary))
            note = 'Source export incomplete: 1 result excluded <script>alert("x")</script>.'
            payload = dashboard.build_payload(manifest, None, note)
        page = dashboard.make_html(payload)
        self.assertIn('id="importNotice" hidden', page)
        self.assertIn('$("importNotice").textContent=data.import_note', page)
        self.assertNotIn('Source export incomplete: 1 result excluded <script>', page)
        self.assertIn("Source export incomplete: 1 result excluded", page)

    def test_payload_uses_only_latest_scan_per_endpoint_without_backfilling_partial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.make_private_inputs(root)
            latest = observation(
                "PRIVATE-HOST-client-a",
                "openai",
                "browser_history",
                {"matched_domain": "chatgpt.com", "browser": "chrome"},
            )
            latest["collected_at"] = "2026-09-29T12:00:00.000Z"
            latest["findings"][0]["observed_at"] = latest["collected_at"]
            latest["collector"]["partial"] = True
            (root / "client-a" / "observations" / "latest.json").write_text(json.dumps(latest), encoding="utf-8")

            payload = dashboard.build_payload(manifest, None)

        client_a_findings = [row for row in payload["findings"] if row["client_id"] == "client-a"]
        client_a_scans = [row for row in payload["scans"] if row["client_id"] == "client-a"]
        self.assertEqual(len(client_a_findings), 1)
        self.assertEqual(client_a_findings[0]["provider_id"], "openai")
        self.assertEqual(len(client_a_scans), 1)
        self.assertEqual(client_a_scans[0]["scan_status"], "partial")
        self.assertNotIn("PRIVATE-HOST-client-a", dashboard.make_html(payload))

    def test_customer_export_requires_one_client_and_exports_filtered_client_rows(self) -> None:
        html = dashboard.DASHBOARD_HTML
        self.assertIn('$("export").disabled=!$("client").value', html)
        self.assertIn('filteredFindings().filter(r=>r.client_id===clientId)', html)
        self.assertIn('Customer CSV export is disabled for the all-client view', html)
        self.assertIn('pageSize:250', html)
        self.assertIn('Export includes all filtered rows for the selected client.', html)
        self.assertIn('timeZone:"UTC"', html)
        self.assertNotIn('"hostname"', html)
        self.assertNotIn('"local_user"', html)
        self.assertNotIn('"reviewer"', html)
        self.assertNotIn('"reason"', html)

    def test_current_state_shows_newest_scan_time_in_selected_scope(self) -> None:
        html = dashboard.DASHBOARD_HTML
        self.assertIn('id="kLastScan"', html)
        self.assertIn('id="kLastScanSub"', html)
        self.assertIn(
            'const newest=scans.filter(s=>s.collected_at&&Number.isFinite(Date.parse(s.collected_at)))',
            html,
        )
        self.assertIn('timeZone:"UTC"', html)
        self.assertIn('No scan timestamp is available in this scope', html)

    def test_client_comparison_can_sort_by_oldest_latest_endpoint_scan(self) -> None:
        html = dashboard.DASHBOARD_HTML
        self.assertIn('data-client-sort="oldest_latest_scan_at"', html)
        self.assertIn('Oldest latest scan (UTC)', html)
        self.assertIn('const x=a[clientSort.key],y=b[clientSort.key];let cmp;', html)
        self.assertIn('if(!x||!y)return x? -1:y?1:a.client_label.localeCompare(b.client_label)', html)
        self.assertIn('cmp=Date.parse(x)-Date.parse(y)', html)
        self.assertIn('"No scan timestamp"', html)

    def test_numeric_finding_columns_sort_by_value_not_lexical_order(self) -> None:
        html = dashboard.DASHBOARD_HTML
        self.assertIn(
            'if(key==="confidence_rank"||key==="evidence_level")return Number(row[key]||0);',
            html,
        )
        self.assertNotIn('||key==="evidence_level")return String(row[key]', html)

    def test_no_observation_status_remains_explicit_for_empty_client_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.make_private_inputs(root)
            (root / "client-b" / "observations" / "scan.json").unlink()
            payload = dashboard.build_payload(manifest, "2026-09")

        missing = next(row for row in payload["scans"] if row["client_id"] == "client-b")
        self.assertEqual(missing["scan_status"], "no_observations")
        self.assertEqual(missing["period"], "2026-09")
        self.assertIn('function filteredScans(){const client=$("client").value;', dashboard.DASHBOARD_HTML)
        self.assertNotIn('id="period"', dashboard.DASHBOARD_HTML)

    def test_payload_is_script_safe_and_offline_only(self) -> None:
        payload = {"clients": [], "findings": [{"client_label": "</script><script>alert(1)</script>"}], "scans": []}
        html = dashboard.make_html(payload)
        self.assertNotIn("</script><script>alert(1)", html)
        self.assertIn("connect-src 'none'", html)
        self.assertNotIn("https://", html)

    def test_private_output_permissions_and_implicit_overwrite_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "dashboard"
            parent.mkdir(mode=0o700)
            path = dashboard.write_dashboard(parent / "index.html", "private", False)
            self.assertEqual(path.read_text(encoding="utf-8"), "private")
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(parent.stat().st_mode & 0o777, 0o700)
            with self.assertRaises(dashboard.build_dashboard_feed.FeedError):
                dashboard.write_dashboard(path, "replacement", False)
            self.assertEqual(path.read_text(encoding="utf-8"), "private")

    def test_refuses_weak_output_directory_and_repository_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            public = Path(temporary) / "shared"
            public.mkdir(mode=0o755)
            if os.name == "posix":
                public.chmod(0o755)
                with self.assertRaises(dashboard.build_dashboard_feed.FeedError):
                    dashboard.write_dashboard(public / "index.html", "private", False)
        with self.assertRaises(dashboard.build_dashboard_feed.FeedError):
            dashboard.write_dashboard(ROOT / "reports" / "internal.html", "private", False)


if __name__ == "__main__":
    unittest.main()
