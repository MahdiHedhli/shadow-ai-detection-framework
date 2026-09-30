from __future__ import annotations

import json
import os
import re
import shutil
import sys
import subprocess
import tempfile
import unittest
from datetime import datetime
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
        provider_ids = {row["provider_id"] for row in payload["inference_providers"]}
        self.assertTrue({"anthropic", "openai"}.issubset(provider_ids))
        self.assertTrue({"generic", "mcp"}.isdisjoint(provider_ids))
        page = dashboard.make_html(payload)
        self.assertNotIn("PRIVATE-HOST-", page)
        self.assertNotIn("local-test-user", page)
        self.assertNotIn('"_endpoint_key"', page)
        self.assertNotIn('"_observation_id"', page)
        self.assertIn('r.client_id!==client', page)
        self.assertIn("latest scan per endpoint", page)
        self.assertTrue(all("_endpoint_key" not in row and "_observation_id" not in row for row in payload["scans"]))
        self.assertTrue(all("_endpoint_key" not in row and "_observation_id" not in row for row in payload["findings"]))

    def test_filter_defaults_fit_compact_controls(self) -> None:
        self.assertIn('>All providers/products</option>', dashboard.DASHBOARD_HTML)
        self.assertIn('placeholder="Domain, extension ID…"', dashboard.DASHBOARD_HTML)

    def test_approved_provider_filter_is_client_scoped_and_composes_with_review_filters(self) -> None:
        html = dashboard.DASHBOARD_HTML
        self.assertIn('id="baselineProviderFilter" disabled', html)
        self.assertIn('Client\'s approved inference providers', html)
        self.assertIn('if(!clientId){fieldset.disabled=true;', html)
        self.assertIn('baseline=client?selectedBaselineProviders():new Set(),baselineOnly=baselineOnlyObservations(baseline);', html)
        self.assertIn('function baselineOnlyObservations(baseline)', html)
        self.assertIn('row.provider_id==="generic"||row.provider_id==="mcp"', html)
        self.assertIn('[...providers].every(id=>baseline.has(id))', html)
        self.assertIn('baselineOnly.has(`${r.client_id}|${r.observation_id}`)', html)
        self.assertIn('Endpoints with evidence only from selected providers are hidden.', html)
        self.assertIn('Endpoints with additional providers remain visible with all their evidence', html)
        self.assertIn('if(hide&&r.review_status!=="open")return false;', html)
        self.assertIn('localStorage.setItem(`${baselineStoragePrefix}${clientId}`,JSON.stringify(ids))', html)
        self.assertIn('function storedBaselineProviders(clientId)', html)
        self.assertIn('saveBaselineProviders(activeProviderClient)', html)
        self.assertIn('localStorage.removeItem(`${baselineStoragePrefix}${client.client_id}`)', html)
        self.assertIn('baselineSelections.clear();try{for(const client of data.clients)', html)
        self.assertIn('activeProviderClient=null;renderBaselineProviders(false)', html)

    @unittest.skipUnless(shutil.which("node"), "Node.js is required to exercise dashboard JavaScript")
    def test_approved_provider_filter_hides_only_baseline_only_endpoints(self) -> None:
        html = dashboard.DASHBOARD_HTML
        match = re.search(
            r"(function baselineOnlyObservations\(baseline\)\{.*?\})\s*function filteredFindings\(\)",
            html,
            re.DOTALL,
        )
        self.assertIsNotNone(match, "Could not extract the dashboard's provider-baseline function")
        findings = [
            {"client_id": "client-a", "observation_id": "claude-only", "provider_id": "anthropic"},
            {"client_id": "client-a", "observation_id": "claude-only", "provider_id": "generic"},
            {"client_id": "client-a", "observation_id": "mixed", "provider_id": "anthropic"},
            {"client_id": "client-a", "observation_id": "mixed", "provider_id": "openai"},
            {"client_id": "client-a", "observation_id": "openai-only", "provider_id": "openai"},
            {"client_id": "client-b", "observation_id": "claude-only", "provider_id": "anthropic"},
            {"client_id": "client-a", "observation_id": "mcp-only", "provider_id": "mcp"},
        ]
        script = (
            "const data=JSON.parse(process.argv[1]);\n"
            + match.group(1)
            + "\nconsole.log(JSON.stringify([...baselineOnlyObservations(new Set(['anthropic']))].sort()));"
        )
        result = subprocess.run(
            ["node", "-e", script, json.dumps({"findings": findings})],
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(
            json.loads(result.stdout),
            ["client-a|claude-only", "client-b|claude-only"],
        )

    def test_incomplete_source_note_is_visible_and_rendered_as_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = self.make_private_inputs(Path(temporary))
            note = 'Source export incomplete: 1 result excluded <script>alert("x")</script>.'
            payload = dashboard.build_payload(manifest, None, note, ["client-a"])
        page = dashboard.make_html(payload)
        self.assertIn('id="importNotice" hidden', page)
        self.assertIn('$("importNotice").textContent=data.import_note', page)
        self.assertNotIn('Source export incomplete: 1 result excluded <script>', page)
        self.assertIn("Source export incomplete: 1 result excluded", page)
        self.assertIn('new Set(data.incomplete_client_ids||[])', page)
        self.assertIn('Affected client(s): ${affected.join(", ")}.', page)
        self.assertIn('const qualityNotice=incompleteClientIds.has(clientId)?', page)
        self.assertIn("a truncated scanner result for this client was excluded", page)
        self.assertIn('${qualityNotice}<div class="scope">', page)

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
            latest["collector"]["version"] = "0.6.6"
            (root / "client-a" / "observations" / "latest.json").write_text(json.dumps(latest), encoding="utf-8")

            payload = dashboard.build_payload(manifest, None)

        client_a_findings = [row for row in payload["findings"] if row["client_id"] == "client-a"]
        client_a_scans = [row for row in payload["scans"] if row["client_id"] == "client-a"]
        self.assertEqual(len(client_a_findings), 1)
        self.assertEqual(client_a_findings[0]["provider_id"], "openai")
        self.assertEqual(len(client_a_scans), 1)
        self.assertEqual(client_a_scans[0]["scan_status"], "partial")
        self.assertEqual(client_a_scans[0]["collector_version"], "0.6.6")
        self.assertIn('id="collectorVersions"', dashboard.DASHBOARD_HTML)
        self.assertIn('collectorVersions.set(version,(collectorVersions.get(version)||0)+1)', dashboard.DASHBOARD_HTML)
        self.assertIn('if(r.scan_status==="complete"||r.scan_status==="partial")', dashboard.DASHBOARD_HTML)
        self.assertNotIn("PRIVATE-HOST-client-a", dashboard.make_html(payload))

    def test_customer_export_requires_one_client_and_exports_filtered_client_rows(self) -> None:
        html = dashboard.DASHBOARD_HTML
        self.assertIn('$("export").disabled=!$("client").value', html)
        self.assertIn('filteredFindings().filter(r=>r.client_id===clientId)', html)
        self.assertIn('Customer exports are disabled for the all-client view', html)
        self.assertIn('Browser downloads use local default permissions', html)
        self.assertIn('.download-status{grid-column:1/-1', html)
        self.assertIn('$("exportReport").disabled=!$("client").value', html)
        self.assertIn('function exportClientReport()', html)
        self.assertIn('"source_export_quality"', html)
        self.assertIn('incomplete_truncated_scanner_result_excluded', html)
        self.assertIn('const qualityNotice=incompleteClientIds.has(clientId)?', html)
        self.assertIn('${qualityNotice}<div class="scope">', html)
        self.assertIn('a truncated scanner result for this client was excluded', html)
        self.assertNotIn('value===client.client_label&&incompleteClientIds.has(clientId)', html)
        self.assertIn('<label>Endpoints with reported scans</label>', html)
        self.assertIn('filteredFindings().filter(r=>r.client_id===clientId)', html)
        self.assertIn('"baseline_provider_filter"', html)
        self.assertIn('selectedBaselineProviderNames().join("; ")', html)
        self.assertIn('Print / Save as PDF', html)
        self.assertIn('excludes endpoint/local-user identities and reviewer notes', html)
        self.assertIn('pageSize:250', html)
        self.assertIn('Export includes all filtered rows for the selected client.', html)
        self.assertIn('timeZone:"UTC"', html)
        self.assertNotIn('"hostname"', html)
        self.assertNotIn('"local_user"', html)
        self.assertNotIn('"reviewer"', html)
        self.assertNotIn('"reason"', html)

    def test_customer_downloads_attach_blob_links_before_clicking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = dashboard.build_payload(self.make_private_inputs(Path(temporary)), None)
        html = dashboard.make_html(payload)

        self.assertIn("function downloadBlob(blob,filename)", html)
        self.assertIn("link.href=activeDownloadUrl;link.download=filename", html)
        self.assertIn("status.replaceChildren(document.createTextNode", html)
        self.assertIn('id="downloadStatus" role="status" aria-live="polite"', html)
        self.assertIn("downloadBlob(new Blob([csv]", html)
        self.assertIn("downloadBlob(new Blob([report]", html)
        self.assertNotIn("a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)", html)

    def test_current_state_shows_newest_scan_time_in_selected_scope(self) -> None:
        html = dashboard.DASHBOARD_HTML
        self.assertIn('id="kLastScan"', html)
        self.assertIn('id="kLastScanSub"', html)
        self.assertIn('id="refreshTimestamp"', html)
        self.assertIn('data.refreshed_at', html)
        self.assertIn('Dashboard build time unavailable', html)
        self.assertIn('Dashboard rebuilt ${new Intl.DateTimeFormat', html)
        self.assertIn(
            'const newest=scans.filter(s=>s.collected_at&&Number.isFinite(Date.parse(s.collected_at)))',
            html,
        )
        self.assertIn('timeZone:"UTC"', html)
        self.assertIn('No scan timestamp is available in this scope', html)

    def test_payload_records_dashboard_refresh_time_in_utc(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = self.make_private_inputs(Path(temporary))
            payload = dashboard.build_payload(manifest, None)

        refreshed = payload["refreshed_at"]
        self.assertTrue(refreshed.endswith("Z"))
        self.assertIsNotNone(datetime.fromisoformat(refreshed.replace("Z", "+00:00")).tzinfo)

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

    def test_initial_and_reset_sort_show_newest_observations_first(self) -> None:
        html = dashboard.DASHBOARD_HTML
        self.assertIn('<option value="desc" selected>Descending</option>', html)
        self.assertIn('$("sortDirection").value="desc";state.sort="observed_at"', html)

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
