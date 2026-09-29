from __future__ import annotations

import csv
import json
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))
import filter_rmm_task_export as task_filter
import build_dashboard_feed
import rmm_output
from test_report import observation


TASK = "Shadow AI Inventory - Windows"


class FilterRmmExportTests(unittest.TestCase):
    def make_manifest(self, root: Path) -> Path:
        manifest = root / "private-clients.json"
        manifest.write_text(json.dumps({
            "schema_version": "1.0",
            "clients": [{
                "client_id": "client-a",
                "client_label": "Client A",
                "rmm_company_unique_id": "company-001",
                "observations": "client-a/observations",
            }],
        }), encoding="utf-8")
        return manifest

    def write_export(self, path: Path, rows: list[dict[str, str]]) -> None:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["company_unique_id", "task_name", "execution_output", "unrelated_column"],
            )
            writer.writeheader()
            writer.writerows(rows)

    def test_filters_exact_task_and_mapped_company_without_copying_other_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "broad.csv"
            output = root / "private" / "shadow-ai.csv"
            doc = observation("HOST-A", "anthropic", "browser_extension", {"extension_name": "Claude"})
            self.write_export(source, [
                {
                    "company_unique_id": "unmapped-company",
                    "task_name": "Unrelated task",
                    "execution_output": "UNRELATED_SECRET_DO_NOT_COPY",
                    "unrelated_column": "also-private",
                },
                {
                    "company_unique_id": "company-001",
                    "task_name": TASK,
                    "execution_output": json.dumps(doc),
                    "unrelated_column": "not-copied",
                },
            ])
            source_before = source.read_bytes()

            self.assertEqual(task_filter.filter_export(source, self.make_manifest(root), TASK, output), (1, 1, 0))

            self.assertEqual(source.read_bytes(), source_before)
            with output.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)
            self.assertEqual(set(rows[0]), {"company_unique_id", "task_name", "execution_output"})
            self.assertEqual(rows[0]["company_unique_id"], "company-001")
            self.assertEqual(rows[0]["task_name"], TASK)
            self.assertEqual(json.loads(rows[0]["execution_output"]), doc)
            self.assertNotIn("UNRELATED_SECRET_DO_NOT_COPY", output.read_text(encoding="utf-8"))
            self.assertNotIn("not-copied", output.read_text(encoding="utf-8"))
            if os.name == "posix":
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                self.assertEqual(output.parent.stat().st_mode & 0o777, 0o700)

    def test_rejects_unmapped_selected_task_without_publishing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "broad.csv"
            output = root / "private" / "shadow-ai.csv"
            self.write_export(source, [{
                "company_unique_id": "unmapped-company",
                "task_name": TASK,
                "execution_output": "{}",
                "unrelated_column": "",
            }])
            with self.assertRaises(task_filter.FilterError):
                task_filter.filter_export(source, self.make_manifest(root), TASK, output)
            self.assertFalse(output.exists())

    def test_rejects_invalid_selected_json_and_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "broad.csv"
            output = root / "private" / "shadow-ai.csv"
            self.write_export(source, [{
                "company_unique_id": "company-001",
                "task_name": TASK,
                "execution_output": "not-json",
                "unrelated_column": "",
            }])
            manifest = self.make_manifest(root)
            with self.assertRaises(task_filter.FilterError):
                task_filter.filter_export(source, manifest, TASK, output)
            self.assertFalse(output.exists())

            output.parent.mkdir(mode=0o700, exist_ok=True)
            output.write_text("keep", encoding="utf-8")
            with self.assertRaises(task_filter.FilterError):
                task_filter.filter_export(source, manifest, TASK, output)
            self.assertEqual(output.read_text(encoding="utf-8"), "keep")

    def test_normalizes_semicolon_separators_only_outside_json_strings(self) -> None:
        document = observation("HOST-A", "anthropic", "browser_extension", {"extension_name": "Claude; Desktop"})
        encoded = json.dumps(document, separators=(",", ":"))
        malformed_export = encoded.replace(',"', ';"')

        parsed = task_filter.parse_scanner_output(malformed_export)

        self.assertEqual(parsed, document)
        self.assertEqual(parsed["findings"][0]["attributes"]["extension_name"], "Claude; Desktop")

    def test_filters_large_compressed_observation_and_writes_validated_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "broad.csv"
            output = root / "private" / "shadow-ai.csv"
            document = observation("HOST-A", "anthropic", "browser_extension", {"extension_name": "Claude"})
            template = document["findings"][0]
            document["findings"] = []
            for _ in range(80):
                finding = json.loads(json.dumps(template))
                finding["finding_id"] = str(uuid.uuid4())
                document["findings"].append(finding)
            compressed = rmm_output.encode_output(json.dumps(document, separators=(",", ":")))
            self.write_export(source, [{
                "company_unique_id": "company-001",
                "task_name": TASK,
                "execution_output": compressed,
                "unrelated_column": "must-not-copy",
            }])

            self.assertEqual(task_filter.filter_export(source, self.make_manifest(root), TASK, output), (1, 0, 0))
            with output.open("r", encoding="utf-8", newline="") as handle:
                row = next(csv.DictReader(handle))
            self.assertFalse(row["execution_output"].startswith(rmm_output.PREFIX))
            self.assertEqual(json.loads(row["execution_output"]), document)

    def test_can_exclude_only_exact_limit_malformed_output_and_reports_incompleteness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "broad.csv"
            output = root / "private" / "shadow-ai.csv"
            valid = observation("HOST-A", "anthropic", "browser_extension", {"extension_name": "Claude"})
            self.write_export(source, [
                {"company_unique_id": "company-001", "task_name": TASK, "execution_output": json.dumps(valid), "unrelated_column": ""},
                {"company_unique_id": "company-001", "task_name": TASK, "execution_output": "x" * task_filter.BRIGHTGAUGE_OUTPUT_CELL_LIMIT, "unrelated_column": ""},
            ])
            with self.assertRaises(task_filter.FilterError):
                task_filter.filter_export(source, self.make_manifest(root), TASK, output)
            self.assertFalse(output.exists())

            result = task_filter.filter_export(source, self.make_manifest(root), TASK, output, allow_truncated_rows=True)
            self.assertEqual(result, (1, 0, 1))
            with output.open("r", encoding="utf-8", newline="") as handle:
                self.assertEqual(len(list(csv.DictReader(handle))), 1)

    def test_rejects_public_repository_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "broad.csv"
            output = ROOT / "should-not-be-created.csv"
            self.write_export(source, [])
            with self.assertRaises(build_dashboard_feed.FeedError):
                task_filter.filter_export(source, self.make_manifest(root), TASK, output)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
