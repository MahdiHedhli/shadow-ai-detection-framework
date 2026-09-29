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
import import_rmm_task_export as importer
from test_report import observation
import rmm_output


TASK = "Shadow AI Inventory - Windows"


class RmmImportTests(unittest.TestCase):
    def make_manifest(self, root: Path) -> Path:
        manifest = root / "rmm-clients.json"
        manifest.write_text(json.dumps({
            "schema_version": "1.0",
            "clients": [
                {
                    "client_id": "client-a",
                    "client_label": "Client A",
                    "rmm_company_unique_id": "company-001",
                    "observations": "client-a/observations",
                },
                {
                    "client_id": "client-b",
                    "client_label": "Client B",
                    "rmm_company_unique_id": "company-002",
                    "observations": "client-b/observations",
                },
            ],
        }), encoding="utf-8")
        return manifest

    def make_csv(self, path: Path, rows: list[dict[str, str]]) -> None:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["company_unique_id", "task_name", "execution_output"])
            writer.writeheader()
            writer.writerows(rows)

    def test_exact_task_allowlist_rejects_duplicates_and_formula_prefixes(self) -> None:
        for names in ([TASK, TASK], ["=unsafe task"]):
            with self.subTest(names=names), self.assertRaises(importer.ImportError):
                importer.normalize_task_names(names)

    def test_import_archives_only_valid_mapped_rows_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.make_manifest(root)
            output = root / "automation.csv"
            documents = [
                observation("PRIVATE-HOST-A", "anthropic", "browser_extension", {"extension_name": "Claude"}),
                observation("PRIVATE-HOST-B", "openai", "browser_history", {"matched_domain": "chatgpt.com"}),
            ]
            self.make_csv(output, [
                {"company_unique_id": "company-001", "task_name": TASK, "execution_output": json.dumps(documents[0])},
                {"company_unique_id": "company-002", "task_name": TASK, "execution_output": json.dumps(documents[1])},
            ])

            self.assertEqual(importer.import_export(output, manifest, TASK), (2, 0))
            self.assertEqual(importer.import_export(output, manifest, TASK), (0, 2))
            first = root / "client-a/observations" / f"{documents[0]['observation_id']}.json"
            second = root / "client-b/observations" / f"{documents[1]['observation_id']}.json"
            self.assertTrue(first.exists())
            self.assertTrue(second.exists())
            self.assertEqual(json.loads(first.read_text(encoding="utf-8")), documents[0])
            if os.name == "posix":
                self.assertEqual(first.stat().st_mode & 0o777, 0o600)
                self.assertEqual(first.parent.stat().st_mode & 0o777, 0o700)

    def test_import_accepts_multiple_explicit_exact_task_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.make_manifest(root)
            output = root / "automation.csv"
            windows = observation("PRIVATE-WINDOWS", "anthropic", "browser_extension", {"extension_name": "Claude"})
            macos = observation("PRIVATE-MACOS", "openai", "browser_history", {"matched_domain": "chatgpt.com"})
            self.make_csv(output, [
                {"company_unique_id": "company-001", "task_name": TASK, "execution_output": json.dumps(windows)},
                {"company_unique_id": "company-001", "task_name": "Shadow AI Inventory - macOS (Perl)", "execution_output": json.dumps(macos)},
            ])

            self.assertEqual(
                importer.import_export(output, manifest, [TASK, "Shadow AI Inventory - macOS (Perl)"]),
                (2, 0),
            )
            self.assertTrue((root / "client-a/observations" / f"{windows['observation_id']}.json").exists())
            self.assertTrue((root / "client-a/observations" / f"{macos['observation_id']}.json").exists())

    def test_import_decodes_large_transport_and_archives_plain_validated_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.make_manifest(root)
            export = root / "automation.csv"
            document = observation("PRIVATE-HOST", "anthropic", "browser_extension", {"extension_name": "Claude"})
            template = document["findings"][0]
            document["findings"] = []
            for _ in range(80):
                finding = json.loads(json.dumps(template))
                finding["finding_id"] = str(uuid.uuid4())
                document["findings"].append(finding)
            plain = json.dumps(document, separators=(",", ":"))
            compressed = rmm_output.encode_output(plain)
            self.assertGreater(len(plain), rmm_output.COMPRESS_THRESHOLD_BYTES)
            self.assertLess(len(compressed), 30_000)
            self.assertTrue(compressed.startswith(rmm_output.PREFIX))
            self.make_csv(export, [{
                "company_unique_id": "company-001",
                "task_name": TASK,
                "execution_output": compressed,
            }])

            self.assertEqual(importer.import_export(export, manifest, TASK), (1, 0))
            archived = root / "client-a/observations" / f"{document['observation_id']}.json"
            stored = json.loads(archived.read_text(encoding="utf-8"))
            self.assertEqual(stored, document)
            self.assertEqual(len(stored["findings"]), 80)
            self.assertFalse(archived.read_text(encoding="utf-8").startswith(rmm_output.PREFIX))

    def test_rejects_unrelated_tasks_unmapped_companies_and_bad_json_before_writing(self) -> None:
        cases = [
            {"company_unique_id": "company-001", "task_name": "Other RMM task", "execution_output": "{}"},
            {"company_unique_id": "unknown-company", "task_name": TASK, "execution_output": "{}"},
            {"company_unique_id": "company-001", "task_name": TASK, "execution_output": "not JSON"},
        ]
        for row in cases:
            with self.subTest(row=row["task_name"]):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    manifest = self.make_manifest(root)
                    export = root / "automation.csv"
                    self.make_csv(export, [row])
                    with self.assertRaises(importer.ImportError):
                        importer.import_export(export, manifest, TASK)
                    self.assertFalse((root / "client-a").exists())
                    self.assertFalse((root / "client-b").exists())

    def test_rejects_wrong_headers_conflicting_duplicate_ids_and_unscoped_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.make_manifest(root)
            export = root / "automation.csv"
            export.write_text("company_unique_id,task_name\ncompany-001,Other\n", encoding="utf-8")
            with self.assertRaisesRegex(importer.ImportError, "missing required columns"):
                importer.import_export(export, manifest, TASK)

            document = observation("PRIVATE-HOST", "anthropic", "software", {"display_name": "Claude"})
            changed = json.loads(json.dumps(document))
            changed["device"]["hostname"] = "DIFFERENT-HOST"
            self.make_csv(export, [
                {"company_unique_id": "company-001", "task_name": TASK, "execution_output": json.dumps(document)},
                {"company_unique_id": "company-001", "task_name": TASK, "execution_output": json.dumps(changed)},
            ])
            with self.assertRaisesRegex(importer.ImportError, "conflicting content"):
                importer.import_export(export, manifest, TASK)
            self.assertFalse((root / "client-a").exists())

            unscoped = root / "unscoped.json"
            unscoped.write_text(json.dumps({
                "schema_version": "1.0",
                "clients": [{"client_id": "client-a", "client_label": "Client A", "observations": "client-a/observations"}],
            }), encoding="utf-8")
            with self.assertRaisesRegex(importer.ImportError, "rmm_company_unique_id"):
                importer.load_clients(unscoped)

    def test_rejects_duplicate_rmm_company_ids_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.make_manifest(root)
            data = json.loads(manifest.read_text(encoding="utf-8"))
            data["clients"][1]["rmm_company_unique_id"] = "company-001"
            manifest.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(importer.build_dashboard_feed.FeedError, "duplicate rmm_company_unique_id"):
                importer.load_clients(manifest)

    def test_rejects_same_observation_id_across_different_client_mappings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.make_manifest(root)
            export = root / "automation.csv"
            document = observation("PRIVATE-HOST", "anthropic", "software", {"display_name": "Claude"})
            self.make_csv(export, [
                {"company_unique_id": "company-001", "task_name": TASK, "execution_output": json.dumps(document)},
                {"company_unique_id": "company-002", "task_name": TASK, "execution_output": json.dumps(document)},
            ])
            with self.assertRaisesRegex(importer.ImportError, "maps to multiple clients"):
                importer.import_export(export, manifest, TASK)
            self.assertFalse((root / "client-a").exists())
            self.assertFalse((root / "client-b").exists())

    def test_public_repo_paths_are_rejected(self) -> None:
        with self.assertRaises(importer.build_dashboard_feed.FeedError):
            importer.read_export(ROOT / "automation.csv", TASK, {})


if __name__ == "__main__":
    unittest.main()
