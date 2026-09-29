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
import build_dashboard_feed
import discover_rmm_clients


TASK = "Shadow AI Inventory - Windows"


class DiscoverRmmClientsTests(unittest.TestCase):
    def write_export(self, path: Path, rows: list[dict[str, str]]) -> None:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["company_unique_id", "company_name", "task_name", "execution_output"],
            )
            writer.writeheader()
            writer.writerows(rows)

    def test_only_exact_task_company_names_and_ids_are_written_privately(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "broad.csv"
            output = root / "private" / "clients.json"
            self.write_export(source, [
                {
                    "company_unique_id": "irrelevant-company",
                    "company_name": "Unrelated Client",
                    "task_name": "Unrelated Task",
                    "execution_output": "UNRELATED_SECRET_DO_NOT_COPY",
                },
                {
                    "company_unique_id": "company-002",
                    "company_name": "Client B",
                    "task_name": TASK,
                    "execution_output": "SCANNER_JSON_NOT_RETAINED",
                },
                {
                    "company_unique_id": "company-001",
                    "company_name": "Client A",
                    "task_name": TASK,
                    "execution_output": "SCANNER_JSON_NOT_RETAINED",
                },
                {
                    "company_unique_id": "company-001",
                    "company_name": "Client A",
                    "task_name": TASK,
                    "execution_output": "ANOTHER_SCANNER_JSON_NOT_RETAINED",
                },
            ])
            original = source.read_bytes()

            self.assertEqual(discover_rmm_clients.write_manifest(source, TASK, output), 2)

            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["schema_version"], "1.0")
            self.assertEqual([client["client_label"] for client in data["clients"]], ["Client A", "Client B"])
            self.assertEqual({client["rmm_company_unique_id"] for client in data["clients"]}, {"company-001", "company-002"})
            self.assertTrue(all(client["client_id"].startswith("rmm-") for client in data["clients"]))
            self.assertEqual(len(build_dashboard_feed.load_manifest(output)), 2)
            self.assertNotIn("UNRELATED_SECRET_DO_NOT_COPY", output.read_text(encoding="utf-8"))
            self.assertNotIn("SCANNER_JSON_NOT_RETAINED", output.read_text(encoding="utf-8"))
            self.assertEqual(source.read_bytes(), original)
            if os.name == "posix":
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                self.assertEqual(output.parent.stat().st_mode & 0o777, 0o700)

    def test_rejects_ambiguous_company_names_and_wrong_or_empty_task(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "broad.csv"
            self.write_export(source, [
                {"company_unique_id": "company-001", "company_name": "Same", "task_name": TASK, "execution_output": "x"},
                {"company_unique_id": "company-002", "company_name": "same", "task_name": TASK, "execution_output": "y"},
            ])
            with self.assertRaises(discover_rmm_clients.DiscoveryError):
                discover_rmm_clients.discover_clients(source, TASK)
            with self.assertRaises(discover_rmm_clients.DiscoveryError):
                discover_rmm_clients.discover_clients(source, "Other exact task")

    def test_accepts_printable_display_name_company_ids_from_brightgauge(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "broad.csv"
            company = "Client A & Partners, LLC"
            self.write_export(source, [{
                "company_unique_id": company,
                "company_name": company,
                "task_name": TASK,
                "execution_output": "not copied",
            }])

            self.assertEqual(discover_rmm_clients.write_manifest(source, TASK, root / "private" / "clients.json"), 1)
            clients = build_dashboard_feed.load_manifest(root / "private" / "clients.json")
            self.assertEqual(clients[0]["rmm_company_unique_id"], company)

    def test_rejects_formula_prefixed_or_control_character_company_ids(self) -> None:
        for invalid in ("=Client Name", "@Client Name", "Client\nName"):
            with self.subTest(invalid=repr(invalid)), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "broad.csv"
                self.write_export(source, [{
                    "company_unique_id": invalid,
                    "company_name": "Client Name",
                    "task_name": TASK,
                    "execution_output": "not copied",
                }])
                with self.assertRaises(discover_rmm_clients.DiscoveryError):
                    discover_rmm_clients.discover_clients(source, TASK)

    def test_refuses_existing_output_and_public_repository_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "broad.csv"
            self.write_export(source, [{
                "company_unique_id": "company-001",
                "company_name": "Client A",
                "task_name": TASK,
                "execution_output": "secret",
            }])
            existing = root / "clients.json"
            existing.write_text("keep", encoding="utf-8")
            with self.assertRaises(discover_rmm_clients.DiscoveryError):
                discover_rmm_clients.write_manifest(source, TASK, existing)
            self.assertEqual(existing.read_text(encoding="utf-8"), "keep")
            with self.assertRaises(build_dashboard_feed.FeedError):
                discover_rmm_clients.write_manifest(source, TASK, ROOT / "clients.json")
            self.assertFalse((ROOT / "clients.json").exists())


if __name__ == "__main__":
    unittest.main()
