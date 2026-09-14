from __future__ import annotations

import csv
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UPDATER_PATH = ROOT / "tools" / "update_browser_extension_history.py"
SPEC = importlib.util.spec_from_file_location("shadow_ai_extension_history", UPDATER_PATH)
assert SPEC and SPEC.loader
updater = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = updater
SPEC.loader.exec_module(updater)


class ExtensionHistoryTests(unittest.TestCase):
    def test_extension_id_from_url(self) -> None:
        extension_id = "hehggadaopoacecdllhhajmbjkdcmajg"
        self.assertEqual(
            updater.extension_id_from_url(f"https://chromewebstore.google.com/detail/chatgpt/{extension_id}?hl=en"),
            extension_id,
        )
        self.assertIsNone(updater.extension_id_from_url("https://example.invalid/no-extension"))

    def test_redirected_id_is_history_and_review_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            catalog = root / "browser_extensions.csv"
            history = root / "browser_extension_history.csv"
            candidates = root / "browser_extension_candidates.csv"
            old_id = "a" * 32
            new_id = "b" * 32
            with catalog.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=(
                        "extension_id",
                        "provider_id",
                        "browser",
                        "extension_name",
                        "source_url",
                        "last_validated",
                        "notes",
                    ),
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "extension_id": old_id,
                        "provider_id": "example",
                        "browser": "chromium-family",
                        "extension_name": "Example AI",
                        "source_url": f"https://chromewebstore.google.com/detail/example/{old_id}",
                        "last_validated": "2026-09-14",
                        "notes": "test",
                    }
                )

            original_paths = updater.CATALOG_PATH, updater.HISTORY_PATH, updater.CANDIDATE_PATH
            updater.CATALOG_PATH, updater.HISTORY_PATH, updater.CANDIDATE_PATH = catalog, history, candidates
            try:
                checked, candidate_count = updater.update_inventory(
                    fetcher=lambda _url, _timeout: updater.FetchResult(
                        200,
                        f"https://chromewebstore.google.com/detail/example/{new_id}",
                        b"Example AI",
                    )
                )
            finally:
                updater.CATALOG_PATH, updater.HISTORY_PATH, updater.CANDIDATE_PATH = original_paths

            self.assertEqual(checked, 1)
            self.assertEqual(candidate_count, 1)
            with history.open("r", encoding="utf-8", newline="") as handle:
                history_rows = list(csv.DictReader(handle))
            with candidates.open("r", encoding="utf-8", newline="") as handle:
                candidate_rows = list(csv.DictReader(handle))
            self.assertEqual(history_rows[0]["verification_status"], "redirected_id_review_required")
            self.assertEqual(candidate_rows[0]["extension_id"], new_id)
            self.assertEqual(candidate_rows[0]["status"], "review_required")

    def test_workflow_actions_are_commit_pinned(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "update-browser-extension-inventory.yml").read_text(
            encoding="utf-8"
        )
        uses_lines = [line.strip() for line in workflow.splitlines() if line.strip().startswith("uses:")]
        self.assertTrue(uses_lines)
        for line in uses_lines:
            reference = line.rsplit("@", 1)[-1]
            self.assertRegex(reference, r"^[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
