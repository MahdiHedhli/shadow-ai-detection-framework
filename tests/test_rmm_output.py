from __future__ import annotations

import gzip
import random
import string
import sys
import unittest
import base64
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import rmm_output


class RmmOutputTests(unittest.TestCase):
    def test_plain_small_json_remains_backward_compatible(self) -> None:
        self.assertEqual(rmm_output.encode_output('{"schema_version":"1.0"}'), '{"schema_version":"1.0"}')

    def test_large_json_round_trips_under_export_limit(self) -> None:
        raw = '{"payload":"' + ("repeated-observation-value," * 2000) + '"}'
        encoded = rmm_output.encode_output(raw)
        self.assertTrue(encoded.startswith(rmm_output.PREFIX))
        self.assertLess(len(encoded), rmm_output.MAX_TRANSPORT_CHARS)
        self.assertEqual(rmm_output.decode_output(encoded), raw)

    def test_rejects_compression_bombs_and_trailing_members(self) -> None:
        bomb = rmm_output.PREFIX + base64.b64encode(
            gzip.compress(b"x" * (rmm_output.MAX_OBSERVATION_BYTES + 1), mtime=0)
        ).decode("ascii")
        with self.assertRaisesRegex(rmm_output.RmmOutputError, "2 MiB"):
            rmm_output.decode_output(bomb)

        trailing = rmm_output.PREFIX + base64.b64encode(gzip.compress(b"{}") + b"junk").decode("ascii")
        with self.assertRaisesRegex(rmm_output.RmmOutputError, "trailing"):
            rmm_output.decode_output(trailing)

    def test_rejects_malformed_and_oversized_transport_envelopes(self) -> None:
        for raw in (rmm_output.PREFIX + "%%%", rmm_output.PREFIX + "H4sIAAAAAA=="):
            with self.subTest(raw=raw):
                with self.assertRaises(rmm_output.RmmOutputError):
                    rmm_output.decode_output(raw)
        noise = "".join(random.Random(7).choices(string.ascii_letters + string.digits, k=40_000))
        with self.assertRaisesRegex(rmm_output.RmmOutputError, "24,000"):
            rmm_output.encode_output('{"payload":"' + noise + '"}')


if __name__ == "__main__":
    unittest.main()
