#!/usr/bin/env python3
"""Bundle the Perl macOS collector into a self-contained RMM Bash script.

The RMM editor runs Bash, not Perl. This generator wraps the canonical Perl
collector in a quoted heredoc, writes it to a mode-0600 temporary file at run
time, and invokes the system Perl interpreter with the original arguments.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import os
import sys
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "dist/rmm-macos-linux/shadow_ai_inventory.pl"
DELIMITER = "__SHADOW_AI_PERL_SOURCE__"


class BundleError(ValueError):
    """Raised when the collector cannot safely be bundled."""


def make_bundle(source: str, *, self_test: bool = False) -> str:
    if DELIMITER in source.splitlines():
        raise BundleError("Perl source contains the reserved shell heredoc delimiter")
    if not source.startswith("#!/usr/bin/perl\n"):
        raise BundleError("Perl source must begin with its expected interpreter line")
    compressed = gzip.compress(source.encode("utf-8"), compresslevel=9, mtime=0)
    payload = "\n".join(textwrap.wrap(base64.b64encode(compressed).decode("ascii"), 76))
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    prefix = f'''#!/bin/bash
set -euo pipefail

tmp_payload="$(/usr/bin/mktemp "${{TMPDIR:-/tmp}}/shadow-ai-inventory.XXXXXX")" || exit 1
tmp_script="$(/usr/bin/mktemp "${{TMPDIR:-/tmp}}/shadow-ai-inventory.XXXXXX")" || {{ /bin/rm -f "$tmp_payload"; exit 1; }}
trap '/bin/rm -f "$tmp_payload" "$tmp_script"' EXIT HUP INT TERM
/bin/cat > "$tmp_payload" <<'{DELIMITER}'
{payload}
{DELIMITER}
/usr/bin/base64 -D -i "$tmp_payload" | /usr/bin/gunzip -c > "$tmp_script"
expected_sha256="{digest}"
actual_sha256="$(/usr/bin/shasum -a 256 "$tmp_script" | /usr/bin/awk '{{print $1}}')"
if [[ "$actual_sha256" != "$expected_sha256" ]]; then
  printf '%s\\n' '{{"error":"fatal:collector_integrity_check_failed","error_id":"integrity_check_failed","command":"verify","parameter":"","line":0}}' >&2
  exit 1
fi
'''
    invocation = '/usr/bin/perl "$tmp_script"'
    invocation += ' --self-test "$@"' if self_test else ' "$@"'
    suffix = f'''{invocation}
exit $?
'''
    return prefix + suffix


def write_bundle(output: Path, *, overwrite: bool = False, self_test: bool = False) -> Path:
    try:
        source = SOURCE.read_text(encoding="utf-8")
    except OSError as exc:
        raise BundleError(f"could not read canonical Perl collector: {exc}") from exc
    bundle = make_bundle(source, self_test=self_test)
    output = output.expanduser().resolve()
    if output.exists() and not overwrite:
        raise BundleError("output exists; pass --overwrite only when replacement is intended")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(bundle)
        os.replace(temporary, output)
        os.chmod(output, 0o600)
    except OSError:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="paste-ready Bash bundle destination")
    parser.add_argument("--self-test", action="store_true", help="build a one-time bundle that always runs Perl self-test mode")
    parser.add_argument("--overwrite", action="store_true", help="replace an existing bundle")
    args = parser.parse_args(argv)
    try:
        output = write_bundle(args.output, overwrite=args.overwrite, self_test=args.self_test)
    except (BundleError, OSError) as exc:
        print(f"Could not build Perl RMM bundle: {exc}", file=sys.stderr)
        return 1
    print(f"Built self-contained RMM Bash bundle: {output}")
    print("The bundle stores the embedded Perl source in a mode-0600 temporary file and removes it on exit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
