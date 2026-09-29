#!/usr/bin/env python3
"""Bounded codec for oversized Shadow AI RMM observations."""

from __future__ import annotations

import base64
import binascii
import gzip
import zlib


PREFIX = "SHADOWAI_GZIP_V1:"
COMPRESS_THRESHOLD_BYTES = 12_000
MAX_TRANSPORT_CHARS = 24_000
MAX_OBSERVATION_BYTES = 2 * 1024 * 1024


class RmmOutputError(ValueError):
    """Raised when an RMM transport envelope is invalid or exceeds limits."""


def encode_output(raw_json: str) -> str:
    """Encode JSON only when it is large enough to risk export truncation."""
    raw = raw_json.encode("utf-8")
    if len(raw) > MAX_OBSERVATION_BYTES:
        raise RmmOutputError("observation exceeds the 2 MiB limit")
    if len(raw) <= COMPRESS_THRESHOLD_BYTES:
        return raw_json
    envelope = PREFIX + base64.b64encode(gzip.compress(raw, compresslevel=9, mtime=0)).decode("ascii")
    if len(envelope) > MAX_TRANSPORT_CHARS:
        raise RmmOutputError("compressed observation exceeds the 24,000-character RMM safety limit")
    return envelope


def decode_output(raw: str) -> str:
    """Decode a bounded, single-member gzip envelope; pass legacy JSON through."""
    if not raw.startswith(PREFIX):
        return raw
    encoded = raw[len(PREFIX):]
    if not encoded or len(raw) > MAX_TRANSPORT_CHARS:
        raise RmmOutputError("compressed observation has an invalid transport length")
    try:
        compressed = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RmmOutputError("compressed observation is not valid base64") from exc

    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        decoded = decompressor.decompress(compressed, MAX_OBSERVATION_BYTES + 1)
    except zlib.error as exc:
        raise RmmOutputError("compressed observation is not a valid gzip stream") from exc
    if len(decoded) > MAX_OBSERVATION_BYTES or decompressor.unconsumed_tail:
        raise RmmOutputError("decompressed observation exceeds the 2 MiB limit")
    if not decompressor.eof:
        raise RmmOutputError("compressed observation is incomplete")
    if decompressor.unused_data:
        raise RmmOutputError("compressed observation has trailing data")
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RmmOutputError("compressed observation is not UTF-8") from exc
