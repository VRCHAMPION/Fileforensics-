"""Streamed cryptographic hashes."""

from __future__ import annotations

import hashlib
from typing import BinaryIO

CHUNK = 64 * 1024


def _hashers() -> dict:
    # MD5/SHA-1 are identifiers here (VirusTotal, threat-intel lookups), not security controls.
    return {
        "md5": hashlib.md5(usedforsecurity=False),
        "sha1": hashlib.sha1(usedforsecurity=False),
        "sha256": hashlib.sha256(),
    }


def hash_bytes(data: bytes | memoryview) -> dict[str, str]:
    """Hash an in-memory buffer chunk by chunk (no extra copies of the payload)."""
    hs = _hashers()
    view = memoryview(data)
    for i in range(0, len(view), CHUNK):
        chunk = view[i : i + CHUNK]
        for h in hs.values():
            h.update(chunk)
    return {name: h.hexdigest() for name, h in hs.items()}


def hash_stream(fh: BinaryIO) -> dict[str, str]:
    hs = _hashers()
    while True:
        chunk = fh.read(CHUNK)
        if not chunk:
            break
        for h in hs.values():
            h.update(chunk)
    return {name: h.hexdigest() for name, h in hs.items()}
