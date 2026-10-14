"""Shannon entropy, overall and per block."""

from __future__ import annotations

import math
from collections import Counter

# Formats that are compressed or encrypted by design; high entropy is expected there.
NATURALLY_DENSE = {
    "jpeg", "png", "gif", "webp", "heic", "avif", "jp2", "zip", "rar", "7z", "gzip", "bzip2", "xz",
    "zstd", "lz4", "cab", "docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "odt", "ods", "odp",
    "epub", "jar", "apk", "mp3", "aac", "flac", "ogg", "m4a", "mp4", "mov", "3gp", "mkv", "webm",
    "woff", "woff2", "pdf", "flv", "mpegts", "avi",
}  # fmt: skip

HIGH_ENTROPY = 7.2
MAX_BLOCKS = 256
MIN_BLOCK = 1024  # smaller blocks bias entropy low: 256 random bytes only reach ~7.2


def shannon(counts: Counter | list[int], total: int) -> float:
    if total <= 0:
        return 0.0
    ent = 0.0
    for c in counts.values() if isinstance(counts, Counter) else counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return ent


def block_size_for(n: int) -> int:
    size = MIN_BLOCK
    while n / size > MAX_BLOCKS:
        size *= 2
    return size


def analyze_entropy(data: bytes, type_id: str = "unknown") -> dict:
    n = len(data)
    if n == 0:
        return {
            "overall": 0.0,
            "block_size": 0,
            "blocks": [],
            "high_blocks": 0,
            "assessment": "empty",
            "likely_packed_or_encrypted": False,
        }
    bs = block_size_for(n)
    total: Counter = Counter()
    blocks: list[float] = []
    view = memoryview(data)
    for i in range(0, n, bs):
        chunk = view[i : i + bs]
        c = Counter(chunk)
        total.update(c)
        blocks.append(round(shannon(c, len(chunk)), 3))
    overall = shannon(total, n)
    high_blocks = sum(1 for b in blocks if b >= HIGH_ENTROPY)
    high_ratio = high_blocks / len(blocks)

    expected_dense = type_id in NATURALLY_DENSE
    likely = False
    if n >= 1024 and not expected_dense and (overall >= HIGH_ENTROPY or high_ratio >= 0.5):
        likely = True
        assessment = "high entropy for this file type: likely packed, compressed or encrypted content"
    elif overall >= HIGH_ENTROPY and expected_dense:
        assessment = "high entropy, expected for a compressed format"
    elif overall >= 6.0:
        assessment = "moderate entropy (typical of binaries and mixed content)"
    elif overall >= 4.0:
        assessment = "low-moderate entropy (typical of text and structured data)"
    else:
        assessment = "low entropy (sparse or highly repetitive data)"

    return {
        "overall": round(overall, 4),
        "block_size": bs,
        "blocks": blocks,
        "high_blocks": high_blocks,
        "high_threshold": HIGH_ENTROPY,
        "assessment": assessment,
        "likely_packed_or_encrypted": likely,
    }
