"""Bounded, in-memory ZIP inspection.

Nothing is ever extracted to disk. The central directory is read for metadata,
and the few members we actually need (OOXML relationship parts, ``mimetype``)
are read through a hard byte cap, so a lying header or a decompression bomb
can only ever cost us ``max_member_read`` bytes of RAM per member.
"""

from __future__ import annotations

import io
import struct
import zipfile
import zlib
from dataclasses import dataclass, field

ARCHIVE_EXTS = (".zip", ".rar", ".7z", ".gz", ".tgz", ".bz2", ".xz", ".tar", ".cab", ".iso", ".jar")


@dataclass(frozen=True)
class ZipLimits:
    max_entries: int = 2000
    max_total_uncompressed: int = 256 * 1024 * 1024
    max_ratio: float = 100.0
    max_member_read: int = 2 * 1024 * 1024
    report_entries: int = 100


@dataclass
class ZipInspection:
    ok: bool = False
    entry_count: int = 0
    names: list[str] = field(default_factory=list)
    entries: list[dict] = field(default_factory=list)
    total_compressed: int = 0
    total_uncompressed: int = 0
    max_entry_ratio: float = 0.0
    encrypted_entries: int = 0
    nested_archives: list[str] = field(default_factory=list)
    overlapping_entries: int = 0
    bomb_reasons: list[str] = field(default_factory=list)
    archive_offset: int = 0
    error: str | None = None
    zf: zipfile.ZipFile | None = field(default=None, repr=False)

    def to_report(self) -> dict:
        return {
            "entry_count": self.entry_count,
            "entries": self.entries,
            "total_compressed": self.total_compressed,
            "total_uncompressed_declared": self.total_uncompressed,
            "max_entry_ratio": round(self.max_entry_ratio, 1),
            "encrypted_entries": self.encrypted_entries,
            "nested_archives": self.nested_archives[:50],
            "overlapping_entries": self.overlapping_entries,
            "bomb_indicators": self.bomb_reasons,
            "archive_offset": self.archive_offset,
            "error": self.error,
        }


def _eocd_entry_count(data: bytes) -> int | None:
    """Read the 'total entries' field of the End Of Central Directory record."""
    tail_start = max(0, len(data) - 65557)
    pos = data.rfind(b"PK\x05\x06", tail_start)
    if pos < 0 or pos + 22 > len(data):
        return None
    return struct.unpack_from("<H", data, pos + 10)[0]


def inspect_zip(data: bytes, limits: ZipLimits | None = None) -> ZipInspection:
    limits = limits or ZipLimits()
    result = ZipInspection()

    declared = _eocd_entry_count(data)
    if declared is not None and declared != 0xFFFF and declared > limits.max_entries:
        result.entry_count = declared
        result.bomb_reasons.append(
            f"central directory declares {declared} entries (limit {limits.max_entries}); not parsed"
        )
        result.error = "too many entries"
        return result

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except Exception as exc:  # zipfile raises a zoo of types on hostile input (NotImplementedError, KeyError, ...)
        result.error = f"not a readable zip: {type(exc).__name__}"
        return result

    result.ok = True
    result.zf = zf
    result.entry_count = len(infos)
    if len(infos) > limits.max_entries:
        result.bomb_reasons.append(f"{len(infos)} entries exceeds limit of {limits.max_entries}")
        infos = infos[: limits.max_entries]

    offsets: dict[int, int] = {}
    min_offset = None
    for info in infos:
        name = info.filename
        result.names.append(name)
        comp = max(info.compress_size, 0)
        uncomp = max(info.file_size, 0)
        result.total_compressed += comp
        result.total_uncompressed += uncomp
        ratio = (uncomp / comp) if comp else (float(uncomp) if uncomp else 0.0)
        if uncomp >= 1024 * 1024:
            result.max_entry_ratio = max(result.max_entry_ratio, ratio)
        encrypted = bool(info.flag_bits & 0x1)
        result.encrypted_entries += int(encrypted)
        if name.lower().endswith(ARCHIVE_EXTS):
            result.nested_archives.append(name)
        offsets[info.header_offset] = offsets.get(info.header_offset, 0) + 1
        if min_offset is None or info.header_offset < min_offset:
            min_offset = info.header_offset
        if len(result.entries) < limits.report_entries:
            result.entries.append(
                {
                    "name": name[:256],
                    "compressed": comp,
                    "uncompressed": uncomp,
                    "ratio": round(ratio, 1),
                    "encrypted": encrypted,
                }
            )

    result.overlapping_entries = sum(c - 1 for c in offsets.values() if c > 1)
    # Bytes before the first local header usually mean something was glued in front.
    if min_offset is not None:
        local = data.find(b"PK\x03\x04")
        result.archive_offset = local if local > 0 else 0

    if result.total_uncompressed > limits.max_total_uncompressed:
        result.bomb_reasons.append(
            f"declared uncompressed size {result.total_uncompressed} bytes exceeds "
            f"{limits.max_total_uncompressed} bytes"
        )
    if result.max_entry_ratio > limits.max_ratio:
        result.bomb_reasons.append(f"compression ratio {result.max_entry_ratio:.0f}:1 exceeds {limits.max_ratio:.0f}:1")
    if result.overlapping_entries:
        result.bomb_reasons.append(
            f"{result.overlapping_entries} central directory entries point at the same local header "
            "(overlapping-file bomb technique)"
        )
    return result


def read_member(zf: zipfile.ZipFile, name: str, limit: int) -> bytes | None:
    """Read at most ``limit`` bytes of a member. Returns None if it can't be read."""
    try:
        info = zf.getinfo(name)
        if info.flag_bits & 0x1:
            return None
        with zf.open(info) as fh:
            return fh.read(limit)
    except (KeyError, RuntimeError, NotImplementedError, zipfile.BadZipFile, zlib.error, EOFError, OSError, ValueError):
        return None
