"""Appended-data and polyglot detection.

For formats with a well-defined end (JPEG EOI, PNG IEND, GIF trailer, PDF
%%EOF, ZIP end-of-central-directory) we walk the structure to find where the
file *should* end, then identify whatever follows. Separately we scan for
high-value embedded signatures (PE, ELF, ZIP, RAR, 7z, OLE, PDF) at non-zero
offsets.
"""

from __future__ import annotations

import struct

from .deadline import Deadline, unlimited
from .safezip import ZipLimits, inspect_zip
from .signatures import identify

_ZIP_FAMILY = {"zip", "docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "odt", "ods", "odp", "epub", "jar", "apk"}
_OLE_FAMILY = {"ole", "doc", "xls", "ppt", "msg", "msi"}
_MAX_SEGMENTS = 10000


def jpeg_end(data: bytes) -> int | None:
    """Offset just past the EOI marker that terminates the first image."""
    if data[:2] != b"\xff\xd8":
        return None
    i = 2
    n = len(data)
    segments = 0
    while i + 2 <= n and segments < _MAX_SEGMENTS:
        segments += 1
        if data[i] != 0xFF:
            return None
        marker = data[i + 1]
        if marker == 0xFF:  # fill byte
            i += 1
            continue
        if marker == 0xD9:
            return i + 2
        if marker in (0x01, *range(0xD0, 0xD8)):
            i += 2
            continue
        if i + 4 > n:
            return None
        seg_len = struct.unpack_from(">H", data, i + 2)[0]
        if seg_len < 2:
            return None
        i += 2 + seg_len
        if marker == 0xDA:  # start of scan: skip entropy-coded data
            while i + 1 < n:
                j = data.find(b"\xff", i)
                if j < 0 or j + 1 >= n:
                    return None
                nxt = data[j + 1]
                if nxt == 0x00 or 0xD0 <= nxt <= 0xD7 or nxt == 0xFF:
                    i = j + 1 if nxt == 0xFF else j + 2
                    continue
                i = j
                break
    return None


def png_end(data: bytes) -> int | None:
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    i = 8
    for _ in range(_MAX_SEGMENTS * 10):
        if i + 8 > len(data):
            return None
        length = struct.unpack_from(">I", data, i)[0]
        ctype = data[i + 4 : i + 8]
        i += 12 + length
        if ctype == b"IEND":
            return i if i <= len(data) else None
    return None


def gif_end(data: bytes) -> int | None:
    if data[:6] not in (b"GIF87a", b"GIF89a") or len(data) < 13:
        return None
    flags = data[10]
    i = 13
    if flags & 0x80:
        i += 3 * (2 ** ((flags & 7) + 1))

    def skip_sub_blocks(pos: int) -> int | None:
        for _ in range(1_000_000):
            if pos >= len(data):
                return None
            size = data[pos]
            pos += 1
            if size == 0:
                return pos
            pos += size
        return None

    for _ in range(_MAX_SEGMENTS * 10):
        if i >= len(data):
            return None
        b = data[i]
        if b == 0x3B:
            return i + 1
        if b == 0x21:
            nxt = skip_sub_blocks(i + 2)
        elif b == 0x2C:
            if i + 10 > len(data):
                return None
            lflags = data[i + 9]
            i += 10
            if lflags & 0x80:
                i += 3 * (2 ** ((lflags & 7) + 1))
            nxt = skip_sub_blocks(i + 1)  # skip LZW minimum code size
        else:
            return None
        if nxt is None:
            return None
        i = nxt
    return None


def pdf_end(data: bytes) -> int | None:
    pos = data.rfind(b"%%EOF")
    if pos < 0:
        return None
    end = pos + 5
    while end < len(data) and data[end] in b"\r\n \t\x00":
        end += 1
    return end


def zip_end(data: bytes) -> int | None:
    pos = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if pos < 0 or pos + 22 > len(data):
        return None
    comment_len = struct.unpack_from("<H", data, pos + 20)[0]
    return pos + 22 + comment_len


_END_FINDERS = {"jpeg": jpeg_end, "png": png_end, "gif": gif_end, "pdf": pdf_end}

_EMBED_MARKERS = (
    (b"This program cannot be run in DOS mode", "PE executable (DOS stub)", "exe"),
    (b"\x7fELF\x02\x01\x01", "ELF 64-bit binary", "elf"),
    (b"\x7fELF\x01\x01\x01", "ELF 32-bit binary", "elf"),
    (b"PK\x03\x04", "ZIP local file header", "zip"),
    (b"Rar!\x1a\x07", "RAR archive", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "7z"),
    (bytes.fromhex("D0CF11E0A1B11AE1"), "OLE2 compound file", "ole"),
    (b"%PDF-", "PDF document", "pdf"),
)


def _skip_marker(kind: str, type_id: str) -> bool:
    if kind == "zip" and type_id in _ZIP_FAMILY:
        return True
    if kind == "ole" and type_id in _OLE_FAMILY:
        return True
    return kind == "pdf" and type_id == "pdf"


def scan_embedded(data: bytes, type_id: str, deadline: Deadline | None = None, limit: int = 30) -> list[dict]:
    deadline = deadline or unlimited()
    hits: list[dict] = []
    for marker, label, kind in _EMBED_MARKERS:
        if _skip_marker(kind, type_id) or deadline.expired():
            continue
        start = 1
        per_marker = 0
        while per_marker < 5 and len(hits) < limit:
            pos = data.find(marker, start)
            if pos < 0:
                break
            offset = pos - 0x4E if kind == "exe" else pos  # DOS stub text sits 0x4E into the file
            if kind == "exe" and (offset <= 0 or data[offset : offset + 2] != b"MZ"):
                offset = pos
            if offset > 0:
                hits.append({"offset": offset, "label": label, "kind": kind})
                per_marker += 1
            start = pos + 1
    return sorted(hits, key=lambda h: h["offset"])


def analyze_appended(data: bytes, type_id: str, deadline: Deadline | None = None) -> dict:
    out: dict = {"logical_end": None, "appended_bytes": 0, "appended_type": None, "appended_label": None,
                 "padding_only": False, "prepended_bytes": 0, "appended_entries": [], "embedded": []}  # fmt: skip
    end = None
    if type_id in _END_FINDERS:
        end = _END_FINDERS[type_id](data)
    elif type_id in _ZIP_FAMILY:
        end = zip_end(data)
    if end is not None and end < len(data):
        tail = data[end:]
        out["logical_end"] = end
        out["appended_bytes"] = len(tail)
        if not tail.strip(b"\x00\r\n\t "):
            out["padding_only"] = True
        else:
            ident = identify(tail)
            if ident.type.id not in ("unknown", "text"):
                out["appended_type"] = ident.type.id
                out["appended_label"] = ident.type.label
                if ident.type.id in _ZIP_FAMILY:
                    zi = inspect_zip(tail, ZipLimits(max_entries=500))
                    out["appended_entries"] = [n[:200] for n in zi.names[:20]]
            elif ident.type.id == "text":
                out["appended_type"] = "text"
                out["appended_label"] = "text"
    elif end is not None:
        out["logical_end"] = end

    if type_id in _ZIP_FAMILY:
        local = data.find(b"PK\x03\x04")
        out["prepended_bytes"] = local if local > 0 else 0
    out["embedded"] = scan_embedded(data, type_id, deadline)
    return out
