"""Static PDF risk scan by raw keyword parsing (in the spirit of pdfid).

Nothing is rendered or executed. We tokenise PDF names (decoding #xx escapes so
/J#61vaScript still counts as /JavaScript), inflate FlateDecode streams under a
strict output budget so keywords hidden in object streams are found, and read
the Info dictionary.
"""

from __future__ import annotations

import re
import zlib
from collections import Counter
from dataclasses import dataclass

from .deadline import Deadline, unlimited
from .iocs import defang_url

KEYWORDS = (
    "JavaScript", "JS", "OpenAction", "AA", "Launch", "EmbeddedFile", "EmbeddedFiles", "URI",
    "AcroForm", "XFA", "RichMedia", "ObjStm", "Encrypt", "SubmitForm", "GoToR", "GoToE", "ImportData",
)  # fmt: skip
_KW = set(KEYWORDS)

_NAME = re.compile(rb"/([A-Za-z0-9#_.+-]{1,64})")
_HEX = re.compile(rb"#([0-9A-Fa-f]{2})")
_OBJ = re.compile(rb"\d{1,10}\s+\d{1,5}\s+obj\b")
_STREAM = re.compile(rb"(?<!end)stream\r?\n")
_INFO_KEYS = ("Title", "Author", "Subject", "Keywords", "Creator", "Producer", "CreationDate", "ModDate")
_INFO_RE = re.compile(rb"/(" + b"|".join(k.encode() for k in _INFO_KEYS) + rb")\s*([(<])")
_URI_RE = re.compile(rb"/URI\s*\(")
_DATE = re.compile(r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([Zz+\-])?(\d{2})?'?(\d{2})?")


@dataclass(frozen=True)
class PdfLimits:
    max_streams: int = 500
    max_stream_out: int = 1024 * 1024
    max_total_out: int = 16 * 1024 * 1024


def _decode_name(raw: bytes) -> tuple[str, bool]:
    if b"#" not in raw:
        return raw.decode("latin-1"), False
    decoded = _HEX.sub(lambda m: bytes([int(m.group(1), 16)]), raw)
    return decoded.decode("latin-1"), True


def _read_literal(buf: bytes, start: int, limit: int = 4096) -> bytes:
    """Read a PDF literal string starting just after '('. Handles nesting and escapes."""
    out = bytearray()
    depth = 1
    i = start
    end = min(len(buf), start + limit)
    escapes = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12}
    while i < end:
        c = buf[i]
        if c == 0x5C and i + 1 < end:  # backslash
            n = buf[i + 1]
            if n in escapes:
                out.append(escapes[n])
                i += 2
            elif 0x30 <= n <= 0x37:
                j = i + 1
                digits = bytearray()
                while j < end and len(digits) < 3 and 0x30 <= buf[j] <= 0x37:
                    digits.append(buf[j])
                    j += 1
                out.append(int(digits, 8) & 0xFF)
                i = j
            else:
                out.append(n)
                i += 2
            continue
        if c == 0x28:
            depth += 1
        elif c == 0x29:
            depth -= 1
            if depth == 0:
                break
        out.append(c)
        i += 1
    return bytes(out)


def _read_hex(buf: bytes, start: int, limit: int = 8192) -> bytes:
    end = buf.find(b">", start, start + limit)
    if end < 0:
        return b""
    digits = re.sub(rb"[^0-9A-Fa-f]", b"", buf[start:end])
    if len(digits) % 2:
        digits += b"0"
    return bytes.fromhex(digits.decode())


def _pdf_text(raw: bytes) -> str:
    if raw.startswith(b"\xfe\xff"):
        text = raw[2:].decode("utf-16-be", "replace")
    elif raw.startswith(b"\xff\xfe"):
        text = raw[2:].decode("utf-16-le", "replace")
    else:
        text = raw.decode("latin-1")
    return "".join(ch for ch in text if ch.isprintable())[:300]


def parse_pdf_date(value: str) -> str | None:
    m = _DATE.match(value.strip())
    if not m:
        return None
    y, mo, d, h, mi, s, tz, tzh, tzm = m.groups()
    iso = f"{y}-{mo or '01'}-{d or '01'}T{h or '00'}:{mi or '00'}:{s or '00'}"
    if tz in ("Z", "z"):
        iso += "Z"
    elif tz in ("+", "-") and tzh:
        iso += f"{tz}{tzh}:{tzm or '00'}"
    return iso


def _inflate_streams(data: bytes, limits: PdfLimits, deadline: Deadline) -> tuple[list[bytes], dict]:
    chunks: list[bytes] = []
    stats = {"streams": 0, "flate_streams": 0, "inflated_bytes": 0, "inflate_errors": 0, "capped": False}
    total = 0
    for m in _STREAM.finditer(data):
        stats["streams"] += 1
        if stats["streams"] > limits.max_streams or total >= limits.max_total_out or deadline.expired():
            stats["capped"] = True
            break
        dict_start = data.rfind(b"<<", max(0, m.start() - 1024), m.start())
        header = data[dict_start : m.start()] if dict_start >= 0 else b""
        if b"/FlateDecode" not in header and b"/Fl " not in header and b"/Fl]" not in header:
            continue
        stats["flate_streams"] += 1
        end = data.find(b"endstream", m.end())
        if end < 0:
            end = len(data)
        budget = min(limits.max_stream_out, limits.max_total_out - total)
        try:
            out = zlib.decompressobj().decompress(data[m.end() : end], budget)
        except zlib.error:
            stats["inflate_errors"] += 1
            continue
        total += len(out)
        chunks.append(out)
    stats["inflated_bytes"] = total
    return chunks, stats


def analyze_pdf(data: bytes, limits: PdfLimits | None = None, deadline: Deadline | None = None) -> dict:
    limits = limits or PdfLimits()
    deadline = deadline or unlimited()
    header_at = data.find(b"%PDF-", 0, 1024)
    version = None
    if header_at >= 0:
        version = data[header_at + 5 : header_at + 8].decode("latin-1", "replace")

    inflated, stream_stats = _inflate_streams(data, limits, deadline)
    sources = [data, *inflated]

    counts: Counter = Counter()
    obfuscated: Counter = Counter()
    for src in sources:
        for m in _NAME.finditer(src):
            name, escaped = _decode_name(m.group(1))
            if name in _KW:
                counts[name] += 1
                if escaped:
                    obfuscated[name] += 1

    info: dict[str, str] = {}
    for src in sources:
        for m in _INFO_RE.finditer(src):
            key = m.group(1).decode()
            raw = _read_literal(src, m.end()) if m.group(2) == b"(" else _read_hex(src, m.end())
            text = _pdf_text(raw)
            if text:
                info[key] = text  # later definitions (incremental updates) win
    dates = {k: parse_pdf_date(info[k]) for k in ("CreationDate", "ModDate") if k in info}

    uris: list[str] = []
    for src in sources:
        for m in _URI_RE.finditer(src):
            uri = _pdf_text(_read_literal(src, m.end(), 2048))
            if uri and len(uris) < 50:
                uris.append(defang_url(uri))

    eof_count = data.count(b"%%EOF")
    last_eof = data.rfind(b"%%EOF")
    trailing = 0
    if last_eof >= 0:
        trailing = len(data[last_eof + 5 :].strip(b"\r\n\t \x00"))

    linearized = b"/Linearized" in data[:2048]
    updates = max(0, eof_count - 1 - (1 if linearized else 0))
    return {
        "version": version,
        "header_offset": header_at,
        "objects": len(_OBJ.findall(data)),
        "endobj": data.count(b"endobj"),
        "streams": stream_stats,
        "keywords": {k: counts.get(k, 0) for k in KEYWORDS},
        "obfuscated_names": dict(obfuscated),
        "eof_markers": eof_count,
        "incremental_updates": updates,
        "linearized": linearized,
        "trailing_bytes_after_eof": trailing,
        "info": info,
        "dates": dates,
        "uris": uris,
        "encrypted": counts.get("Encrypt", 0) > 0,
    }
