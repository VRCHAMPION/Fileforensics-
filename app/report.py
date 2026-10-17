"""Run every analyzer over one in-memory buffer and assemble the report."""

from __future__ import annotations

import logging
import time
import uuid
from datetime import UTC, datetime

from . import __version__
from .analyzers.deadline import Deadline
from .analyzers.entropy import analyze_entropy
from .analyzers.hashing import hash_bytes
from .analyzers.images import PILLOW_TYPES, analyze_image
from .analyzers.iocs import extract_iocs
from .analyzers.mismatch import check_mismatch
from .analyzers.office import analyze_ole, analyze_ooxml
from .analyzers.pdf import analyze_pdf
from .analyzers.pe import analyze_pe
from .analyzers.polyglot import analyze_appended
from .analyzers.risk import build_risk
from .analyzers.safezip import ZipLimits, inspect_zip
from .analyzers.signatures import TYPES, Identification, identify
from .analyzers.strings import extract_strings
from .sanitize import sanitize_filename

log = logging.getLogger("fileforensics.report")

_OOXML = {"docx", "docm", "xlsx", "xlsm", "pptx", "pptm"}
_OLE = {"ole", "doc", "xls", "ppt", "msg", "msi"}
_EMPTY_APPENDED = {
    "logical_end": None,
    "appended_bytes": 0,
    "appended_type": None,
    "appended_label": None,
    "padding_only": False,
    "prepended_bytes": 0,
    "appended_entries": [],
    "embedded": [],
}
_ZIPLIKE = {"zip", "jar", "apk", "epub", "odt", "ods", "odp"} | _OOXML


def analyze(data: bytes, filename: str | None, budget_s: float = 10.0) -> dict:
    deadline = Deadline(budget_s)
    timings: dict[str, float] = {}
    started = time.perf_counter()

    errors: list[str] = []

    def timed(name, fn, *args, fallback=None, **kwargs):
        t0 = time.perf_counter()
        try:
            return fn(*args, **kwargs)
        except Exception:  # one broken parser must not sink the whole report
            log.warning("analyzer %s failed", name, exc_info=True)
            errors.append(name)
            return fallback
        finally:
            timings[name] = round((time.perf_counter() - t0) * 1000, 2)

    safe_name = sanitize_filename(filename)
    ident = timed(
        "identify", identify, data, fallback=Identification(TYPES["unknown"], "low", ["identification failed"])
    )
    tid = ident.type.id

    report: dict = {
        "tool": {"name": "FileForensics", "version": __version__},
        "case_id": "FF-" + uuid.uuid4().hex[:10].upper(),
        "analyzed_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "file": {"name": safe_name, "size": len(data)},
        "type": ident.to_report(),
        "mismatch": check_mismatch(safe_name, ident.type),
        "hashes": timed("hashes", hash_bytes, data),
        "hex_preview": {"offset": 0, "length": min(256, len(data)), "hex": data[:256].hex()},
    }
    report["entropy"] = timed("entropy", analyze_entropy, data, tid, fallback=analyze_entropy(b""))

    strings = timed("strings", extract_strings, data, deadline=deadline, fallback=extract_strings(b""))
    blob = strings.pop("_blob")
    report["strings"] = strings
    report["iocs"] = timed("iocs", extract_iocs, blob, fallback=extract_iocs(""))

    report["image"] = timed("image", analyze_image, data) if tid in PILLOW_TYPES else None
    report["pdf"] = timed("pdf", analyze_pdf, data, deadline=deadline) if tid == "pdf" else None
    report["pe"] = timed("pe", analyze_pe, data) if tid in ("exe", "dll") else None

    report["office"] = None
    report["archive"] = None
    if tid in _ZIPLIKE:
        zi = timed("archive", inspect_zip, data, ZipLimits())
        report["archive"] = zi.to_report()
        if tid in _OOXML:
            report["office"] = timed("office", analyze_ooxml, data, zi)
    elif tid in _OLE:
        report["office"] = timed("office", analyze_ole, data)

    report["appended"] = timed("appended", analyze_appended, data, tid, deadline, fallback=_EMPTY_APPENDED)
    report["analyzer_errors"] = errors
    report["analysis_incomplete"] = deadline.hit or strings["capped"] or bool(errors)
    report["risk"] = build_risk(report)
    timings["total"] = round((time.perf_counter() - started) * 1000, 2)
    report["timings_ms"] = timings
    return report
