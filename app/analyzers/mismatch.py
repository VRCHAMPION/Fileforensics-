"""Compare what the filename claims with what the bytes say."""

from __future__ import annotations

from .signatures import TYPES, FileType, type_for_extension

# Extensions a victim would double-click without a second thought.
HARMLESS_LOOKING = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "odt",
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "heic", "mp3", "mp4", "wav", "mov", "avi", "zip",
}  # fmt: skip

EXECUTABLE_EXTS = {
    "exe", "dll", "scr", "com", "pif", "cpl", "msi", "bat", "cmd", "ps1", "vbs", "vbe", "js",
    "jse", "wsf", "wsh", "hta", "lnk", "jar", "sh", "elf", "apk", "reg",
}  # fmt: skip

_DANGEROUS_CATEGORIES = {"executable", "script"}

# Container formats that are legitimately ZIPs under the hood.
_ZIP_FAMILY = {"zip", "docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "odt", "ods", "odp", "epub", "jar", "apk"}
_OLE_FAMILY = {"ole", "doc", "xls", "ppt", "msg", "msi"}
_TEXTUAL = {"text", "html", "xml", "svg", "script_python", "script_shell", "script_perl", "script_ruby",
            "script_node", "script_php", "script_batch", "script_other", "pem"}  # fmt: skip


def split_extension(filename: str) -> tuple[str, list[str]]:
    """Return (final extension, every extension) from a basename, lowercased."""
    base = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].strip().rstrip(".")
    parts = base.split(".")
    if len(parts) < 2 or (not parts[0] and len(parts) == 2):
        return "", []
    exts = [p.lower() for p in parts[1:] if p and len(p) <= 10]
    return (exts[-1] if exts else ""), exts


def check_mismatch(filename: str, detected: FileType) -> dict:
    ext, all_exts = split_extension(filename)
    result = {
        "claimed_extension": ext or None,
        "detected_type": detected.id,
        "expected_extensions": list(detected.extensions),
        "mismatch": False,
        "severity": "info",
        "reason": "",
        "double_extension": False,
    }

    # invoice.pdf.exe / photo.jpg.scr - the classic Windows "hide known extensions" trick.
    if len(all_exts) >= 2 and all_exts[-2] in HARMLESS_LOOKING and all_exts[-1] in EXECUTABLE_EXTS:
        result["double_extension"] = True

    if not ext:
        result["reason"] = "file has no extension"
        result["severity"] = "low" if detected.category in _DANGEROUS_CATEGORIES else "info"
        return result

    if detected.id == "unknown":
        result["reason"] = "content type could not be identified, so the extension cannot be verified"
        return result

    if ext in detected.extensions:
        result["reason"] = f".{ext} matches detected {detected.label}"
        if result["double_extension"]:
            result["severity"] = "high"
            result["reason"] += f"; deceptive double extension .{all_exts[-2]}.{ext}"
        return result

    claimed = type_for_extension(ext)
    claimed_ids = {t.id for t in claimed}

    # A macro-enabled document renamed to the macro-free extension is a classic lure.
    if detected.id in {"docm", "xlsm", "pptm"} and ext in {"docx", "xlsx", "pptx", "doc", "xls", "ppt"}:
        result.update(mismatch=True, severity="high", reason=f"macro-enabled {detected.label} disguised as .{ext}")
        return result

    # Benign container relationships: report.docx saved as .zip, a .txt that is really CSV, etc.
    if (
        detected.id in _ZIP_FAMILY
        and ("zip" in claimed_ids or claimed_ids & _ZIP_FAMILY)
        and detected.category != "executable"
    ):
        result.update(
            mismatch=True, severity="low", reason=f".{ext} is a ZIP-based container; content is {detected.label}"
        )
        return result
    if detected.id in _OLE_FAMILY and claimed_ids & _OLE_FAMILY and detected.id != "msi":
        result.update(mismatch=True, severity="low", reason=f".{ext} and {detected.label} are both OLE compound files")
        return result
    if detected.id == "text" and claimed_ids & _TEXTUAL:
        result["reason"] = f".{ext} is a text format and content is plain text"
        return result

    result["mismatch"] = True
    claimed_label = claimed[0].label if claimed else f"unrecognised .{ext}"
    if detected.category in _DANGEROUS_CATEGORIES and ext not in EXECUTABLE_EXTS:
        result["severity"] = "critical"
        result["reason"] = f"named .{ext} ({claimed_label}) but content is {detected.label}"
    elif not claimed:
        result["severity"] = "low"
        result["reason"] = f"unrecognised extension .{ext}; content is {detected.label}"
    elif ext in HARMLESS_LOOKING:
        result["severity"] = "medium"
        result["reason"] = f"named .{ext} ({claimed_label}) but content is {detected.label}"
    else:
        result["severity"] = "low"
        result["reason"] = f"named .{ext} ({claimed_label}) but content is {detected.label}"
    if result["double_extension"] and result["severity"] in {"info", "low", "medium"}:
        result["severity"] = "high"
    return result


__all__ = ["TYPES", "check_mismatch", "split_extension"]
