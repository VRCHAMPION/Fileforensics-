"""Filename sanitising and an HTML-safe JSON response."""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

from fastapi.responses import JSONResponse

_UNSAFE = re.compile(r"[^\w.\- ()\[\]+@,]", re.UNICODE)
MAX_NAME = 200


def sanitize_filename(name: str | None) -> str:
    """Reduce a client-supplied filename to something safe to display and log.

    The result is never used as a filesystem path - uploads are not written to
    disk - but it still ends up in JSON, HTML and Content-Disposition headers.
    """
    if not name:
        return "unnamed"
    name = unicodedata.normalize("NFKC", str(name))
    name = name.replace("\\", "/").rsplit("/", 1)[-1]  # drop any client path
    name = "".join(ch for ch in name if unicodedata.category(ch)[0] != "C")  # control/format chars, RTLO
    name = _UNSAFE.sub("_", name).strip(" .")
    if not name or set(name) <= {"_", "."}:
        return "unnamed"
    if len(name) > MAX_NAME:
        stem, dot, ext = name.rpartition(".")
        name = (stem[: MAX_NAME - len(ext) - 1] + dot + ext) if dot and len(ext) <= 10 else name[:MAX_NAME]
    return name


def ascii_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:100] or "report"


class SafeJSONResponse(JSONResponse):
    """JSON with <, >, & and the JS line separators escaped.

    Browsers won't sniff application/json as HTML when nosniff is set, but if a
    report is ever pasted into a page or opened by a lenient viewer, escaped
    angle brackets can't open a tag.
    """

    def render(self, content: Any) -> bytes:
        text = json.dumps(content, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        text = (
            text.replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026")
            .replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029")
        )
        return text.encode("utf-8")
