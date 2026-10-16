"""Office document checks: OOXML macros, external relationships, DDE, legacy OLE.

Relationship XML is matched with regular expressions rather than an XML parser,
which sidesteps entity-expansion and XXE problems entirely (we only need a few
attributes). All member reads go through safezip's byte cap.
"""

from __future__ import annotations

import re

from .cfb import parse_cfb
from .iocs import defang_url
from .safezip import ZipInspection, ZipLimits, inspect_zip, read_member

_REL = re.compile(rb"<(?:\w+:)?Relationship\b([^>]{0,4096})>", re.IGNORECASE)
_ATTR = re.compile(rb'([A-Za-z]+)\s*=\s*"([^"]{0,2048})"')
_DDE = re.compile(rb"DDEAUTO|\bDDE\b\s|<w:fldSimple[^>]{0,200}DDE", re.IGNORECASE)
_MAX_RELS_FILES = 200
_REL_READ = 256 * 1024
_DOC_READ = 2 * 1024 * 1024

_REL_KINDS = {
    "attachedtemplate": ("template_injection", "high"),
    "oleobject": ("external_ole_object", "high"),
    "frame": ("external_frame", "high"),
    "subdocument": ("external_subdocument", "medium"),
    "externallinkpath": ("external_link", "medium"),
    "image": ("remote_image", "medium"),
    "hyperlink": ("hyperlink", "info"),
}


def _defang_target(target: str) -> str:
    if "://" in target:
        return defang_url(target)
    return target


def _classify(rel_type: str, target: str) -> tuple[str, str]:
    suffix = rel_type.rsplit("/", 1)[-1].lower()
    kind, sev = _REL_KINDS.get(suffix, ("external_" + (suffix or "unknown"), "medium"))
    # UNC / file:// targets make Office reach out over SMB and can leak NTLM hashes.
    t = target.lower()
    if t.startswith(("\\\\", "file:")) and sev in ("info", "medium"):
        sev = "high"
    return kind, sev


def analyze_ooxml(data: bytes, zi: ZipInspection | None = None) -> dict:
    zi = zi or inspect_zip(data, ZipLimits())
    out: dict = {"container": "ooxml", "parsed": zi.ok}
    if not zi.ok or zi.zf is None:
        out["error"] = zi.error
        return out
    names = zi.names
    lower = [n.lower() for n in names]
    out["macros"] = [n for n, lo in zip(names, lower, strict=False) if lo.endswith("vbaproject.bin")]
    out["activex"] = [n for n, lo in zip(names, lower, strict=False) if "/activex/" in lo][:50]
    out["embedded_objects"] = [n for n, lo in zip(names, lower, strict=False) if "/embeddings/" in lo][:50]
    ct = read_member(zi.zf, "[Content_Types].xml", _REL_READ) or b""
    out["macro_enabled_content_type"] = b"macroEnabled" in ct

    external: list[dict] = []
    rels_files = [n for n in names if n.lower().endswith(".rels")][:_MAX_RELS_FILES]
    for rel_name in rels_files:
        blob = read_member(zi.zf, rel_name, _REL_READ)
        if not blob:
            continue
        for m in _REL.finditer(blob):
            attrs = {k.decode().lower(): v.decode("utf-8", "replace") for k, v in _ATTR.findall(m.group(1))}
            if attrs.get("targetmode", "").lower() != "external":
                continue
            target = attrs.get("target", "")
            kind, sev = _classify(attrs.get("type", ""), target)
            if len(external) < 100:
                external.append(
                    {"part": rel_name[:200], "kind": kind, "severity": sev, "target": _defang_target(target)[:500]}
                )
    out["external_relationships"] = external
    out["template_injection"] = any(e["kind"] == "template_injection" for e in external)

    dde = False
    for part in ("word/document.xml", "xl/externalLinks/externalLink1.xml"):
        blob = read_member(zi.zf, part, _DOC_READ)
        if blob and _DDE.search(blob):
            dde = True
    out["dde"] = dde
    return out


_OLE_MACRO_STREAMS = ("_VBA_PROJECT", "VBA", "Macros", "_VBA_PROJECT_CUR", "PROJECT")


def analyze_ole(data: bytes) -> dict:
    info = parse_cfb(data)
    out: dict = {"container": "ole", "parsed": info is not None}
    if info is None:
        out["error"] = "invalid compound file header"
        return out
    names = info.names
    out["sector_size"] = info.sector_size
    out["entry_count"] = len(info.entries)
    out["truncated"] = info.truncated
    out["streams"] = [{"name": e.name[:64], "kind": e.kind, "size": e.size} for e in info.entries[:100]]
    out["macros"] = sorted(n for n in names if n in _OLE_MACRO_STREAMS)
    out["has_macros"] = bool(out["macros"])
    out["embedded_ole_native"] = "\x01Ole10Native" in names
    out["object_pool"] = "ObjectPool" in names
    out["encrypted_package"] = "EncryptedPackage" in names
    out["summary_information"] = "\x05SummaryInformation" in names
    return out
