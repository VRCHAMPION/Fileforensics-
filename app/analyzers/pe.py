"""Light PE header parse: machine, timestamp, sections, overlay.

Just enough structure for triage: per-section entropy (packers leave
high-entropy sections with tell-tale names) and the overlay - bytes past the
last section, where droppers often stash a second payload.
"""

from __future__ import annotations

import struct
from collections import Counter
from datetime import UTC, datetime

from .entropy import shannon

_MACHINES = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64", 0x200: "IA64"}
_PACKER_SECTIONS = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX", ".aspack": "ASPack", ".adata": "ASPack",
    ".petite": "Petite", ".nsp0": "NsPack", ".nsp1": "NsPack", "MPRESS1": "MPRESS", "MPRESS2": "MPRESS",
    ".themida": "Themida", ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".enigma1": "Enigma",
}  # fmt: skip
_MAX_SECTIONS = 96


def analyze_pe(data: bytes) -> dict | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None
    coff = e_lfanew + 4
    machine, nsec, timestamp, _, _, opt_size, characteristics = struct.unpack_from("<HHIIIHH", data, coff)
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0] if opt + 2 <= len(data) else 0
    out: dict = {
        "machine": _MACHINES.get(machine, f"0x{machine:04X}"),
        "format": {0x10B: "PE32", 0x20B: "PE32+"}.get(magic, "unknown"),
        "is_dll": bool(characteristics & 0x2000),
        "compile_time": None,
        "timestamp_raw": timestamp,
        "sections": [],
        "packer_hints": [],
        "overlay_offset": None,
        "overlay_size": 0,
    }
    if 0 < timestamp < 4102444800:  # before 2100; reproducible builds use hashes here
        out["compile_time"] = datetime.fromtimestamp(timestamp, UTC).isoformat()
    if opt + 70 <= len(data):
        subsystem = struct.unpack_from("<H", data, opt + 68)[0]
        out["subsystem"] = {2: "GUI", 3: "console", 1: "native", 10: "EFI"}.get(subsystem, str(subsystem))

    sec_table = opt + opt_size
    raw_end = 0
    for i in range(min(nsec, _MAX_SECTIONS)):
        off = sec_table + i * 40
        if off + 40 > len(data):
            break
        name = data[off : off + 8].rstrip(b"\x00").decode("latin-1", "replace")
        vsize, _vaddr, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
        flags = struct.unpack_from("<I", data, off + 36)[0]
        chunk = data[rptr : rptr + rsize] if rptr < len(data) else b""
        ent = round(shannon(Counter(chunk), len(chunk)), 3) if chunk else 0.0
        out["sections"].append({
            "name": name, "virtual_size": vsize, "raw_size": rsize, "raw_offset": rptr,
            "entropy": ent, "executable": bool(flags & 0x20000000), "writable": bool(flags & 0x80000000),
        })  # fmt: skip
        if name in _PACKER_SECTIONS:
            out["packer_hints"].append(_PACKER_SECTIONS[name])
        if rsize and rptr:
            raw_end = max(raw_end, rptr + rsize)
    out["packer_hints"] = sorted(set(out["packer_hints"]))
    out["wx_sections"] = [s["name"] for s in out["sections"] if s["executable"] and s["writable"]]
    if raw_end and raw_end < len(data):
        out["overlay_offset"] = raw_end
        out["overlay_size"] = len(data) - raw_end
    return out
