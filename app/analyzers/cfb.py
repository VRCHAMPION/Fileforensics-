"""Minimal, read-only parser for OLE2 / Compound File Binary (CFB) containers.

Only the directory is parsed (stream names, types, sizes). Stream contents are
never extracted. Every loop is bounded so a malformed or hostile file cannot
make the parser spin forever.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")

_FREE = 0xFFFFFFFF
_END_OF_CHAIN = 0xFFFFFFFE
_MAX_REGULAR = 0xFFFFFFFA
_MAX_DIR_ENTRIES = 4096
_MAX_DIFAT_SECTORS = 256

# Root CLSID of Windows Installer packages: {000C1084-0000-0000-C000-000000000046}
MSI_CLSID = bytes.fromhex("84100C0000000000C000000000000046")


@dataclass
class CFBEntry:
    name: str
    kind: str  # storage | stream | root
    size: int


@dataclass
class CFBInfo:
    sector_size: int
    entries: list[CFBEntry] = field(default_factory=list)
    root_clsid: bytes = b""
    truncated: bool = False

    @property
    def names(self) -> set[str]:
        return {e.name for e in self.entries}


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def parse_cfb(data: bytes) -> CFBInfo | None:
    """Parse the CFB directory. Returns None if the header is not valid CFB."""
    if len(data) < 512 or data[:8] != OLE_MAGIC:
        return None
    sector_shift = struct.unpack_from("<H", data, 0x1E)[0]
    if sector_shift not in (9, 12):
        return None
    ss = 1 << sector_shift
    total_sectors = max(0, (len(data) - ss) // ss + 1)

    def sector(sid: int) -> bytes | None:
        start = (sid + 1) * ss
        if sid >= _MAX_REGULAR or start >= len(data):
            return None
        return data[start : start + ss]

    # Collect FAT sector ids from the header DIFAT and any DIFAT chain.
    fat_sids: list[int] = []
    for i in range(109):
        sid = _u32(data, 0x4C + i * 4)
        if sid < _MAX_REGULAR:
            fat_sids.append(sid)
    difat_sid = _u32(data, 0x44)
    seen: set[int] = set()
    truncated = False
    while difat_sid < _MAX_REGULAR and len(seen) < _MAX_DIFAT_SECTORS:
        if difat_sid in seen:
            truncated = True
            break
        seen.add(difat_sid)
        blob = sector(difat_sid)
        if blob is None or len(blob) < ss:
            truncated = True
            break
        ids = struct.unpack_from(f"<{ss // 4}I", blob)
        fat_sids.extend(s for s in ids[:-1] if s < _MAX_REGULAR)
        difat_sid = ids[-1]

    fat: list[int] = []
    for sid in fat_sids[: total_sectors + 1]:
        blob = sector(sid)
        if blob is None or len(blob) < ss:
            truncated = True
            continue
        fat.extend(struct.unpack_from(f"<{ss // 4}I", blob))
        if len(fat) > total_sectors * 2 + 1024:
            break

    info = CFBInfo(sector_size=ss, truncated=truncated)
    dir_sid = _u32(data, 0x30)
    visited: set[int] = set()
    while dir_sid < _MAX_REGULAR and len(info.entries) < _MAX_DIR_ENTRIES:
        if dir_sid in visited:
            info.truncated = True
            break
        visited.add(dir_sid)
        blob = sector(dir_sid)
        if blob is None:
            info.truncated = True
            break
        for off in range(0, len(blob) - 127, 128):
            entry = blob[off : off + 128]
            obj_type = entry[66]
            if obj_type not in (1, 2, 5):
                continue
            name_len = struct.unpack_from("<H", entry, 64)[0]
            name_len = min(max(name_len - 2, 0), 62)
            name = entry[:name_len].decode("utf-16-le", errors="replace")
            size = struct.unpack_from("<Q", entry, 120)[0]
            if ss == 512:
                size &= 0xFFFFFFFF
            kind = {1: "storage", 2: "stream", 5: "root"}[obj_type]
            if obj_type == 5:
                info.root_clsid = bytes(entry[80:96])
            info.entries.append(CFBEntry(name=name, kind=kind, size=size))
        dir_sid = fat[dir_sid] if dir_sid < len(fat) else _END_OF_CHAIN
    return info
