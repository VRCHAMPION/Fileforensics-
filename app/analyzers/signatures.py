"""Pure-Python magic-byte signature database.

No libmagic, no external tools: every signature lives in this file. A signature
is one or more (offset, bytes) patterns that must all match. The most specific
match (most magic bytes matched) wins, then a per-format "refiner" can look a
little deeper - e.g. a ZIP is opened in memory to tell DOCX from JAR, a PE header
is walked to tell EXE from DLL, a shebang line names the interpreter.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

from .cfb import MSI_CLSID, parse_cfb
from .safezip import ZipLimits, inspect_zip, read_member


@dataclass(frozen=True)
class FileType:
    id: str
    label: str
    mime: str
    category: str
    extensions: tuple[str, ...]


def _t(id_: str, label: str, mime: str, category: str, exts: str) -> FileType:
    return FileType(id_, label, mime, category, tuple(e for e in exts.split() if e))


# fmt: off
_TYPE_LIST = [
    # images
    _t("jpeg", "JPEG image", "image/jpeg", "image", "jpg jpeg jpe jfif"),
    _t("png", "PNG image", "image/png", "image", "png"),
    _t("gif", "GIF image", "image/gif", "image", "gif"),
    _t("bmp", "Windows bitmap", "image/bmp", "image", "bmp dib"),
    _t("tiff", "TIFF image", "image/tiff", "image", "tif tiff dng nef cr2 arw"),
    _t("webp", "WebP image", "image/webp", "image", "webp"),
    _t("ico", "Windows icon", "image/vnd.microsoft.icon", "image", "ico cur"),
    _t("psd", "Photoshop document", "image/vnd.adobe.photoshop", "image", "psd"),
    _t("heic", "HEIF/HEIC image", "image/heic", "image", "heic heif"),
    _t("avif", "AVIF image", "image/avif", "image", "avif"),
    _t("jp2", "JPEG 2000 image", "image/jp2", "image", "jp2 j2k jpf jpx"),
    _t("svg", "SVG vector image", "image/svg+xml", "image", "svg svgz"),
    # documents
    _t("pdf", "PDF document", "application/pdf", "document", "pdf"),
    _t("rtf", "Rich Text Format", "application/rtf", "document", "rtf doc"),
    _t("postscript", "PostScript", "application/postscript", "document", "ps eps ai"),
    _t("ole", "OLE2 compound file", "application/x-ole-storage", "document", "ole cfb"),
    _t("doc", "Word 97-2003 document (OLE)", "application/msword", "document", "doc dot"),
    _t("xls", "Excel 97-2003 workbook (OLE)", "application/vnd.ms-excel", "document", "xls xlt"),
    _t("ppt", "PowerPoint 97-2003 (OLE)", "application/vnd.ms-powerpoint", "document", "ppt pps pot"),
    _t("msg", "Outlook message (OLE)", "application/vnd.ms-outlook", "document", "msg"),
    _t("msi", "Windows Installer package", "application/x-msi", "executable", "msi msp"),
    _t("docx", "Word document (OOXML)", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "document", "docx dotx"),
    _t("docm", "Word macro-enabled document", "application/vnd.ms-word.document.macroEnabled.12", "document", "docm dotm"),
    _t("xlsx", "Excel workbook (OOXML)", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "document", "xlsx xltx"),
    _t("xlsm", "Excel macro-enabled workbook", "application/vnd.ms-excel.sheet.macroEnabled.12", "document", "xlsm xltm"),
    _t("pptx", "PowerPoint presentation (OOXML)", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "document", "pptx potx ppsx"),
    _t("pptm", "PowerPoint macro-enabled", "application/vnd.ms-powerpoint.presentation.macroEnabled.12", "document", "pptm potm ppsm"),
    _t("odt", "OpenDocument text", "application/vnd.oasis.opendocument.text", "document", "odt"),
    _t("ods", "OpenDocument spreadsheet", "application/vnd.oasis.opendocument.spreadsheet", "document", "ods"),
    _t("odp", "OpenDocument presentation", "application/vnd.oasis.opendocument.presentation", "document", "odp"),
    _t("epub", "EPUB e-book", "application/epub+zip", "document", "epub"),
    # archives
    _t("zip", "ZIP archive", "application/zip", "archive", "zip"),
    _t("rar", "RAR archive", "application/vnd.rar", "archive", "rar"),
    _t("7z", "7-Zip archive", "application/x-7z-compressed", "archive", "7z"),
    _t("gzip", "gzip compressed data", "application/gzip", "archive", "gz tgz gzip"),
    _t("bzip2", "bzip2 compressed data", "application/x-bzip2", "archive", "bz2 tbz2"),
    _t("xz", "XZ compressed data", "application/x-xz", "archive", "xz txz"),
    _t("zstd", "Zstandard compressed data", "application/zstd", "archive", "zst"),
    _t("lz4", "LZ4 frame", "application/x-lz4", "archive", "lz4"),
    _t("tar", "POSIX tar archive", "application/x-tar", "archive", "tar"),
    _t("cab", "Microsoft Cabinet", "application/vnd.ms-cab-compressed", "archive", "cab"),
    _t("iso", "ISO 9660 disk image", "application/x-iso9660-image", "archive", "iso"),
    _t("ar", "Unix ar archive", "application/x-archive", "archive", "a ar lib"),
    _t("deb", "Debian package", "application/vnd.debian.binary-package", "archive", "deb"),
    _t("rpm", "RPM package", "application/x-rpm", "archive", "rpm"),
    _t("jar", "Java archive", "application/java-archive", "executable", "jar war ear"),
    _t("apk", "Android package", "application/vnd.android.package-archive", "executable", "apk"),
    # executables / code
    _t("exe", "Windows PE executable", "application/vnd.microsoft.portable-executable", "executable", "exe scr com cpl"),
    _t("dll", "Windows PE DLL", "application/vnd.microsoft.portable-executable", "executable", "dll ocx sys drv cpl"),
    _t("dos_exe", "MS-DOS executable", "application/x-dosexec", "executable", "exe com"),
    _t("elf", "ELF binary", "application/x-elf", "executable", "elf so o bin out axf"),
    _t("macho", "Mach-O binary", "application/x-mach-binary", "executable", "dylib bundle o macho"),
    _t("macho_fat", "Mach-O universal binary", "application/x-mach-binary", "executable", "dylib macho"),
    _t("java_class", "Java class file", "application/java-vm", "executable", "class"),
    _t("dex", "Android DEX bytecode", "application/x-dex", "executable", "dex"),
    _t("wasm", "WebAssembly module", "application/wasm", "executable", "wasm"),
    _t("lnk", "Windows shortcut (LNK)", "application/x-ms-shortcut", "executable", "lnk"),
    # scripts / markup
    _t("script_python", "Python script", "text/x-python", "script", "py pyw"),
    _t("script_shell", "Shell script", "text/x-shellscript", "script", "sh bash zsh ksh"),
    _t("script_perl", "Perl script", "text/x-perl", "script", "pl pm"),
    _t("script_ruby", "Ruby script", "text/x-ruby", "script", "rb"),
    _t("script_node", "Node.js script", "text/javascript", "script", "js mjs cjs"),
    _t("script_php", "PHP script", "application/x-php", "script", "php phtml php5"),
    _t("script_batch", "Windows batch script", "application/x-bat", "script", "bat cmd"),
    _t("script_other", "Script (shebang)", "text/plain", "script", ""),
    _t("html", "HTML document", "text/html", "markup", "html htm xhtml"),
    _t("xml", "XML document", "application/xml", "markup", "xml xsd xsl rss"),
    # audio
    _t("mp3", "MP3 audio", "audio/mpeg", "audio", "mp3"),
    _t("flac", "FLAC audio", "audio/flac", "audio", "flac"),
    _t("ogg", "Ogg container", "audio/ogg", "audio", "ogg oga ogv opus"),
    _t("wav", "WAVE audio", "audio/wav", "audio", "wav"),
    _t("midi", "MIDI", "audio/midi", "audio", "mid midi"),
    _t("aac", "AAC (ADTS) audio", "audio/aac", "audio", "aac"),
    _t("m4a", "MPEG-4 audio", "audio/mp4", "audio", "m4a m4b"),
    # video
    _t("mp4", "MPEG-4 video", "video/mp4", "video", "mp4 m4v"),
    _t("mov", "QuickTime video", "video/quicktime", "video", "mov qt"),
    _t("3gp", "3GPP video", "video/3gpp", "video", "3gp 3g2"),
    _t("avi", "AVI video", "video/x-msvideo", "video", "avi"),
    _t("mkv", "Matroska video", "video/x-matroska", "video", "mkv mka"),
    _t("webm", "WebM video", "video/webm", "video", "webm"),
    _t("flv", "Flash video", "video/x-flv", "video", "flv"),
    _t("mpegts", "MPEG transport stream", "video/mp2t", "video", "ts mts m2ts"),
    # data / system
    _t("sqlite", "SQLite 3 database", "application/vnd.sqlite3", "database", "sqlite sqlite3 db db3"),
    _t("ttf", "TrueType font", "font/ttf", "font", "ttf"),
    _t("otf", "OpenType font", "font/otf", "font", "otf"),
    _t("woff", "WOFF font", "font/woff", "font", "woff"),
    _t("woff2", "WOFF2 font", "font/woff2", "font", "woff2"),
    _t("pcap", "pcap capture", "application/vnd.tcpdump.pcap", "forensic", "pcap cap dmp"),
    _t("pcapng", "pcapng capture", "application/x-pcapng", "forensic", "pcapng"),
    _t("regf", "Windows registry hive", "application/x-windows-registry", "forensic", "dat hiv hve"),
    _t("evtx", "Windows event log", "application/x-ms-evtx", "forensic", "evtx"),
    _t("pem", "PEM encoded data", "application/x-pem-file", "crypto", "pem crt cer key csr"),
    # fallbacks
    _t("text", "Plain text", "text/plain", "text", "txt log csv md json ini cfg conf"),
    _t("unknown", "Unknown binary data", "application/octet-stream", "unknown", "bin dat"),
]
# fmt: on

TYPES: dict[str, FileType] = {t.id: t for t in _TYPE_LIST}
# Types that can actually be identified (fallbacks excluded).
SUPPORTED_TYPE_COUNT = len([t for t in _TYPE_LIST if t.id not in {"text", "unknown"}])


@dataclass(frozen=True)
class Signature:
    type_id: str
    patterns: tuple[tuple[int, bytes], ...]
    window: int = 0  # >0: first pattern may start anywhere in data[:window]

    @property
    def weight(self) -> int:
        return sum(len(p) for _, p in self.patterns)


def _s(type_id: str, *patterns: tuple[int, bytes], window: int = 0) -> Signature:
    return Signature(type_id, tuple(patterns), window)


def _h(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr)


SIGNATURES: list[Signature] = [
    _s("jpeg", (0, _h("FFD8FF"))),
    _s("png", (0, _h("89504E470D0A1A0A"))),
    _s("gif", (0, b"GIF87a")),
    _s("gif", (0, b"GIF89a")),
    _s("bmp", (0, b"BM")),
    _s("tiff", (0, b"II*\x00")),
    _s("tiff", (0, b"MM\x00*")),
    _s("webp", (0, b"RIFF"), (8, b"WEBP")),
    _s("ico", (0, _h("00000100"))),
    _s("psd", (0, b"8BPS")),
    _s("mp4", (4, b"ftyp")),  # ISO-BMFF, refined by brand
    _s("jp2", (0, _h("0000000C6A5020200D0A870A"))),
    _s("pdf", (0, b"%PDF-"), window=1024),
    _s("rtf", (0, b"{\\rtf")),
    _s("postscript", (0, b"%!PS")),
    _s("ole", (0, _h("D0CF11E0A1B11AE1"))),
    _s("zip", (0, b"PK\x03\x04")),
    _s("zip", (0, b"PK\x05\x06")),
    _s("zip", (0, b"PK\x07\x08")),
    _s("rar", (0, b"Rar!\x1a\x07\x00")),
    _s("rar", (0, b"Rar!\x1a\x07\x01\x00")),
    _s("7z", (0, _h("377ABCAF271C"))),
    _s("gzip", (0, _h("1F8B08"))),
    _s("bzip2", (0, b"BZh"), (4, b"1AY&SY")),
    _s("bzip2", (0, b"BZh"), (4, _h("177245385090"))),
    _s("xz", (0, _h("FD377A585A00"))),
    _s("zstd", (0, _h("28B52FFD"))),
    _s("lz4", (0, _h("04224D18"))),
    _s("tar", (257, b"ustar")),
    _s("cab", (0, b"MSCF\x00\x00\x00\x00")),
    _s("iso", (32769, b"CD001")),
    _s("iso", (34817, b"CD001")),
    _s("iso", (36865, b"CD001")),
    _s("ar", (0, b"!<arch>\n")),
    _s("rpm", (0, _h("EDABEEDB"))),
    _s("dos_exe", (0, b"MZ")),  # refined to exe/dll via the PE header
    _s("elf", (0, b"\x7fELF")),
    _s("macho", (0, _h("FEEDFACE"))),
    _s("macho", (0, _h("FEEDFACF"))),
    _s("macho", (0, _h("CEFAEDFE"))),
    _s("macho", (0, _h("CFFAEDFE"))),
    _s("java_class", (0, _h("CAFEBABE"))),  # refined: may be a Mach-O fat binary
    _s("dex", (0, b"dex\n"), (7, b"\x00")),
    _s("wasm", (0, b"\x00asm")),
    _s("lnk", (0, _h("4C0000000114020000000000C000000000000046"))),
    _s("script_other", (0, b"#!")),  # refined by interpreter
    _s("script_php", (0, b"<?php")),
    _s("mp3", (0, b"ID3")),
    _s("mp3", (0, _h("FFFB"))),
    _s("mp3", (0, _h("FFF3"))),
    _s("mp3", (0, _h("FFF2"))),
    _s("aac", (0, _h("FFF1"))),
    _s("aac", (0, _h("FFF9"))),
    _s("flac", (0, b"fLaC")),
    _s("ogg", (0, b"OggS")),
    _s("wav", (0, b"RIFF"), (8, b"WAVE")),
    _s("avi", (0, b"RIFF"), (8, b"AVI ")),
    _s("midi", (0, b"MThd")),
    _s("mkv", (0, _h("1A45DFA3"))),  # refined: WebM by DocType
    _s("flv", (0, b"FLV\x01")),
    _s("mpegts", (0, b"\x47"), (188, b"\x47"), (376, b"\x47"), (564, b"\x47")),
    _s("sqlite", (0, b"SQLite format 3\x00")),
    _s("ttf", (0, _h("0001000000"))),
    _s("otf", (0, b"OTTO")),
    _s("woff", (0, b"wOFF")),
    _s("woff2", (0, b"wOF2")),
    _s("pcap", (0, _h("D4C3B2A1"))),
    _s("pcap", (0, _h("A1B2C3D4"))),
    _s("pcap", (0, _h("4D3CB2A1"))),
    _s("pcap", (0, _h("A1B23C4D"))),
    _s("pcapng", (0, _h("0A0D0D0A"))),
    _s("regf", (0, b"regf")),
    _s("evtx", (0, b"ElfFile\x00")),
    _s("pem", (0, b"-----BEGIN ")),
]


@dataclass
class Identification:
    type: FileType
    confidence: str
    evidence: list[str] = field(default_factory=list)
    magic_offset: int = 0
    magic_length: int = 0

    def to_report(self) -> dict:
        return {
            "id": self.type.id,
            "label": self.type.label,
            "mime": self.type.mime,
            "category": self.type.category,
            "extensions": list(self.type.extensions),
            "confidence": self.confidence,
            "evidence": self.evidence,
            "magic_offset": self.magic_offset,
            "magic_length": self.magic_length,
        }


def _match(sig: Signature, data: bytes) -> int | None:
    """Return the offset of the first pattern if every pattern matches."""
    first_off, first_bytes = sig.patterns[0]
    if sig.window:
        pos = data.find(first_bytes, 0, sig.window + len(first_bytes))
        if pos < 0:
            return None
        base = pos
    else:
        if data[first_off : first_off + len(first_bytes)] != first_bytes:
            return None
        base = first_off
    for off, pat in sig.patterns[1:]:
        if data[off : off + len(pat)] != pat:
            return None
    return base


# ---------------------------------------------------------------- refiners


def _refine_mz(data: bytes, ev: list[str]) -> str:
    if len(data) < 0x40:
        return "dos_exe"
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        ev.append("MZ header without a valid PE signature")
        return "dos_exe"
    characteristics = struct.unpack_from("<H", data, e_lfanew + 22)[0]
    ev.append(f"PE\\0\\0 signature at e_lfanew=0x{e_lfanew:X}")
    if characteristics & 0x2000:
        ev.append("IMAGE_FILE_DLL flag set")
        return "dll"
    return "exe"


def _refine_cafebabe(data: bytes, ev: list[str]) -> str:
    if len(data) < 8:
        return "java_class"
    second = struct.unpack_from(">I", data, 4)[0]
    # Fat Mach-O stores an architecture count (small); Java stores minor/major version (major >= 45).
    if 0 < second < 30:
        ev.append(f"fat header with {second} architecture(s)")
        return "macho_fat"
    ev.append(f"class file version {struct.unpack_from('>H', data, 6)[0]}")
    return "java_class"


_BMFF_BRANDS = {
    b"heic": "heic", b"heix": "heic", b"hevc": "heic", b"heim": "heic", b"heis": "heic",
    b"mif1": "heic", b"msf1": "heic", b"avif": "avif", b"avis": "avif",
    b"qt  ": "mov", b"M4A ": "m4a", b"M4B ": "m4a", b"M4P ": "m4a", b"F4A ": "m4a",
    b"3gp4": "3gp", b"3gp5": "3gp", b"3gp6": "3gp", b"3g2a": "3gp", b"3ge6": "3gp",
}  # fmt: skip


def _refine_bmff(data: bytes, ev: list[str]) -> str:
    brand = data[8:12]
    ev.append(f"ftyp major brand '{brand.decode('latin-1', 'replace').strip()}'")
    if brand in _BMFF_BRANDS:
        return _BMFF_BRANDS[brand]
    if brand.startswith(b"3g"):
        return "3gp"
    return "mp4"


def _refine_ebml(data: bytes, ev: list[str]) -> str:
    if b"webm" in data[:64]:
        ev.append("EBML DocType 'webm'")
        return "webm"
    return "mkv"


_SHEBANG = re.compile(rb"^#!\s*(\S+)(?:[ \t]+(\S+))?")


def _refine_shebang(data: bytes, ev: list[str]) -> str:
    m = _SHEBANG.match(data[:256])
    if not m:
        return "script_other"
    interp = m.group(1).rsplit(b"/", 1)[-1]
    if interp == b"env" and m.group(2):
        interp = m.group(2)
    ev.append(f"shebang interpreter '{interp.decode('latin-1', 'replace')[:40]}'")
    table = {
        b"python": "script_python", b"bash": "script_shell", b"sh": "script_shell", b"zsh": "script_shell",
        b"ksh": "script_shell", b"dash": "script_shell", b"perl": "script_perl", b"ruby": "script_ruby",
        b"node": "script_node", b"nodejs": "script_node", b"php": "script_php",
    }  # fmt: skip
    for key, tid in table.items():
        if interp == key or (
            interp.startswith(key) and interp[len(key) : len(key) + 1] in (b"", b"2", b"3", b"5", b".")
        ):
            return tid
    return "script_other"


def _refine_bmp(data: bytes, ev: list[str]) -> str | None:
    if len(data) < 18:
        return None
    dib = struct.unpack_from("<I", data, 14)[0]
    if dib in (12, 40, 52, 56, 64, 108, 124):
        ev.append(f"DIB header size {dib}")
        return "bmp"
    return None


def _refine_ico(data: bytes, ev: list[str]) -> str | None:
    if len(data) < 22:
        return None
    count = struct.unpack_from("<H", data, 4)[0]
    if 0 < count <= 256 and data[9] == 0:
        ev.append(f"{count} icon image(s) in directory")
        return "ico"
    return None


def _refine_ar(data: bytes, ev: list[str]) -> str:
    if data[8:24].startswith(b"debian-binary"):
        ev.append("first member is debian-binary")
        return "deb"
    return "ar"


def _refine_ole(data: bytes, ev: list[str]) -> str:
    info = parse_cfb(data)
    if info is None:
        return "ole"
    names = info.names
    if info.root_clsid == MSI_CLSID:
        ev.append("root storage CLSID is Windows Installer")
        return "msi"
    for stream, tid in (("WordDocument", "doc"), ("Workbook", "xls"), ("Book", "xls"), ("PowerPoint Document", "ppt")):
        if stream in names:
            ev.append(f"CFB stream '{stream}' present")
            return tid
    if any(n.startswith("__substg1.0_") for n in names):
        ev.append("MAPI property streams (__substg1.0_*)")
        return "msg"
    return "ole"


def _refine_zip(data: bytes, ev: list[str]) -> str:
    zi = inspect_zip(data, ZipLimits(max_member_read=4096))
    if not zi.ok or zi.zf is None:
        return "zip"
    names = set(zi.names)
    lower = {n.lower() for n in names}
    if "mimetype" in names:
        mt = (read_member(zi.zf, "mimetype", 128) or b"").strip()
        odf = {
            b"application/vnd.oasis.opendocument.text": "odt",
            b"application/vnd.oasis.opendocument.spreadsheet": "ods",
            b"application/vnd.oasis.opendocument.presentation": "odp",
            b"application/epub+zip": "epub",
        }
        if mt in odf:
            ev.append(f"mimetype entry '{mt.decode()}'")
            return odf[mt]
    if "[Content_Types].xml" in names:
        macro = any(n.endswith("vbaproject.bin") for n in lower)
        ct = read_member(zi.zf, "[Content_Types].xml", 256 * 1024) or b""
        macro = macro or b"macroEnabled" in ct
        for prefix, base in (("word/", "docx"), ("xl/", "xlsx"), ("ppt/", "pptx")):
            if any(n.startswith(prefix) for n in names):
                ev.append(f"[Content_Types].xml with {prefix} part")
                if macro:
                    ev.append("macro-enabled content (vbaProject.bin or macroEnabled content type)")
                    return base[:-1] + "m"
                return base
    if "androidmanifest.xml" in lower and "classes.dex" in lower:
        ev.append("AndroidManifest.xml + classes.dex")
        return "apk"
    if "meta-inf/manifest.mf" in lower:
        ev.append("META-INF/MANIFEST.MF present")
        return "jar"
    return "zip"


_REFINERS = {
    "dos_exe": _refine_mz,
    "java_class": _refine_cafebabe,
    "mp4": _refine_bmff,
    "mkv": _refine_ebml,
    "script_other": _refine_shebang,
    "ole": _refine_ole,
    "zip": _refine_zip,
    "ar": _refine_ar,
}
# Refiners that may reject a weak match (returning None) so the next candidate is tried.
_VALIDATORS = {"bmp": _refine_bmp, "ico": _refine_ico}


# ---------------------------------------------------------------- text sniffing

_PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D, 0x0C}


def looks_like_text(sample: bytes) -> bool:
    if not sample:
        return False
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        return True
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError as exc:
        if exc.start >= len(sample) - 4:  # multibyte char cut off by the sample boundary
            return True
    printable = sum(1 for b in sample if b in _PRINTABLE)
    return printable / len(sample) >= 0.95


def _sniff_text(data: bytes, ev: list[str]) -> str | None:
    sample = data[:8192]
    if not looks_like_text(sample):
        return None
    head = sample.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if head.startswith(b"<?xml"):
        if b"<svg" in head[:2048]:
            ev.append("XML prolog with <svg> root")
            return "svg"
        ev.append("XML prolog")
        return "xml"
    if head.startswith(b"<svg"):
        ev.append("<svg> root element")
        return "svg"
    if head.startswith((b"<!doctype html", b"<html")) or (head.startswith(b"<") and b"<body" in head[:2048]):
        ev.append("HTML doctype/root element")
        return "html"
    if head.startswith((b"@echo off", b"@echo on")):
        ev.append("batch '@echo' directive")
        return "script_batch"
    ev.append("printable text, no binary signature")
    return "text"


# ---------------------------------------------------------------- public API


def identify(data: bytes) -> Identification:
    """Identify ``data`` by its content. The filename is never consulted."""
    candidates = []
    for sig in SIGNATURES:
        off = _match(sig, data)
        if off is not None:
            candidates.append((sig.weight, off, sig))
    candidates.sort(key=lambda c: -c[0])

    for weight, off, sig in candidates:
        ev: list[str] = []
        first = sig.patterns[0][1]
        shown = first[:16].hex(" ").upper()
        ev.append(f"magic {shown} at offset {off}")
        tid: str | None = sig.type_id
        if tid in _VALIDATORS:
            try:
                tid = _VALIDATORS[tid](data, ev)
            except Exception:
                tid = None
            if tid is None:
                continue
        if tid in _REFINERS:
            try:
                tid = _REFINERS[tid](data, ev)
            except Exception:  # a malformed container keeps its base type
                ev.append("deeper inspection failed on malformed structure")
                tid = sig.type_id
        confidence = "high" if weight >= 4 or len(ev) > 1 else "medium"
        return Identification(TYPES[tid], confidence, ev, magic_offset=off, magic_length=len(first))

    ev = []
    tid = _sniff_text(data, ev)
    if tid:
        return Identification(TYPES[tid], "low" if tid == "text" else "medium", ev)
    if not data:
        return Identification(TYPES["unknown"], "low", ["empty file"])
    return Identification(TYPES["unknown"], "low", ["no known signature matched"])


def type_for_extension(ext: str) -> list[FileType]:
    ext = ext.lower().lstrip(".")
    return [t for t in _TYPE_LIST if ext in t.extensions]
