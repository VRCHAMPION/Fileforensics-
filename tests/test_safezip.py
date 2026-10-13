import struct
import zipfile

from app.analyzers.safezip import ZipLimits, inspect_zip, read_member
from tests.corpus import make_bomb, make_overlapping_zip, make_zip


def test_compression_ratio_bomb_flagged():
    r = inspect_zip(make_bomb(mb=24))
    assert r.ok
    assert r.max_entry_ratio > 100
    assert any("compression ratio" in b for b in r.bomb_reasons)


def test_total_size_cap():
    r = inspect_zip(make_bomb(mb=8), ZipLimits(max_total_uncompressed=1024 * 1024))
    assert any("declared uncompressed size" in b for b in r.bomb_reasons)


def test_overlapping_entries_flagged():
    r = inspect_zip(make_overlapping_zip())
    assert r.overlapping_entries == 1
    assert any("overlapping" in b for b in r.bomb_reasons)


def test_too_many_entries_rejected_before_parsing():
    eocd = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 5000, 5000, 0, 0, 0)
    r = inspect_zip(eocd, ZipLimits(max_entries=100))
    assert not r.ok and r.entry_count == 5000 and r.bomb_reasons


def test_member_read_is_capped_never_extracted():
    r = inspect_zip(make_bomb(mb=4))
    blob = read_member(r.zf, "report.txt", 1000)
    assert len(blob) == 1000


def test_encrypted_flag_and_nested_archives():
    data = bytearray(make_zip({"inner.zip": b"PK", "x.txt": b"y"}, zipfile.ZIP_STORED))
    pos = data.find(b"PK\x01\x02")
    struct.pack_into("<H", data, pos + 8, 0x1)  # mark first entry encrypted in central dir
    r = inspect_zip(bytes(data))
    assert r.encrypted_entries == 1
    assert r.nested_archives == ["inner.zip"]
    assert read_member(r.zf, "inner.zip", 10) is None


def test_garbage_is_not_a_zip():
    r = inspect_zip(b"definitely not a zip")
    assert not r.ok and r.error


def test_report_shape():
    rep = inspect_zip(make_zip({"a.txt": b"hi"})).to_report()
    assert rep["entry_count"] == 1 and rep["entries"][0]["name"] == "a.txt"
