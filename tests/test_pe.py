from app.analyzers.pe import analyze_pe
from tests.corpus import make_pe


def test_basic_pe_fields():
    r = analyze_pe(make_pe())
    assert r["machine"] == "x86" and r["format"] == "PE32" and r["is_dll"] is False
    assert [s["name"] for s in r["sections"]] == [".text", ".data"]
    assert r["compile_time"].startswith("2023-11-14")
    assert r["overlay_size"] == 0


def test_dll_and_overlay():
    r = analyze_pe(make_pe(dll=True, overlay=b"X" * 300))
    assert r["is_dll"] is True
    assert r["overlay_size"] == 300


def test_packer_section_names_and_wx():
    r = analyze_pe(make_pe(sections=("UPX0", "UPX1"), high_entropy=True))
    assert r["packer_hints"] == ["UPX"]
    assert r["wx_sections"] == ["UPX0", "UPX1"]
    assert all(s["entropy"] > 7.5 for s in r["sections"])


def test_not_a_pe():
    assert analyze_pe(b"MZ" + b"\x00" * 100) is None
    assert analyze_pe(b"hello") is None
