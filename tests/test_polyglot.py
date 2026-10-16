import pytest

from app.analyzers.polyglot import analyze_appended, gif_end, jpeg_end, png_end, scan_embedded
from app.analyzers.signatures import identify
from tests.corpus import make_image, make_pdf, make_pe, polyglot_corpus

CASES = polyglot_corpus()


@pytest.mark.parametrize("sample", CASES, ids=[s.name for s in CASES])
def test_polyglot_corpus(sample):
    tid = identify(sample.data).type.id
    assert tid == sample.expected_type
    r = analyze_appended(sample.data, tid)
    is_poly = r["appended_type"] not in (None, "text")
    assert is_poly is sample.tags["polyglot"]
    if is_poly:
        assert r["appended_type"] == sample.tags["appended"]


def test_structure_walkers_find_exact_end():
    for fmt, fn in (("JPEG", jpeg_end), ("PNG", png_end), ("GIF", gif_end)):
        img = make_image(fmt)
        assert fn(img) == len(img), fmt


def test_appended_zip_entries_listed():
    data = CASES[0].data
    r = analyze_appended(data, "jpeg")
    assert r["appended_entries"] == ["payload.txt"]


def test_padding_is_not_a_polyglot():
    r = analyze_appended(make_image("PNG") + b"\x00" * 100, "png")
    assert r["padding_only"] and r["appended_type"] is None


def test_embedded_pe_inside_pdf():
    hits = scan_embedded(make_pdf() + make_pe(), "pdf")
    assert any(h["kind"] == "exe" for h in hits)


def test_zip_markers_ignored_inside_zip_family():
    assert scan_embedded(b"PK\x03\x04" * 3, "docx") == []


def test_truncated_structures_return_none():
    assert jpeg_end(b"\xff\xd8\xff\xe0\x00\x10JFIF") is None
    assert png_end(b"\x89PNG\r\n\x1a\n\x00\x00") is None
    assert gif_end(b"GIF89a") is None
