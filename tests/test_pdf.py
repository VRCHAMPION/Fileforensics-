import zlib

from app.analyzers.pdf import PdfLimits, analyze_pdf, parse_pdf_date
from tests.corpus import make_pdf


def test_javascript_and_open_action_counted():
    r = analyze_pdf(make_pdf(javascript=True, open_action=True))
    assert r["keywords"]["JavaScript"] == 1
    assert r["keywords"]["JS"] == 1
    assert r["keywords"]["OpenAction"] == 1


def test_hex_obfuscated_names_are_decoded():
    r = analyze_pdf(make_pdf(javascript=True, obfuscate=True))
    assert r["keywords"]["JavaScript"] == 1
    assert r["obfuscated_names"] == {"JavaScript": 1}


def test_keywords_inside_flate_streams():
    r = analyze_pdf(make_pdf(flate_js=True))
    assert r["streams"]["flate_streams"] == 1
    assert r["keywords"]["JavaScript"] >= 1
    assert r["keywords"]["ObjStm"] == 1


def test_launch_and_embedded_file():
    r = analyze_pdf(make_pdf(launch=True, embedded=True))
    assert r["keywords"]["Launch"] == 1
    assert r["keywords"]["EmbeddedFiles"] == 1 and r["keywords"]["EmbeddedFile"] == 1


def test_incremental_updates_and_info():
    r = analyze_pdf(make_pdf(incremental=2))
    assert r["incremental_updates"] == 2
    assert r["info"]["Producer"] == "edit 1"  # newest revision wins
    assert r["info"]["Title"] == "Invoice 2291"
    assert r["dates"]["CreationDate"] == "2025-03-14T09:15:27+05:30"
    assert r["version"] == "1.7"


def test_uri_is_defanged():
    r = analyze_pdf(make_pdf(uri="http://phish.example.net/login"))
    assert r["uris"] == ["hxxp[://]phish[.]example[.]net/login"]


def test_trailing_bytes_after_eof():
    r = analyze_pdf(make_pdf(appended=b"PK\x03\x04hidden"))
    assert r["trailing_bytes_after_eof"] == 10


def test_inflate_output_is_capped():
    bomb = zlib.compress(b"\x00" * (8 * 1024 * 1024))
    pdf = b"%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode >>\nstream\n" + bomb + b"\nendstream\nendobj\n%%EOF"
    r = analyze_pdf(pdf, PdfLimits(max_stream_out=64 * 1024))
    assert r["streams"]["inflated_bytes"] == 64 * 1024


def test_literal_string_escapes_and_utf16():
    pdf = b"%PDF-1.4\n/Title (a \\(nested\\) \\101) /Author <FEFF00480069>\n%%EOF"
    r = analyze_pdf(pdf)
    assert r["info"]["Title"] == "a (nested) A"
    assert r["info"]["Author"] == "Hi"


def test_date_parsing_variants():
    assert parse_pdf_date("D:2024") == "2024-01-01T00:00:00"
    assert parse_pdf_date("D:20240102030405Z") == "2024-01-02T03:04:05Z"
    assert parse_pdf_date("garbage") is None
