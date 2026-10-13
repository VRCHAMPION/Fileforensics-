from pathlib import Path

import pytest

from app.analyzers.signatures import SIGNATURES, SUPPORTED_TYPE_COUNT, TYPES, identify, looks_like_text
from tests.corpus import make_cfb, make_pe, make_zip, pad, type_corpus

CORPUS = type_corpus()


@pytest.mark.parametrize("sample", CORPUS, ids=[s.name for s in CORPUS])
def test_identifies_crafted_sample(sample):
    assert identify(sample.data).type.id == sample.expected_type


def test_supports_at_least_forty_types():
    assert SUPPORTED_TYPE_COUNT >= 40
    assert len({s.type_id for s in SIGNATURES}) >= 40


def test_every_signature_points_at_a_known_type():
    assert all(s.type_id in TYPES for s in SIGNATURES)


def test_corpus_covers_every_supported_type():
    covered = {s.expected_type for s in CORPUS}
    missing = set(TYPES) - covered
    assert not missing, missing


def test_pe_dll_flag_distinguishes_dll():
    assert identify(make_pe()).type.id == "exe"
    ident = identify(make_pe(dll=True))
    assert ident.type.id == "dll"
    assert any("IMAGE_FILE_DLL" in e for e in ident.evidence)


def test_mz_without_pe_header_is_dos():
    assert identify(pad(b"MZ")).type.id == "dos_exe"


def test_offset_signature_for_iso_and_tar():
    iso = identify(b"\x00" * 32769 + b"CD001" + b"\x00" * 100)
    assert iso.type.id == "iso" and iso.magic_offset == 32769


def test_pdf_header_found_inside_first_kb():
    ident = identify(b"junk" * 50 + b"%PDF-1.4\n...")
    assert ident.type.id == "pdf"
    assert ident.magic_offset == 200


def test_ooxml_needs_content_types_to_be_docx():
    plain = make_zip({"word/document.xml": b"<x/>"})
    assert identify(plain).type.id == "zip"


def test_broken_zip_falls_back_to_zip():
    assert identify(b"PK\x03\x04" + b"\x00" * 30).type.id == "zip"


def test_ole_with_unknown_streams_stays_generic():
    assert identify(make_cfb([("Foo", 2)])).type.id == "ole"


def test_truncated_ole_header_is_still_ole():
    assert identify(bytes.fromhex("D0CF11E0A1B11AE1") + b"\x00" * 20).type.id == "ole"


def test_bmp_validator_rejects_bm_text():
    assert identify(b"BM is not a bitmap, it's a sentence that starts with BM").type.id == "text"


def test_empty_and_random_data():
    assert identify(b"").type.id == "unknown"
    assert identify(bytes(range(256)) * 4).type.id == "unknown"


def test_text_detection():
    assert looks_like_text("héllo wörld".encode())
    assert looks_like_text(b"\xff\xfeh\x00i\x00")
    assert not looks_like_text(b"\x00\x01\x02binary")


def test_identification_ignores_filename():
    # identify() only receives bytes, so the extension can never influence it
    import inspect

    assert list(inspect.signature(identify).parameters) == ["data"]


def test_no_libmagic_dependency():
    import app.analyzers.signatures as sig

    src = Path(sig.__file__).read_text(encoding="utf-8")
    assert "import magic" not in src and "libmagic" not in src.split('"""', 2)[2]
