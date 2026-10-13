import pytest

from app.analyzers.mismatch import check_mismatch, split_extension
from app.analyzers.signatures import TYPES, identify
from tests.corpus import make_pe, mismatch_corpus

CASES = mismatch_corpus()


@pytest.mark.parametrize("sample", CASES, ids=[s.name for s in CASES])
def test_mismatch_corpus(sample):
    ident = identify(sample.data)
    assert ident.type.id == sample.expected_type
    result = check_mismatch(sample.name, ident.type)
    assert result["mismatch"] is sample.tags["mismatch"]
    assert result["severity"] == sample.tags["severity"]
    assert result["double_extension"] is sample.tags.get("double", False)


@pytest.mark.parametrize(
    "name,ext,exts",
    [
        ("a.PDF", "pdf", ["pdf"]),
        ("archive.tar.gz", "gz", ["tar", "gz"]),
        ("noext", "", []),
        (".bashrc", "", []),
        ("C:\\Users\\x\\evil.pdf.exe", "exe", ["pdf", "exe"]),
        ("trailing.dot.", "dot", ["dot"]),
    ],
)
def test_split_extension(name, ext, exts):
    assert split_extension(name) == (ext, exts)


def test_no_extension_on_executable_is_low():
    result = check_mismatch("payload", identify(make_pe()).type)
    assert result["severity"] == "low" and result["claimed_extension"] is None


def test_unknown_content_cannot_be_verified():
    result = check_mismatch("x.pdf", TYPES["unknown"])
    assert result["mismatch"] is False
