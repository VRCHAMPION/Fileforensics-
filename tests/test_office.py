from app.analyzers.office import analyze_ole, analyze_ooxml
from tests.corpus import make_cfb, make_ooxml, make_zip


def test_vba_project_detected():
    r = analyze_ooxml(make_ooxml("docx", macros=True))
    assert r["macros"] == ["word/vbaProject.bin"]
    assert r["macro_enabled_content_type"] is True


def test_clean_docx():
    r = analyze_ooxml(make_ooxml("docx"))
    assert r["parsed"] and r["macros"] == [] and r["external_relationships"] == []
    assert r["template_injection"] is False and r["dde"] is False


def test_remote_template_injection():
    r = analyze_ooxml(make_ooxml("docx", template_url="https://203.0.113.9/payload.dotm"))
    assert r["template_injection"] is True
    rel = r["external_relationships"][0]
    assert rel["kind"] == "template_injection" and rel["severity"] == "high"
    assert rel["target"] == "hxxps[://]203[.]0[.]113[.]9/payload.dotm"


def test_unc_hyperlink_escalates_severity():
    r = analyze_ooxml(make_ooxml("docx", hyperlink="\\\\attacker.example\\share\\x"))
    assert r["external_relationships"][0]["severity"] == "high"


def test_web_hyperlink_is_info():
    r = analyze_ooxml(make_ooxml("docx", hyperlink="https://example.org"))
    assert r["external_relationships"][0]["severity"] == "info"


def test_dde_field():
    assert analyze_ooxml(make_ooxml("docx", dde=True))["dde"] is True


def test_activex_and_embeddings_listed():
    data = make_zip(
        {
            "[Content_Types].xml": b"<Types/>",
            "word/document.xml": b"<w/>",
            "word/activeX/activeX1.xml": b"<ax/>",
            "word/embeddings/oleObject1.bin": b"\x00",
        }
    )
    r = analyze_ooxml(data)
    assert r["activex"] == ["word/activeX/activeX1.xml"]
    assert r["embedded_objects"] == ["word/embeddings/oleObject1.bin"]


def test_ooxml_on_non_zip():
    r = analyze_ooxml(b"not a zip")
    assert r["parsed"] is False


def test_legacy_ole_macros():
    r = analyze_ole(make_cfb([("WordDocument", 2), ("Macros", 1), ("VBA", 1), ("_VBA_PROJECT", 2)]))
    assert r["has_macros"] is True
    assert "Macros" in r["macros"] and "_VBA_PROJECT" in r["macros"]


def test_legacy_ole_package_and_encryption():
    r = analyze_ole(make_cfb([("\x01Ole10Native", 2), ("EncryptedPackage", 2)]))
    assert r["embedded_ole_native"] and r["encrypted_package"] and not r["has_macros"]


def test_ole_bad_header():
    assert analyze_ole(b"\x00" * 600)["parsed"] is False
