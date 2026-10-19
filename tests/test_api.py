import time

import pytest

import app.main as main_module
from tests.corpus import make_jpeg_with_gps, make_pdf, make_pe, make_zip

REPORT_KEYS = {
    "tool",
    "case_id",
    "analyzed_at",
    "file",
    "type",
    "mismatch",
    "hashes",
    "hex_preview",
    "entropy",
    "strings",
    "iocs",
    "image",
    "pdf",
    "pe",
    "office",
    "archive",
    "appended",
    "risk",
    "timings_ms",
    "analysis_incomplete",
}


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_limits_endpoint(make_client):
    r = make_client(max_upload_bytes=2 * 1024 * 1024).get("/api/limits")
    assert r.json()["max_upload_bytes"] == 2 * 1024 * 1024


def test_index_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "FileForensics" in r.text
    assert r.headers["content-type"].startswith("text/html")


def test_static_assets_served(client):
    assert client.get("/static/js/app.js").status_code == 200
    assert client.get("/static/css/style.css").status_code == 200


def test_full_report_shape(upload):
    r = upload("IMG_0042.jpg", make_jpeg_with_gps() + make_zip({"a.txt": b"b"}))
    assert r.status_code == 200
    rep = r.json()
    assert set(rep) >= REPORT_KEYS
    assert rep["type"]["id"] == "jpeg"
    assert rep["image"]["gps"]["latitude"] == pytest.approx(19.076, abs=1e-3)
    assert rep["appended"]["appended_type"] == "zip"
    assert len(rep["hex_preview"]["hex"]) == 512
    assert rep["case_id"].startswith("FF-")


def test_pdf_report(upload):
    rep = upload("doc.pdf", make_pdf(javascript=True, open_action=True)).json()
    assert rep["pdf"]["keywords"]["OpenAction"] == 1
    assert any(f["id"] == "pdf.js_autorun" for f in rep["risk"]["findings"])


def test_spoofed_executable(upload):
    rep = upload("invoice.pdf", make_pe()).json()
    assert rep["mismatch"]["severity"] == "critical"
    assert rep["risk"]["level"] in ("high", "critical")


def test_download_sets_attachment(upload):
    r = upload("a.pdf", make_pdf(), download="true")
    cd = r.headers["content-disposition"]
    assert cd.startswith('attachment; filename="fileforensics-') and cd.endswith('.json"')


def test_empty_file_rejected(upload):
    r = upload("empty.txt", b"")
    assert r.status_code == 400 and r.json()["error"]["code"] == "empty_file"


def test_missing_file_field(client):
    r = client.post("/api/analyze", files={"other": ("a.txt", b"x")})
    assert r.status_code == 400 and r.json()["error"]["code"] == "missing_file"


def test_wrong_content_type(client):
    r = client.post("/api/analyze", content=b"raw", headers={"content-type": "application/octet-stream"})
    assert r.status_code == 415


def test_too_many_files_rejected(client):
    r = client.post("/api/analyze", files=[("file", ("a", b"1")), ("file", ("b", b"2"))])
    assert r.status_code == 400
    assert "Traceback" not in r.text


def test_size_limit_by_content_length(make_client):
    c = make_client(max_upload_bytes=1024 * 1024)
    r = c.post("/api/analyze", files={"file": ("big.bin", b"\x00" * (2 * 1024 * 1024))})
    assert r.status_code == 413
    assert r.json()["error"]["code"] == "payload_too_large"


def test_size_limit_while_streaming_chunked(make_client):
    c = make_client(max_upload_bytes=1024 * 1024)

    def body():
        yield b'--b\r\nContent-Disposition: form-data; name="file"; filename="a.bin"\r\n\r\n'
        for _ in range(64):
            yield b"\x00" * 65536
        yield b"\r\n--b--\r\n"

    r = c.post("/api/analyze", content=body(), headers={"content-type": "multipart/form-data; boundary=b"})
    assert r.status_code == 413


def test_exact_limit_is_enforced_on_file_bytes(make_client):
    limit = 1024 * 1024
    c = make_client(max_upload_bytes=limit)
    ok = c.post("/api/analyze", files={"file": ("ok.bin", b"\x01" * limit)})
    over = c.post("/api/analyze", files={"file": ("over.bin", b"\x01" * (limit + 10))})
    assert ok.status_code == 200
    assert over.status_code == 413


def test_internal_errors_hide_details(make_client, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("secret internal path /srv/app/thing.py")

    monkeypatch.setattr(main_module, "analyze", boom)
    c = make_client()
    c_raise = c.__class__(c.app, raise_server_exceptions=False)
    r = c_raise.post("/api/analyze", files={"file": ("a.txt", b"hello")})
    assert r.status_code == 500
    assert r.json() == {
        "error": {"code": "internal_error", "message": "Something went wrong while analysing the file."}
    }
    assert "secret" not in r.text and "Traceback" not in r.text


def test_analysis_timeout(make_client, monkeypatch):
    def slow(*_a, **_k):
        time.sleep(0.5)
        return {}

    monkeypatch.setattr(main_module, "analyze", slow)
    r = make_client(analysis_timeout_s=0.05).post("/api/analyze", files={"file": ("a.txt", b"hello")})
    assert r.status_code == 503 and r.json()["error"]["code"] == "analysis_timeout"


def test_unknown_route_and_method_are_json(client):
    assert client.get("/nope").json()["error"]["code"] == "not_found"
    r = client.get("/api/analyze")
    assert r.status_code == 405 and r.json()["error"]["code"] == "method_not_allowed"


def test_docs_disabled(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404
