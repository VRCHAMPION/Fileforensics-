import json
import tempfile
from pathlib import Path

from starlette.formparsers import MultiPartParser

from app.ratelimit import TokenBucketLimiter
from app.sanitize import SafeJSONResponse, ascii_filename, sanitize_filename

REQUIRED_HEADERS = {
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "x-frame-options",
}


def test_security_headers_everywhere(client):
    for path in ("/", "/api/health", "/static/css/style.css", "/does-not-exist"):
        r = client.get(path)
        missing = REQUIRED_HEADERS - set(r.headers)
        assert not missing, (path, missing)
        assert "server" not in r.headers


def test_csp_is_strict(client):
    csp = client.get("/").headers["content-security-policy"]
    for directive in (
        "default-src 'self'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "script-src 'self'",
        "require-trusted-types-for 'script'",
    ):
        assert directive in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert client.get("/").headers["x-content-type-options"] == "nosniff"


def test_api_responses_not_cached(client):
    assert client.get("/api/health").headers["cache-control"] == "no-store"


def test_hsts_only_over_https(make_client):
    plain = make_client()
    assert "strict-transport-security" not in plain.get("/").headers
    proxied = make_client(trust_proxy=True)
    r = proxied.get("/", headers={"x-forwarded-proto": "https"})
    assert r.headers["strict-transport-security"].startswith("max-age=")
    # an untrusted client can't fake it
    assert "strict-transport-security" not in plain.get("/", headers={"x-forwarded-proto": "https"}).headers
    assert "strict-transport-security" in make_client(force_hsts=True).get("/").headers


def test_rate_limit_returns_429(make_client):
    c = make_client(rate_limit_per_minute=2, rate_limit_burst=2)
    codes = [c.post("/api/analyze", files={"file": ("a.txt", b"hi")}).status_code for _ in range(4)]
    assert codes[:2] == [200, 200] and codes[2:] == [429, 429]
    r = c.post("/api/analyze", files={"file": ("a.txt", b"hi")})
    assert r.json()["error"]["code"] == "rate_limited"
    assert int(r.headers["retry-after"]) >= 1


def test_rate_limit_is_per_ip_behind_trusted_proxy(make_client):
    c = make_client(rate_limit_per_minute=1, rate_limit_burst=1, trust_proxy=True)
    send = lambda ip: c.post("/api/analyze", files={"file": ("a", b"x")}, headers={"x-forwarded-for": ip})  # noqa: E731
    assert send("1.1.1.1").status_code == 200
    assert send("1.1.1.1").status_code == 429
    assert send("2.2.2.2").status_code == 200


def test_token_bucket_refills():
    now = [0.0]
    lim = TokenBucketLimiter(rate_per_minute=60, burst=1, clock=lambda: now[0])
    assert lim.allow("a")[0] is True
    allowed, retry = lim.allow("a")
    assert allowed is False and 0 < retry <= 1
    now[0] += 1.0
    assert lim.allow("a")[0] is True


def test_token_bucket_memory_is_bounded():
    lim = TokenBucketLimiter(60, 1, max_clients=50)
    for i in range(500):
        lim.allow(f"10.0.{i // 256}.{i % 256}")
    assert len(lim) == 50


def test_uploads_never_touch_disk(client, tmp_path, monkeypatch):
    # 1) Any temp file Python creates (including a SpooledTemporaryFile rolling over to
    #    disk) goes through tempfile.TemporaryFile / NamedTemporaryFile: spy on both.
    created = []
    real_tf, real_ntf = tempfile.TemporaryFile, tempfile.NamedTemporaryFile

    def spy(real):
        def _wrapped(*a, **k):
            created.append(real.__name__)
            return real(*a, **k)

        return _wrapped

    monkeypatch.setattr(tempfile, "TemporaryFile", spy(real_tf))
    monkeypatch.setattr(tempfile, "NamedTemporaryFile", spy(real_ntf))
    # 2) And nothing may appear in the working directory or a private temp dir.
    spill = tmp_path / "spill"
    spill.mkdir()
    work = tmp_path / "cwd"
    work.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(spill))
    monkeypatch.chdir(work)

    payload = b"FF-MARKER" + b"\x00" * (3 * 1024 * 1024)  # bigger than Starlette's default 1 MB spool
    r = client.post("/api/analyze", files={"file": ("../../etc/passwd", payload)})
    assert r.status_code == 200
    assert created == []
    assert list(spill.iterdir()) == []
    assert list(work.iterdir()) == []


def test_spool_would_have_spilled_without_our_setting(client, monkeypatch):
    """Negative control: proves the spy above actually detects a rollover."""
    created = []
    real_tf = tempfile.TemporaryFile
    monkeypatch.setattr(MultiPartParser, "spool_max_size", 1024 * 1024)
    monkeypatch.setattr(tempfile, "TemporaryFile", lambda *a, **k: created.append(1) or real_tf(*a, **k))
    client.post("/api/analyze", files={"file": ("x.bin", b"\x00" * (3 * 1024 * 1024))})
    assert created


def test_filename_never_used_as_path(upload):
    rep = upload("../../../../etc/cron.d/evil", b"hello").json()
    assert rep["file"]["name"] == "evil"


def test_sanitize_filename_cases():
    assert sanitize_filename(None) == "unnamed"
    assert sanitize_filename("..") == "unnamed"
    assert sanitize_filename("C:\\Windows\\System32\\x.dll") == "x.dll"
    assert sanitize_filename("in\u202egnp.exe") == "ingnp.exe"  # RTLO override stripped
    assert sanitize_filename("a\x00b\r\nc.txt") == "abc.txt"
    assert sanitize_filename('"><img src=x onerror=alert(1)>.png') == "___img src_x onerror_alert(1)_.png"
    long = sanitize_filename("a" * 500 + ".pdf")
    assert len(long) == 200 and long.endswith(".pdf")
    assert ascii_filename("résumé file.pdf") == "r_sum__file.pdf"


def test_safe_json_escapes_html():
    body = SafeJSONResponse({"x": "</script><script>alert(1)</script>&\u2028"}).body
    assert b"<" not in body and b">" not in body and b"&" not in body
    assert json.loads(body)["x"] == "</script><script>alert(1)</script>&\u2028"


def test_xss_payloads_in_file_content_are_escaped(upload):
    evil = b"<script>alert(document.cookie)</script> <img src=x onerror=alert(1)> http://x.test/<svg/onload=1>"
    r = upload("<svg onload=alert(1)>.html", evil)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert b"<script" not in r.content and b"<img" not in r.content and b"<svg" not in r.content
    rep = r.json()
    assert "<" not in rep["file"]["name"]
    assert any("<script>" in s["value"] for s in rep["strings"]["sample"])  # data intact once decoded


STATIC = Path(__file__).resolve().parent.parent / "app" / "static"


def test_frontend_uses_no_html_sinks():
    js = (STATIC / "js" / "app.js").read_text(encoding="utf-8")
    code = "\n".join(line for line in js.splitlines() if not line.strip().startswith("//"))
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert sink not in code, sink


def test_index_has_no_inline_script_or_style():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert "<style" not in html and " style=" not in html
    assert "<script>" not in html and "javascript:" not in html
    for attr in ("onclick=", "onload=", "onerror=", "onchange="):
        assert attr not in html
    assert "http://" not in html and "cdn" not in html.lower()
