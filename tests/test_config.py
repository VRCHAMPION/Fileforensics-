from app.config import Settings


def test_defaults():
    s = Settings()
    assert s.max_upload_bytes == 15 * 1024 * 1024
    assert s.trust_proxy is False


def test_from_env(monkeypatch):
    monkeypatch.setenv("FF_MAX_UPLOAD_MB", "5")
    monkeypatch.setenv("FF_RATE_LIMIT_PER_MIN", "7")
    monkeypatch.setenv("FF_TRUST_PROXY", "yes")
    monkeypatch.setenv("FF_ANALYSIS_TIMEOUT", "3.5")
    s = Settings.from_env()
    assert s.max_upload_bytes == 5 * 1024 * 1024
    assert s.rate_limit_per_minute == 7
    assert s.trust_proxy is True
    assert s.analysis_timeout_s == 3.5


def test_bad_env_values_fall_back(monkeypatch):
    monkeypatch.setenv("FF_MAX_UPLOAD_MB", "lots")
    monkeypatch.setenv("FF_ANALYSIS_TIMEOUT", "soon")
    s = Settings.from_env()
    assert s.max_upload_bytes == 15 * 1024 * 1024
    assert s.analysis_timeout_s == 20.0
