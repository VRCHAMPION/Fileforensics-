from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


@pytest.fixture
def make_client():
    def _make(**overrides) -> TestClient:
        base = {"rate_limit_per_minute": 10_000, "rate_limit_burst": 10_000}
        base.update(overrides)
        return TestClient(create_app(Settings(**base)))

    return _make


@pytest.fixture
def client(make_client):
    return make_client()


@pytest.fixture
def upload(client):
    def _upload(name: str, data: bytes, **params):
        return client.post("/api/analyze", files={"file": (name, data, "application/octet-stream")}, params=params)

    return _upload
