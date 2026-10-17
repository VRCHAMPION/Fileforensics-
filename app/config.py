"""Runtime settings, read from environment variables (no .env file needed)."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    max_upload_bytes: int = 15 * 1024 * 1024
    rate_limit_per_minute: int = 20
    rate_limit_burst: int = 5
    analysis_timeout_s: float = 20.0
    analysis_budget_s: float = 10.0
    max_concurrent_analyses: int = 4
    trust_proxy: bool = False
    force_hsts: bool = False

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            max_upload_bytes=_int("FF_MAX_UPLOAD_MB", 15) * 1024 * 1024,
            rate_limit_per_minute=_int("FF_RATE_LIMIT_PER_MIN", 20),
            rate_limit_burst=_int("FF_RATE_LIMIT_BURST", 5),
            analysis_timeout_s=_float("FF_ANALYSIS_TIMEOUT", 20.0),
            analysis_budget_s=_float("FF_ANALYSIS_BUDGET", 10.0),
            max_concurrent_analyses=_int("FF_MAX_CONCURRENT", 4),
            trust_proxy=_bool("FF_TRUST_PROXY", False),
            force_hsts=_bool("FF_FORCE_HSTS", False),
        )
