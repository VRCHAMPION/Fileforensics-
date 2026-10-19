"""FastAPI application: one upload endpoint, a health check, and the static UI."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.formparsers import MultiPartParser

from . import __version__
from .config import Settings
from .ratelimit import TokenBucketLimiter
from .report import analyze
from .sanitize import SafeJSONResponse
from .security import BodySizeLimitMiddleware, SecurityHeadersMiddleware

log = logging.getLogger("fileforensics")
STATIC_DIR = Path(__file__).parent / "static"
MULTIPART_OVERHEAD = 64 * 1024


def error(status: int, code: str, message: str, headers: dict | None = None) -> SafeJSONResponse:
    return SafeJSONResponse({"error": {"code": code, "message": message}}, status_code=status, headers=headers)


def client_ip(request: Request, trust_proxy: bool) -> str:
    if trust_proxy:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()[:64]
    return request.client.host if request.client else "unknown"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    # Keep the whole upload in RAM: Starlette would otherwise roll parts larger than
    # 1 MB over to a temporary file on disk.
    MultiPartParser.spool_max_size = settings.max_upload_bytes + MULTIPART_OVERHEAD

    app = FastAPI(title="FileForensics", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.limiter = TokenBucketLimiter(settings.rate_limit_per_minute, settings.rate_limit_burst)
    app.state.slots = asyncio.Semaphore(settings.max_concurrent_analyses)

    app.add_middleware(BodySizeLimitMiddleware, max_body=settings.max_upload_bytes + MULTIPART_OVERHEAD)
    app.add_middleware(SecurityHeadersMiddleware, trust_proxy=settings.trust_proxy, force_hsts=settings.force_hsts)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_request: Request, exc: StarletteHTTPException):
        codes = {400: "bad_request", 404: "not_found", 405: "method_not_allowed", 413: "payload_too_large"}
        message = exc.detail if exc.status_code < 500 and isinstance(exc.detail, str) else "Request failed."
        return error(exc.status_code, codes.get(exc.status_code, "error"), message[:200])

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, _exc: RequestValidationError):
        return error(422, "invalid_request", "Request parameters are invalid.")

    @app.exception_handler(Exception)
    async def unhandled(_request: Request, exc: Exception):
        log.exception("unhandled error: %s", type(exc).__name__)
        return error(500, "internal_error", "Something went wrong while analysing the file.")

    @app.get("/api/health")
    async def health():
        return SafeJSONResponse({"status": "ok", "version": __version__})

    @app.get("/api/limits")
    async def limits():
        return SafeJSONResponse(
            {"max_upload_bytes": settings.max_upload_bytes, "rate_limit_per_minute": settings.rate_limit_per_minute}
        )

    @app.post("/api/analyze")
    async def analyze_endpoint(request: Request, download: bool = False):
        allowed, retry = app.state.limiter.allow(client_ip(request, settings.trust_proxy))
        if not allowed:
            wait = max(1, int(retry + 0.999))
            return error(
                429, "rate_limited", f"Too many uploads. Try again in {wait}s.", headers={"Retry-After": str(wait)}
            )
        if not request.headers.get("content-type", "").startswith("multipart/form-data"):
            return error(415, "unsupported_media_type", "Send the file as multipart/form-data in a 'file' field.")

        async with request.form(max_files=1, max_fields=4, max_part_size=4096) as form:
            upload = form.get("file")
            if not isinstance(upload, UploadFile):
                return error(400, "missing_file", "No file was uploaded in the 'file' field.")
            data = await upload.read(settings.max_upload_bytes + 1)
            filename = upload.filename
        # Leaving the context manager closed the spooled buffer; `data` is the only copy.

        if len(data) > settings.max_upload_bytes:
            return error(
                413, "payload_too_large", f"Upload exceeds the {settings.max_upload_bytes // (1024 * 1024)} MB limit."
            )
        if not data:
            return error(400, "empty_file", "The uploaded file is empty.")

        async with app.state.slots:
            try:
                report = await asyncio.wait_for(
                    asyncio.to_thread(analyze, data, filename, settings.analysis_budget_s),
                    timeout=settings.analysis_timeout_s,
                )
            except TimeoutError:
                return error(503, "analysis_timeout", "Analysis took too long and was stopped.")
            finally:
                del data

        headers = {}
        if download:
            headers["Content-Disposition"] = (
                f'attachment; filename="fileforensics-{report["hashes"]["sha256"][:16]}.json"'
            )
        return SafeJSONResponse(report, headers=headers)

    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(STATIC_DIR / "index.html", media_type="text/html; charset=utf-8")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


app = create_app()
