"""ASGI middleware: security headers and a streaming request-body cap."""

from __future__ import annotations

import json

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "require-trusted-types-for 'script'"
)

BASE_HEADERS = [
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"x-permitted-cross-domain-policies", b"none"),
]
HSTS = (b"strict-transport-security", b"max-age=63072000; includeSubDomains")


def _is_https(scope, trust_proxy: bool) -> bool:
    if scope.get("scheme") == "https":
        return True
    if trust_proxy:
        for k, v in scope.get("headers", []):
            if k == b"x-forwarded-proto" and v.split(b",")[0].strip().lower() == b"https":
                return True
    return False


class SecurityHeadersMiddleware:
    def __init__(self, app, trust_proxy: bool = False, force_hsts: bool = False):
        self.app = app
        self.trust_proxy = trust_proxy
        self.force_hsts = force_hsts

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        https = self.force_hsts or _is_https(scope, self.trust_proxy)
        is_api = scope.get("path", "").startswith("/api/")

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                drop = {h[0] for h in BASE_HEADERS} | {b"server"}
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() not in drop]
                headers.extend(BASE_HEADERS)
                if https:
                    headers.append(HSTS)
                if is_api:
                    headers.append((b"cache-control", b"no-store"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


class BodyTooLarge(Exception):
    pass


def error_body(code: str, message: str) -> bytes:
    return json.dumps({"error": {"code": code, "message": message}}).encode()


class BodySizeLimitMiddleware:
    """Reject oversized uploads early.

    1. If Content-Length is declared and too big, answer 413 before reading a byte.
    2. Otherwise count bytes as they stream in and abort the moment the cap is
       crossed, so a chunked upload can't sneak past the declared-length check.
    """

    def __init__(self, app, max_body: int):
        self.app = app
        self.max_body = max_body

    async def _reject(self, send):
        body = error_body("payload_too_large", f"Upload exceeds the {self.max_body // (1024 * 1024)} MB limit.")
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                                (b"connection", b"close")]})  # fmt: skip
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return
        for k, v in scope.get("headers", []):
            if k == b"content-length":
                try:
                    declared = int(v)
                except ValueError:
                    declared = -1
                if declared < 0 or declared > self.max_body:
                    await self._reject(send)
                    return

        received = 0
        started = False

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body:
                    raise BodyTooLarge()
            return message

        async def tracking_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except BodyTooLarge:
            if not started:
                await self._reject(send)
