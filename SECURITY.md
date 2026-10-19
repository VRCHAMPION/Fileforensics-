# Security

FileForensics takes untrusted files from strangers and parses them. That is the whole threat model, so most of the code is written around one question: what happens when the file is lying?

## Reporting a vulnerability

Please don't open a public issue for security bugs.

Use GitHub's **private vulnerability reporting** on this repository (Security tab → "Report a vulnerability").

Include the file (or a script that generates it) and what you expected vs. what happened. I'll acknowledge within 72 hours and aim to ship a fix or mitigation within 14 days for anything that leads to code execution, file disclosure, persistence of uploads, or a reliable denial of service. Please give me that window before disclosing publicly. I'm happy to credit you in the release notes.

Supported version: the latest commit on `main`.

## Design: what each control does and why

### 1. Uploads never touch disk

- The request body is parsed into memory and the bytes live only in the request handler's scope. The multipart form is opened with `async with request.form(...)`, so the upload buffer is closed as soon as the bytes are read.
- Starlette's multipart parser normally rolls any part larger than 1 MB over to a temporary file. `create_app()` raises `MultiPartParser.spool_max_size` to the upload limit plus multipart overhead, so the spool never spills.
- The client's filename is never used as a path. It goes through `sanitize_filename()` (strips directories, control and bidi-override characters like U+202E, unsafe punctuation, and length) and is only ever displayed.
- Tests: `test_uploads_never_touch_disk` spies on `tempfile.TemporaryFile` / `NamedTemporaryFile` and checks that the working directory and a private temp dir stay empty for a 3 MB upload. `test_spool_would_have_spilled_without_our_setting` is the negative control that proves the spy catches a rollover.

### 2. Size limits enforced while streaming

`BodySizeLimitMiddleware` (pure ASGI) does two things:

1. If `Content-Length` is larger than the limit, it answers `413` before reading a single body byte.
2. Otherwise it counts bytes as they arrive and aborts the moment the cap is crossed, so chunked uploads with no declared length can't get past it.

The handler then reads at most `limit + 1` bytes from the part and rejects anything over the exact limit (default 15 MB, `FF_MAX_UPLOAD_MB`). The form parser is also limited to one file and four fields.

### 3. Decompression and zip-bomb guards

ZIP-based formats (ZIP, OOXML, ODF, JAR, APK, EPUB) are inspected with `zipfile` over a `BytesIO`. Nothing is extracted.

- The End Of Central Directory record is read first, and archives that declare more than 2,000 entries are refused before `ZipFile` parses the directory.
- Declared total uncompressed size (256 MB cap) and per-entry compression ratio (100:1 for entries ≥ 1 MB) are flagged.
- Central directory entries that point at the same local header (the overlapping-file technique from David Fifield's "better zip bomb") are detected.
- The few members we actually read (`[Content_Types].xml`, `*.rels`, `word/document.xml`, `mimetype`) go through `read_member()`, which calls `read(limit)` on the decompressing stream. A lying header can cost at most that many bytes.
- PDF `FlateDecode` streams are inflated with `zlib.decompressobj().decompress(data, max_length)`: 1 MB per stream, 16 MB in total, 500 streams max.
- Relationship XML is matched with bounded regular expressions instead of an XML parser, which rules out entity expansion and XXE.

### 4. Images

- `Image.MAX_IMAGE_PIXELS` is set to 64 megapixels, and `DecompressionBombWarning` is promoted to an error, so anything over the limit is rejected rather than just logged.
- `Image.open()` is lazy and `load()` is never called. Only headers and metadata are parsed, and pixel data is never decoded.

### 5. Nothing is executed

No file is run, rendered, emulated, or passed to an external tool. There is no `subprocess`, `eval`, or `pickle` anywhere in `app/`. PDFs are scanned for keywords and Office files are read as ZIP/CFB structures.

### 6. Time and work caps

- String extraction scans at most 16 MB, returns at most 20,000 strings (512 chars each), and checks a cooperative deadline as it goes.
- Every structure walker (JPEG segments, PNG chunks, GIF blocks, CFB sector chains, DIFAT) has an iteration cap and cycle detection.
- The whole analysis runs in a worker thread under `asyncio.wait_for` (`FF_ANALYSIS_TIMEOUT`, default 20 s). At most `FF_MAX_CONCURRENT` (default 4) analyses run at once.
- Each analyzer is isolated. If one throws on a malformed file, the report records it in `analyzer_errors` and the other analyzers still run. The benchmark fuzzes 5,000+ truncated and bit-flipped inputs to check this.

### 7. Rate limiting

There's an in-memory token bucket per client IP on `POST /api/analyze` (default 20/min, burst 5). It returns `429` with `Retry-After`. The table is LRU-bounded (10,000 clients), so spraying source addresses can't exhaust memory. `X-Forwarded-For` is only trusted when `FF_TRUST_PROXY=1`.

Limitation: the limiter is per process. If you run several workers or replicas, put the limit in the reverse proxy as well.

### 8. HTTP security headers

Every response, including errors and static files, gets:

| Header | Value |
|---|---|
| Content-Security-Policy | `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; require-trusted-types-for 'script'` |
| X-Content-Type-Options | `nosniff` |
| X-Frame-Options | `DENY` |
| Referrer-Policy | `no-referrer` |
| Permissions-Policy | camera, microphone, geolocation, payment, usb disabled |
| Cross-Origin-Opener-Policy | `same-origin` |
| Cross-Origin-Resource-Policy | `same-origin` |
| Strict-Transport-Security | only over HTTPS (direct, or `X-Forwarded-Proto: https` from a trusted proxy, or `FF_FORCE_HSTS=1`) |
| Cache-Control | `no-store` on `/api/*` |

The `Server` header is stripped, and the OpenAPI/Swagger endpoints are disabled.

### 9. XSS-safe output

- The frontend has no inline scripts or styles and no third-party assets, which is what lets the CSP above stay strict. A test enforces this.
- All file-derived text is written with `textContent` or `setAttribute` on elements we create. `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, and `eval` are absent, and a test greps for them. Trusted Types in the CSP would block them anyway.
- API responses are JSON with `<`, `>`, `&`, U+2028, and U+2029 escaped as `\uXXXX`. A report pasted into a page can't open a tag.
- Network IOCs (URLs, domains, IPs, emails) are defanged (`hxxp[://]evil[.]com`), so a report can't turn into a clickable live link.

### 10. Errors

Errors are structured (`{"error": {"code", "message"}}`). Unhandled exceptions are logged server-side and the client gets a generic 500 with no stack trace, path, or exception text. A test checks this.

### 11. Supply chain and CI

- There are four runtime dependencies, all pinned. `pip-audit` runs in CI.
- `bandit` runs over `app/` with zero findings and no `# nosec` suppressions.
- GitHub Actions are pinned to full commit SHAs, workflows default to `permissions: contents: read`, and checkout uses `persist-credentials: false`.
- CodeQL (`security-extended`) scans Python and JavaScript.
- Dependabot watches pip, Docker, and Actions.

### 12. Container

- The base image is pinned by tag and digest. It's a multi-stage build, and the runtime image has no compilers and no `pip` in the app venv.
- It runs as UID 10001, writes nothing at runtime, and works with `--read-only`.
- It includes a `HEALTHCHECK` and runs uvicorn with `--no-server-header` and a concurrency limit.

Recommended run:

```bash
docker run --rm -p 8000:8000 --read-only --tmpfs /tmp:size=16m \
  --cap-drop ALL --security-opt no-new-privileges --memory 512m --pids-limit 128 fileforensics
```

## Known limitations

- Static analysis can be evaded. A clean report doesn't mean a file is safe.
- Rate limiting and concurrency limits are per process.
- A Python thread can't be killed. If the request timeout fires, the request is answered, but the worker finishes its current bounded step in the background.
