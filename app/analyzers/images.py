"""Image metadata via Pillow: dimensions, EXIF, GPS.

Pillow only parses headers here (Image.open is lazy and we never call load()),
so pixel data is not decoded. MAX_IMAGE_PIXELS is lowered and the bomb warning
is promoted to an error.
"""

from __future__ import annotations

import contextlib
import io
import struct
import warnings
from datetime import datetime

from PIL import ExifTags, Image, UnidentifiedImageError

MAX_PIXELS = 64_000_000  # ~8000 x 8000
Image.MAX_IMAGE_PIXELS = MAX_PIXELS

PILLOW_TYPES = {"jpeg", "png", "gif", "bmp", "tiff", "webp", "ico", "psd", "jp2"}

_INTERESTING = {
    "Make", "Model", "Software", "DateTime", "DateTimeOriginal", "DateTimeDigitized", "Artist",
    "Copyright", "ImageDescription", "LensMake", "LensModel", "BodySerialNumber", "CameraOwnerName",
    "HostComputer", "OffsetTimeOriginal", "ExifImageWidth", "ExifImageHeight", "Orientation",
    "XPAuthor", "XPComment", "UserComment",
}  # fmt: skip
_EDITORS = ("photoshop", "gimp", "lightroom", "affinity", "paint.net", "pixelmator", "snapseed", "canva", "picsart")
_MAX_VALUE_LEN = 200


def _clean(value) -> str | int | float | None:
    if isinstance(value, bytes):
        if value.startswith(b"ASCII\x00\x00\x00"):
            value = value[8:]
        try:
            text = value.decode("utf-16-le" if b"\x00" in value[1::2] and len(value) % 2 == 0 else "utf-8")
        except UnicodeDecodeError:
            return f"<{len(value)} bytes binary>"
        value = text
    if isinstance(value, (int, float)):
        return value
    try:
        f = float(value)  # IFDRational
        return round(f, 6) if not f.is_integer() else int(f)
    except (TypeError, ValueError):
        pass
    text = str(value).replace("\x00", "").strip()
    text = "".join(ch for ch in text if ch.isprintable())
    return text[:_MAX_VALUE_LEN] if text else None


def _dms_to_decimal(dms, ref) -> float | None:
    try:
        d, m, s = (float(x) for x in dms)
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    dec = d + m / 60.0 + s / 3600.0
    if isinstance(ref, bytes):
        ref = ref.decode("ascii", "ignore")
    if str(ref).strip().upper() in ("S", "W"):
        dec = -dec
    return round(dec, 6)


def _parse_exif_time(value) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value.strip()[:19], "%Y:%m:%d %H:%M:%S").isoformat()
    except ValueError:
        return None


def analyze_image(data: bytes) -> dict:
    out: dict = {"parsed": False}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # Pillow warns on corrupt EXIF; we report what parses
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as img:
                out.update(
                    parsed=True,
                    format=img.format,
                    width=img.width,
                    height=img.height,
                    mode=img.mode,
                    frames=getattr(img, "n_frames", 1),
                )
                if img.width * img.height > MAX_PIXELS:
                    raise Image.DecompressionBombError("image exceeds pixel limit")
                exif = img.getexif()
                tags: dict = {}
                for tag_id, val in list(exif.items())[:200]:
                    name = ExifTags.TAGS.get(tag_id, f"0x{tag_id:04X}")
                    if name in _INTERESTING:
                        tags[name] = _clean(val)
                try:
                    sub = exif.get_ifd(ExifTags.IFD.Exif)
                except (KeyError, ValueError, TypeError, SyntaxError):
                    sub = {}
                for tag_id, val in list(sub.items())[:200]:
                    name = ExifTags.TAGS.get(tag_id, f"0x{tag_id:04X}")
                    if name in _INTERESTING:
                        tags[name] = _clean(val)
                out["exif"] = {k: v for k, v in tags.items() if v is not None}
                out["exif_tag_count"] = len(exif) + len(sub)

                gps = None
                try:
                    gps_ifd = exif.get_ifd(ExifTags.IFD.GPSInfo)
                except (KeyError, ValueError, TypeError, SyntaxError):
                    gps_ifd = {}
                if gps_ifd:
                    g = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_ifd.items()}
                    lat = _dms_to_decimal(g.get("GPSLatitude"), g.get("GPSLatitudeRef", "N"))
                    lon = _dms_to_decimal(g.get("GPSLongitude"), g.get("GPSLongitudeRef", "E"))
                    if lat is not None and lon is not None and -90 <= lat <= 90 and -180 <= lon <= 180:
                        gps = {"latitude": lat, "longitude": lon}
                        alt = g.get("GPSAltitude")
                        if alt is not None:
                            with contextlib.suppress(TypeError, ValueError, ZeroDivisionError):
                                gps["altitude_m"] = round(float(alt), 1)
                        gps["map_url"] = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=15/{lat}/{lon}"
                out["gps"] = gps

                text_chunks = {}
                for k, v in list((img.info or {}).items())[:50]:
                    if k in (
                        "exif",
                        "icc_profile",
                        "xmp",
                        "transparency",
                        "dpi",
                        "gamma",
                        "duration",
                        "loop",
                        "background",
                        "jfif",
                        "jfif_version",
                        "jfif_unit",
                        "jfif_density",
                        "adobe",
                        "adobe_transform",
                        "progression",
                        "progressive",
                        "aspect",
                        "sizes",
                        "version",
                    ):
                        continue
                    if isinstance(v, (str, bytes)):
                        text_chunks[str(k)[:64]] = _clean(v)
                out["text_chunks"] = text_chunks
                out["has_xmp"] = "xmp" in (img.info or {}) or b"<x:xmpmeta" in data[:65536]
                out["has_icc_profile"] = "icc_profile" in (img.info or {})
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        out.update(parsed=False, error="decompression bomb guard triggered", bomb=True, detail=str(exc)[:120])
        return out
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError, TypeError, EOFError, struct.error):
        out.update(parsed=False, error="image header could not be parsed")
        return out

    exif = out.get("exif", {})
    software = str(exif.get("Software") or "")
    out["edited_with"] = software if any(e in software.lower() for e in _EDITORS) else None
    original = _parse_exif_time(exif.get("DateTimeOriginal"))
    modified = _parse_exif_time(exif.get("DateTime"))
    out["timestamps"] = {"original": original, "modified": modified}
    out["modified_after_capture"] = bool(original and modified and modified > original)
    return out
