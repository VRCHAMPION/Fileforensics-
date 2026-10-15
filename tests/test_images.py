import struct
import zlib

from app.analyzers.images import MAX_PIXELS, analyze_image
from tests.corpus import make_image, make_jpeg_with_gps


def test_gps_converted_to_decimal():
    r = analyze_image(make_jpeg_with_gps(lat=19.0760, lon=72.8777))
    assert r["parsed"]
    assert abs(r["gps"]["latitude"] - 19.076) < 1e-3
    assert abs(r["gps"]["longitude"] - 72.8777) < 1e-3
    assert r["gps"]["altitude_m"] == 14.0
    assert r["gps"]["map_url"].startswith("https://www.openstreetmap.org/?mlat=19.07")


def test_southern_western_hemisphere_is_negative():
    r = analyze_image(make_jpeg_with_gps(lat=-33.8688, lon=-70.6693))
    assert r["gps"]["latitude"] < 0 and r["gps"]["longitude"] < 0


def test_camera_software_and_timestamps():
    r = analyze_image(make_jpeg_with_gps())
    assert r["exif"]["Make"] == "Canon"
    assert r["exif"]["Model"] == "Canon EOS 90D"
    assert r["edited_with"] == "Adobe Photoshop 25.0"
    assert r["timestamps"]["original"] == "2025-03-14T09:15:27"
    assert r["modified_after_capture"] is True


def test_plain_image_has_no_gps():
    r = analyze_image(make_image("PNG"))
    assert r["parsed"] and r["gps"] is None and r["format"] == "PNG"
    assert r["width"] == 32 and r["height"] == 24


def _png_header(width: int, height: int) -> bytes:
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    chunk = b"IHDR" + ihdr
    return (
        b"\x89PNG\r\n\x1a\n"
        + struct.pack(">I", len(ihdr))
        + chunk
        + struct.pack(">I", zlib.crc32(chunk))
        + b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )


def test_decompression_bomb_guard():
    side = int((MAX_PIXELS * 3) ** 0.5)
    r = analyze_image(_png_header(side, side))
    assert r["parsed"] is False and r.get("bomb") is True


def test_moderately_oversized_image_also_rejected():
    side = int((MAX_PIXELS * 1.5) ** 0.5)  # between the warning and error thresholds
    r = analyze_image(_png_header(side, side))
    assert r.get("bomb") is True


def test_garbage_does_not_raise():
    r = analyze_image(b"\xff\xd8\xff\xe0garbage")
    assert r["parsed"] is False and "error" in r
