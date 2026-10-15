from app.analyzers.deadline import Deadline
from app.analyzers.strings import StringLimits, extract_strings


def test_ascii_and_utf16():
    data = b"\x00\x01hello world\x00\x00" + "WIDE STRING".encode("utf-16-le") + b"\x00\x00abc\x00"
    r = extract_strings(data)
    values = [s["value"] for s in r["sample"]]
    assert "hello world" in values and "WIDE STRING" in values
    assert "abc" not in values  # below the minimum length
    assert r["ascii"] >= 1 and r["utf16le"] >= 1


def test_string_count_cap():
    data = b"\x00".join(b"str%05d" % i for i in range(5000))
    r = extract_strings(data, StringLimits(max_strings=100))
    assert r["total"] == 100 and r["capped"]


def test_long_strings_truncated_and_sample_limited():
    r = extract_strings(b"A" * 5000, StringLimits(max_string_len=64))
    assert len(r["sample"][0]["value"]) <= 64


def test_expired_deadline_stops_early():
    r = extract_strings(b"\x00".join(b"abcd" for _ in range(2000)), deadline=Deadline(-1))
    assert r["capped"]


def test_suspicious_tokens():
    r = extract_strings(b"\x00VirtualAlloc\x00CreateRemoteThread\x00powershell -enc AAA\x00")
    tokens = {s["token"] for s in r["suspicious"]}
    assert {"VirtualAlloc", "CreateRemoteThread", "powershell -e"} <= tokens


def test_scan_byte_cap():
    r = extract_strings(b"x" * 100 + b"\x00" + b"tail-string", StringLimits(max_scan_bytes=50))
    assert r["scanned_bytes"] == 50
