import hashlib
import io

from app.analyzers.hashing import CHUNK, hash_bytes, hash_stream


def test_known_vectors():
    h = hash_bytes(b"abc")
    assert h["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert h["sha1"] == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert h["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_streamed_matches_one_shot_across_chunk_boundary():
    data = bytes(range(256)) * (CHUNK // 256 * 3 + 7)
    assert hash_bytes(data)["sha256"] == hashlib.sha256(data).hexdigest()
    assert hash_stream(io.BytesIO(data)) == hash_bytes(data)


def test_empty_input():
    assert hash_bytes(b"")["sha256"] == hashlib.sha256(b"").hexdigest()
