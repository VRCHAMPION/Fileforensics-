from app.analyzers.entropy import MAX_BLOCKS, analyze_entropy, block_size_for
from tests.corpus import rand_bytes


def test_constant_data_has_zero_entropy():
    r = analyze_entropy(b"\x00" * 4096)
    assert r["overall"] == 0.0
    assert not r["likely_packed_or_encrypted"]


def test_uniform_bytes_are_eight_bits():
    r = analyze_entropy(bytes(range(256)) * 64)
    assert r["overall"] == 8.0


def test_random_blob_flagged_as_packed():
    r = analyze_entropy(rand_bytes(64 * 1024), "unknown")
    assert r["overall"] > 7.9
    assert r["likely_packed_or_encrypted"]
    assert r["high_blocks"] == len(r["blocks"])


def test_random_blob_not_flagged_for_compressed_type():
    r = analyze_entropy(rand_bytes(8192), "zip")
    assert not r["likely_packed_or_encrypted"]
    assert "expected" in r["assessment"]


def test_block_count_is_capped():
    assert block_size_for(15 * 1024 * 1024) * MAX_BLOCKS >= 15 * 1024 * 1024
    r = analyze_entropy(b"ab" * 300_000)
    assert len(r["blocks"]) <= MAX_BLOCKS


def test_empty():
    assert analyze_entropy(b"")["assessment"] == "empty"
