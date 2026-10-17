"""Hostile-input tests: truncated and bit-flipped files must never crash the analyzers."""

import random
import struct

import pytest

from app.analyzers.cfb import parse_cfb
from app.report import analyze
from tests.corpus import make_cfb, polyglot_corpus, risk_corpus, type_corpus

SEEDS = type_corpus() + polyglot_corpus()[:5] + risk_corpus()[:10]


@pytest.mark.parametrize("sample", SEEDS, ids=[f"{s.group}-{s.name}" for s in SEEDS])
def test_truncation_and_bitflips_never_crash(sample):
    rng = random.Random(sample.name)
    data = sample.data
    variants = [data[: len(data) // 2], data[:17], data[:1]]
    for _ in range(4):
        mutated = bytearray(data)
        for _ in range(max(1, len(mutated) // 64)):
            mutated[rng.randrange(len(mutated))] = rng.randrange(256)
        variants.append(bytes(mutated))
    for v in variants:
        report = analyze(v, sample.name, budget_s=5)
        assert 0 <= report["risk"]["score"] <= 100


def test_cfb_directory_cycle_terminates():
    data = bytearray(make_cfb([("WordDocument", 2)]))
    struct.pack_into("<I", data, 512 + 4, 1)  # FAT: directory sector points at itself
    info = parse_cfb(bytes(data))
    assert info is not None and info.truncated


def test_cfb_difat_cycle_terminates():
    data = bytearray(make_cfb([("WordDocument", 2)]))
    struct.pack_into("<I", data, 0x44, 1)  # DIFAT chain starts at the directory sector
    struct.pack_into("<I", data, 512 + 512 + 508, 1)  # ...whose last slot loops back to itself
    assert parse_cfb(bytes(data)) is not None


def test_cfb_rejects_bad_sector_shift():
    data = bytearray(make_cfb([("X", 2)]))
    struct.pack_into("<H", data, 0x1E, 7)
    assert parse_cfb(bytes(data)) is None


def test_cfb_directory_beyond_eof():
    data = bytearray(make_cfb([("X", 2)]))
    struct.pack_into("<I", data, 0x30, 999)
    info = parse_cfb(bytes(data))
    assert info.truncated and info.entries == []
