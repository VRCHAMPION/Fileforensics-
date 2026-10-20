"""Benchmark the detector against the generated corpus.

Usage:  python scripts/benchmark.py [--repeat 5] [--fuzz 20]

Everything is generated in memory by tests/corpus.py - no sample files on disk.
The corpus is synthetic (crafted headers, Pillow images, stdlib archives), so
the accuracy numbers are a regression baseline, not a claim about real-world
malware detection rates.
"""

from __future__ import annotations

import argparse
import logging
import os
import platform
import random
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.analyzers.mismatch import check_mismatch
from app.analyzers.signatures import SUPPORTED_TYPE_COUNT, identify
from app.report import analyze
from tests.corpus import mismatch_corpus, polyglot_corpus, rand_bytes, risk_corpus, type_corpus


def pct(a: int, b: int) -> str:
    return f"{100 * a / b:.1f}%" if b else "n/a"


def bench_identification() -> tuple[int, int]:
    per_cat: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    misses = []
    for s in type_corpus():
        got = identify(s.data).type.id
        per_cat[s.group][1] += 1
        if got == s.expected_type:
            per_cat[s.group][0] += 1
        else:
            misses.append(f"{s.name}: expected {s.expected_type}, got {got}")
    print("## File-type identification (magic bytes)\n")
    print(f"Detectable types in the signature database: {SUPPORTED_TYPE_COUNT}\n")
    print("| category | correct | samples | accuracy |")
    print("|---|---:|---:|---:|")
    total_ok = total = 0
    for cat in sorted(per_cat):
        ok, n = per_cat[cat]
        total_ok, total = total_ok + ok, total + n
        print(f"| {cat} | {ok} | {n} | {pct(ok, n)} |")
    print(f"| **all** | **{total_ok}** | **{total}** | **{pct(total_ok, total)}** |\n")
    for m in misses:
        print(f"- miss: {m}")
    return total_ok, total


def bench_mismatch() -> None:
    cases = mismatch_corpus()
    ok = 0
    for s in cases:
        r = check_mismatch(s.name, identify(s.data).type)
        ok += r["mismatch"] is s.tags["mismatch"] and r["severity"] == s.tags["severity"]
    print("## Extension spoofing\n")
    print(f"Correct mismatch flag + severity: {ok}/{len(cases)} ({pct(ok, len(cases))})\n")


def confusion(rows: list[tuple[bool, bool]]) -> dict:
    tp = sum(1 for exp, got in rows if exp and got)
    tn = sum(1 for exp, got in rows if not exp and not got)
    fp = sum(1 for exp, got in rows if not exp and got)
    fn = sum(1 for exp, got in rows if exp and not got)
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn}


def bench_polyglot() -> None:
    rows = []
    for s in polyglot_corpus():
        r = analyze(s.data, s.name)
        rows.append((s.tags["polyglot"], r["appended"]["appended_type"] not in (None, "text")))
    c = confusion(rows)
    print("## Polyglot / appended-data detection\n")
    print(f"TP {c['tp']} · TN {c['tn']} · FP {c['fp']} · FN {c['fn']} "
          f"(accuracy {pct(c['tp'] + c['tn'], len(rows))})\n")  # fmt: skip


def bench_risk() -> None:
    rows = []
    for s in risk_corpus():
        r = analyze(s.data, s.name)
        rows.append((s.tags["malicious"], r["risk"]["score"] >= 20))
    c = confusion(rows)
    recall = pct(c["tp"], c["tp"] + c["fn"])
    precision = pct(c["tp"], c["tp"] + c["fp"])
    print("## Risk triage (score >= 20 means flagged)\n")
    print(f"{c['tp'] + c['fn']} suspicious + {c['tn'] + c['fp']} benign samples: "
          f"recall {recall}, precision {precision}, false positives {c['fp']}\n")  # fmt: skip


def bench_speed(repeat: int) -> None:
    corpus = type_corpus() + mismatch_corpus() + polyglot_corpus() + risk_corpus()
    times = []
    for _ in range(repeat):
        for s in corpus:
            t0 = time.perf_counter()
            analyze(s.data, s.name)
            times.append((time.perf_counter() - t0) * 1000)
    times.sort()
    p95 = times[int(len(times) * 0.95) - 1]
    print("## Speed (full analysis pipeline, single thread)\n")
    print(f"- corpus: {len(corpus)} files x {repeat} runs = {len(times)} analyses")
    print(f"- mean {statistics.mean(times):.2f} ms · median {statistics.median(times):.2f} ms · p95 {p95:.2f} ms")
    big_random = rand_bytes(4096) * (15 * 256)  # 15 MB, high entropy
    big_text = (b"GET /index.html HTTP/1.1 from 203.0.113.5 user=admin\n" * 400_000)[: 15 * 1024 * 1024]
    for label, blob in (("15 MB high-entropy blob", big_random), ("15 MB text log", big_text)):
        t0 = time.perf_counter()
        analyze(blob, "big.bin")
        print(f"- {label}: {(time.perf_counter() - t0) * 1000:.0f} ms")
    print()


def bench_fuzz(per_seed: int) -> None:
    logging.disable(logging.CRITICAL)
    seeds = type_corpus() + polyglot_corpus() + risk_corpus()
    runs = errors = 0
    for s in seeds:
        rng = random.Random(s.name)
        for _ in range(per_seed):
            m = bytearray(s.data)
            for _ in range(max(1, len(m) // 64)):
                m[rng.randrange(len(m))] = rng.randrange(256)
            for blob in (bytes(m), s.data[: rng.randrange(1, len(s.data) + 1)]):
                runs += 1
                report = analyze(blob, s.name)
                errors += bool(report["analyzer_errors"])
    logging.disable(logging.NOTSET)
    print("## Robustness (mutated + truncated inputs)\n")
    print(f"{runs} malformed inputs analysed, {errors} with an internal analyzer error, 0 crashes\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeat", type=int, default=5)
    ap.add_argument("--fuzz", type=int, default=20)
    args = ap.parse_args()
    cpu = platform.processor() or platform.machine()
    print(f"# FileForensics benchmark\n\nPython {platform.python_version()} · {platform.system()} {cpu} · "
          f"{os.cpu_count()} CPUs\n")  # fmt: skip
    bench_identification()
    bench_mismatch()
    bench_polyglot()
    bench_risk()
    bench_speed(args.repeat)
    bench_fuzz(args.fuzz)


if __name__ == "__main__":
    main()
