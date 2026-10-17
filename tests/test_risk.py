import pytest

from app.analyzers.risk import WEIGHTS, level_for
from app.report import analyze
from tests.corpus import make_pdf, make_pe, risk_corpus

CASES = risk_corpus()


@pytest.mark.parametrize("sample", CASES, ids=[s.name for s in CASES])
def test_risk_corpus(sample):
    report = analyze(sample.data, sample.name)
    assert report["type"]["id"] == sample.expected_type
    flagged = report["risk"]["score"] >= 20
    assert flagged is sample.tags["malicious"], report["risk"]["findings"]


def test_score_is_sum_of_weights_capped():
    report = analyze(make_pe(sections=("UPX0", "UPX1"), high_entropy=True), "cute_cat.jpg")
    risk = report["risk"]
    assert risk["score"] == min(100, sum(f["weight"] for f in risk["findings"]))
    assert risk["score"] <= 100


def test_findings_sorted_by_severity():
    order = list(WEIGHTS)
    findings = analyze(make_pdf(javascript=True, open_action=True, incremental=1), "x.pdf")["risk"]["findings"]
    ranks = [order.index(f["severity"]) for f in findings]
    assert ranks == sorted(ranks)


@pytest.mark.parametrize(
    "score,level",
    [(0, "clean"), (4, "clean"), (5, "low"), (20, "medium"), (45, "high"), (70, "critical"), (100, "critical")],
)
def test_levels(score, level):
    assert level_for(score) == level


def test_every_finding_is_explained():
    findings = analyze(make_pe(), "invoice.pdf")["risk"]["findings"]
    assert findings
    for f in findings:
        assert f["title"] and f["severity"] in WEIGHTS and f["weight"] == WEIGHTS[f["severity"]]


def test_executable_hidden_in_appended_archive():
    from tests.corpus import make_image, make_zip

    data = make_image("JPEG") + make_zip({"invoice_scan.exe": make_pe()})
    ids = {f["id"] for f in analyze(data, "cat.jpg")["risk"]["findings"]}
    assert {"polyglot.appended", "polyglot.hidden_executable"} <= ids
