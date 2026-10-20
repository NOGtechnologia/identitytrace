"""Benchmark regression tests.

These thresholds document the current state honestly, including the known
misses. If a change improves detection, update the expectations and
docs/benchmark-results.md together.
"""

import json

from benchmark.run import evaluate
from examples.generate_synthetic import build
from tests.conftest import DATASET, TRUTH


def test_dataset_is_reproducible():
    dataset, truth = build()
    assert json.loads(DATASET.read_text(encoding="utf-8")) == dataset
    assert json.loads(TRUTH.read_text(encoding="utf-8")) == truth


def test_metrics(demo_result, truth):
    m = evaluate(demo_result, truth)
    assert m["confusion"] == {"tp": 13, "fp": 2, "fn": 3, "tn": 434}
    assert m["precision"] >= 0.85
    assert m["recall"] >= 0.80
    assert m["false_positive_rate"] <= 0.01
    assert m["critical_findings_on_benign_events"] == []
    assert m["data_quality"]["matches_expectation"]


def test_required_test_cases(demo_result, truth):
    outcome = {s["id"]: s["outcome"] for s in evaluate(demo_result, truth)["scenarios"]}
    assert outcome["S14"] == "korrekt still"  # normal sign-in
    assert outcome["S02"] == "erkannt"  # new privileged role
    assert outcome["S03"] == "erkannt"  # unexpected permission expansion
    assert outcome["S04"] == "erkannt"  # audit logging changed
    assert outcome["S05"] == "erfüllt"  # incomplete logs made visible
    assert outcome["S06"] == "erkannt"  # manipulative text treated as data
    assert outcome["S13"] == "korrekt still"


def test_known_limitations_are_still_documented(demo_result, truth):
    outcome = {s["id"]: s["outcome"] for s in evaluate(demo_result, truth)["scenarios"]}
    assert outcome["S10"] == "übersehen"
    assert outcome["S15"] == "übersehen"
    assert outcome["S11"] == "Fehlalarm"
