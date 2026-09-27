"""
Debt scoring and before/after comparison.

The property under test throughout: the reported reduction must be a
consequence of a real re-scan, never a formula applied to the input alone.
"""

from __future__ import annotations

import pytest

from backend import metrics

CLEAN_PYTHON = '''"""Module docstring."""


def add(left: int, right: int) -> int:
    """Add two numbers."""
    return left + right
'''

DIRTY_PYTHON = "import hashlib\ndigest = hashlib.md5(b'x').hexdigest()\n"


# ── Normalisation ────────────────────────────────────────────────────────────

def test_zero_points_is_zero_score():
    assert metrics.normalise(0) == 0


def test_score_is_bounded():
    assert 0 <= metrics.normalise(10_000) <= 100


def test_score_is_monotonic():
    scores = [metrics.normalise(points) for points in range(0, 400, 7)]
    assert scores == sorted(scores)


def test_score_never_saturates_to_a_flat_cap():
    """The old implementation clipped at 98 and lost all resolution above it."""
    assert metrics.normalise(500) > metrics.normalise(200)


# ── Breakdown ────────────────────────────────────────────────────────────────

def test_breakdown_accounts_for_every_point(example):
    assessment = metrics.assess(example["original_code"], example["language"])
    itemised = sum(item["points"] for item in assessment["debt_breakdown"])
    assert itemised == assessment["debt_points"]


def test_breakdown_items_reference_a_source(example):
    assessment = metrics.assess(example["original_code"], example["language"])
    for item in assessment["debt_breakdown"]:
        assert item["source"]
        assert item["label"]
        assert item["points"] > 0


def test_structural_penalties_are_itemised_separately():
    assessment = metrics.assess(DIRTY_PYTHON, "python")
    sources = {item["source"] for item in assessment["debt_breakdown"]}
    assert "PY-SEC-002" in sources
    assert "STRUCT-TYPING" in sources
    assert "STRUCT-DOCS" in sources


def test_annotated_documented_code_avoids_structural_penalties():
    assessment = metrics.assess(CLEAN_PYTHON, "python")
    sources = {item["source"] for item in assessment["debt_breakdown"]}
    assert "STRUCT-TYPING" not in sources
    assert "STRUCT-DOCS" not in sources
    assert assessment["debt_score"] == 0


# ── Structure inspection ─────────────────────────────────────────────────────

def test_python_structure_is_measured_not_estimated():
    structure = metrics.inspect_structure(CLEAN_PYTHON, "python")
    assert structure["complexity_estimated"] is False
    assert structure["num_functions"] == 1
    assert structure["has_type_annotations"] is True
    assert structure["has_docstrings"] is True


def test_non_python_structure_is_labelled_as_an_estimate():
    structure = metrics.inspect_structure("class A { void f() { if (x) {} } }", "java")
    assert structure["complexity_estimated"] is True


def test_complexity_grows_with_branching():
    simple = metrics.inspect_structure("def f():\n    return 1\n", "python")
    branchy = metrics.inspect_structure(
        "def f(x):\n    if x:\n        for i in x:\n            while i:\n                pass\n    return 1\n",
        "python",
    )
    assert branchy["cyclomatic_complexity"] > simple["cyclomatic_complexity"]


# ── Comparison ───────────────────────────────────────────────────────────────

def test_identical_revisions_report_no_progress():
    before = metrics.assess(DIRTY_PYTHON, "python")
    comparison = metrics.compare(before, before)
    assert comparison["debt_reduction_percent"] == 0
    assert comparison["counts"]["resolved"] == 0
    assert comparison["counts"]["remaining"] == len(before["findings"])
    assert comparison["residual_debt_score"] == comparison["initial_debt_score"]


def test_a_real_fix_is_reported_as_resolved():
    before = metrics.assess(DIRTY_PYTHON, "python")
    after = metrics.assess("import hashlib\ndigest = hashlib.sha256(b'x').hexdigest()\n", "python")
    comparison = metrics.compare(before, after)

    assert [f["id"] for f in comparison["resolved"]] == ["PY-SEC-002"]
    assert comparison["counts"]["remaining"] == 0
    assert comparison["debt_reduction_percent"] > 0
    assert comparison["residual_debt_score"] < comparison["initial_debt_score"]


def test_a_new_defect_is_reported_as_introduced():
    before = metrics.assess("x = 1\n", "python")
    after = metrics.assess("import subprocess\nsubprocess.run('ls', shell=True)\n", "python")
    comparison = metrics.compare(before, after)
    assert "PY-SEC-005" in {f["id"] for f in comparison["introduced"]}
    assert comparison["counts"]["introduced"] == 1


def test_unparseable_output_marks_the_comparison_unreliable():
    """
    The load-bearing safety property.

    AST rules return nothing for source that will not parse. Without this guard
    a syntax error would look like every finding had been fixed.
    """
    before = metrics.assess("def f(cache={}):\n    return cache\n", "python")
    after = metrics.assess("def f(cache=:\n", "python")
    comparison = metrics.compare(before, after)

    assert comparison["reliable"] is False
    assert comparison["debt_reduction_percent"] == 0
    assert comparison["residual_debt_score"] == comparison["initial_debt_score"]


def test_reduction_is_never_negative():
    before = metrics.assess("x = 1\n", "python")
    after = metrics.assess("import subprocess\nsubprocess.run('ls', shell=True)\n", "python")
    assert metrics.compare(before, after)["debt_reduction_percent"] == 0


def test_counts_are_internally_consistent(example):
    before = metrics.assess(example["original_code"], example["language"])
    after = metrics.assess("", example["language"]) if False else before
    comparison = metrics.compare(before, after)
    counts = comparison["counts"]
    assert counts["detected"] == counts["resolved"] + counts["remaining"]
    assert counts["vulnerabilities_resolved"] <= counts["vulnerabilities_detected"]


# ── Effort estimate ──────────────────────────────────────────────────────────

def test_hours_saved_counts_resolved_findings_only():
    before = metrics.assess(DIRTY_PYTHON, "python")
    unchanged = metrics.compare(before, before)
    assert metrics.engineering_hours_saved(unchanged) == 0


def test_hours_saved_is_positive_after_a_fix():
    before = metrics.assess(DIRTY_PYTHON, "python")
    after = metrics.assess("import hashlib\ndigest = hashlib.sha256(b'x').hexdigest()\n", "python")
    assert metrics.engineering_hours_saved(metrics.compare(before, after)) > 0
