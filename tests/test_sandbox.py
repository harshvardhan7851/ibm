"""
Verification sandbox tests.

The central claim being tested: the generated harness is a real gate. It must
fail when a finding survives, and the verifier must refuse to certify output it
could not parse.
"""

from __future__ import annotations

import pytest

from backend import metrics, rules, sandbox

WEAK_HASH = "import hashlib\ndigest = hashlib.md5(b'x').hexdigest()\n"
FIXED_HASH = "import hashlib\ndigest = hashlib.sha256(b'x').hexdigest()\n"


def verification_for(original: str, candidate: str, language: str = "python"):
    before = metrics.assess(original, language)
    after = metrics.assess(candidate, language)
    comparison = metrics.compare(before, after)
    return sandbox.verify(candidate, language, before["findings"], comparison), comparison


# ── Syntax checking ──────────────────────────────────────────────────────────

def test_valid_python_passes_the_compile_check():
    result = sandbox.check_syntax("x = 1\n", "python")
    assert result["ok"] is True
    assert result["heuristic"] is False
    assert result["check"] == "cpython-compile"


def test_broken_python_fails_with_a_line_number():
    result = sandbox.check_syntax("def f(:\n", "python")
    assert result["ok"] is False
    assert "line 1" in result["detail"]


def test_empty_output_is_a_failure():
    assert sandbox.check_syntax("   \n", "python")["ok"] is False


def test_non_python_syntax_check_is_labelled_a_heuristic():
    result = sandbox.check_syntax("class A { void f() {} }\n", "java")
    assert result["ok"] is True
    assert result["heuristic"] is True


def test_unbalanced_brackets_are_detected():
    result = sandbox.check_syntax("class A { void f() { \n", "java")
    assert result["ok"] is False
    assert "unclosed" in result["detail"] or "unbalanced" in result["detail"]


def test_brackets_inside_strings_do_not_count():
    assert sandbox.check_syntax('const a = "{{{";\n', "javascript")["ok"] is True


# ── Harness generation ───────────────────────────────────────────────────────

def test_harness_has_an_assertion_per_finding():
    findings = rules.scan(WEAK_HASH, "python")
    harness = sandbox.generate_pytest_harness(
        "python", findings, "test_h.py", "modernized_sample.py"
    )
    assert "def test_modernized_source_parses" in harness
    for finding in findings:
        assert sandbox._rule_slug(finding["id"]) in harness
    assert harness.count("def test_") == len(findings) + 1


def test_harness_is_valid_python():
    findings = rules.scan(WEAK_HASH, "python")
    harness = sandbox.generate_pytest_harness(
        "python", findings, "test_h.py", "modernized_sample.py"
    )
    compile(harness, "<harness>", "exec")


def test_harness_for_clean_source_still_guards_against_new_findings():
    harness = sandbox.generate_pytest_harness("python", [], "test_h.py", "modernized_sample.py")
    assert "test_no_findings_to_regress" in harness
    compile(harness, "<harness>", "exec")


# ── Harness execution ────────────────────────────────────────────────────────

@pytest.mark.slow
def test_harness_passes_when_the_finding_is_fixed():
    findings = rules.scan(WEAK_HASH, "python")
    result = sandbox.run_pytest_harness(FIXED_HASH, "python", findings)
    assert result["executed"] is True
    assert result["failed"] == 0
    assert result["passed"] >= len(findings)


@pytest.mark.slow
def test_harness_fails_when_the_finding_survives():
    """A harness that cannot fail would prove nothing."""
    findings = rules.scan(WEAK_HASH, "python")
    result = sandbox.run_pytest_harness(WEAK_HASH, "python", findings)
    assert result["executed"] is True
    assert result["failed"] >= 1
    failed_ids = [c["id"] for c in result["cases"] if c["status"] == "FAILED"]
    assert any("py_sec_002" in name for name in failed_ids)


# ── Verdicts ─────────────────────────────────────────────────────────────────

@pytest.mark.slow
def test_a_complete_fix_verifies_clean():
    verification, comparison = verification_for(WEAK_HASH, FIXED_HASH)
    assert verification["verdict"] == "clean"
    assert verification["passed"] is True
    assert verification["blocking_failures"] == []
    assert comparison["counts"]["resolved"] == 1


@pytest.mark.slow
def test_an_unfixed_finding_verifies_partial_not_rejected():
    """
    'Did not fix everything' and 'produced broken output' are different things.

    The assertion for a surviving finding fails, but that is expected and must
    not be reported as a blocking failure.
    """
    verification, _ = verification_for(WEAK_HASH, WEAK_HASH)
    assert verification["verdict"] == "partial"
    assert verification["passed"] is True
    assert verification["blocking_failures"] == []
    expected_failures = [c for c in verification["test_cases"] if c.get("expected")]
    assert expected_failures, "surviving finding was not marked as expected"


def test_broken_output_is_rejected():
    verification, comparison = verification_for(WEAK_HASH, "def broken(:\n")
    assert verification["verdict"] == "rejected"
    assert verification["passed"] is False
    assert comparison["reliable"] is False
    assert comparison["debt_reduction_percent"] == 0
    assert any("SyntaxError" in problem for problem in verification["blocking_failures"])


def test_broken_output_does_not_claim_resolutions():
    """The failure mode this guards: no parse tree means no AST rule matches."""
    _, comparison = verification_for("def f(cache={}):\n    return cache\n", "def f(cache=:\n")
    assert comparison["counts"]["resolved"] == 0 or comparison["reliable"] is False


@pytest.mark.slow
def test_introducing_a_critical_finding_is_blocking():
    verification, _ = verification_for(
        "x = 1\n", "import subprocess\nsubprocess.run('ls', shell=True)\n"
    )
    assert verification["verdict"] == "rejected"
    assert any("Introduced" in problem for problem in verification["blocking_failures"])


# ── Execution gate ───────────────────────────────────────────────────────────

def test_code_execution_is_off_by_default():
    assert sandbox.allow_exec() is False
    assert sandbox.import_smoke_test("x = 1\n", "python") is None


def test_code_execution_can_be_enabled_explicitly(monkeypatch):
    monkeypatch.setenv("BOBPULSE_ALLOW_EXEC", "1")
    assert sandbox.allow_exec() is True
    result = sandbox.import_smoke_test("VALUE = 1\n", "python")
    assert result is not None
    assert result["status"] == "PASSED"


def test_import_smoke_test_catches_import_time_errors(monkeypatch):
    monkeypatch.setenv("BOBPULSE_ALLOW_EXEC", "1")
    result = sandbox.import_smoke_test("import a_module_that_does_not_exist_xyz\n", "python")
    assert result["status"] == "FAILED"


# ── Native test skeletons ────────────────────────────────────────────────────

@pytest.mark.parametrize("language", ["java", "javascript", "typescript", "go", "php"])
def test_native_skeletons_are_generated_and_labelled_unexecuted(language):
    findings = rules.scan("x", language) or [
        {
            "id": "X-1",
            "cwe": "CWE-1",
            "severity": "HIGH",
            "category": "vulnerability",
            "title": "Example finding",
            "description": "d",
            "remediation": "r",
            "lines": [1],
            "debt": 10,
            "occurrences": 1,
            "snippets": [],
        }
    ]
    skeleton = sandbox.generate_native_tests(language, findings)
    assert skeleton
    assert "NOT executed" in skeleton


def test_python_has_no_native_skeleton():
    """Python is covered by the executed harness, so a second file would be noise."""
    assert sandbox.generate_native_tests("python", []) is None


# ── Failure report ───────────────────────────────────────────────────────────

def test_failure_report_lists_blocking_problems_and_survivors():
    verification, comparison = verification_for(WEAK_HASH, "def broken(:\n")
    report = sandbox.failure_report(verification, comparison)
    assert "SyntaxError" in report
    assert report.startswith("-")
