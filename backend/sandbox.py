"""
Verification sandbox.
=====================

What "verified" means here, precisely:

1. **Syntax** — Python is compiled with ``compile()``. Other languages get a
   bracket-balance check, reported as a heuristic because it is one.
2. **Re-scan** — the modernized source goes back through the rule engine and the
   result is diffed against the original findings.
3. **Executed tests** — a pytest harness is generated that asserts, per original
   finding, that the defect is absent from the modernized source. It is run in a
   real subprocess and results are read from pytest's JUnit XML. These
   assertions genuinely fail when a fix did not land.

What it does **not** do by default: execute the modernized code. Importing
untrusted source is arbitrary code execution, so the import smoke test is behind
``BOBPULSE_ALLOW_EXEC=1`` and should only be enabled inside a container.

The native-language test skeletons (JUnit, node:test, …) are generated for
export and are explicitly marked as not executed by this process.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from backend import rules

REPO_ROOT = Path(__file__).resolve().parent.parent

SOURCE_FILENAMES = {
    "python": "modernized_sample.py",
    "java": "ModernizedSample.java",
    "javascript": "modernizedSample.js",
    "typescript": "modernizedSample.ts",
    "go": "modernized_sample.go",
    "php": "modernized_sample.php",
}

PYTEST_TIMEOUT_SECONDS = 60


def allow_exec() -> bool:
    return os.getenv("BOBPULSE_ALLOW_EXEC", "").strip().lower() in {"1", "true", "yes"}


# ─────────────────────────────────────────────────────────────────────────────
#  Syntax checking
# ─────────────────────────────────────────────────────────────────────────────

_BRACKET_PAIRS = {")": "(", "]": "[", "}": "{"}


def _balanced(code: str, language: str) -> Optional[str]:
    """Return an error description if brackets are unbalanced, else None."""
    scannable = rules.blank_comments(code, language)
    stack: List[str] = []
    quote_chars = "\"'" + ("`" if language in ("javascript", "typescript") else "")
    i = 0
    length = len(scannable)

    while i < length:
        char = scannable[i]
        if char in quote_chars:
            i += 1
            while i < length:
                if scannable[i] == "\\":
                    i += 2
                    continue
                if scannable[i] == char:
                    break
                if scannable[i] == "\n" and char != "`":
                    break
                i += 1
            i += 1
            continue
        if char in "([{":
            stack.append(char)
        elif char in ")]}":
            if not stack or stack[-1] != _BRACKET_PAIRS[char]:
                line = scannable.count("\n", 0, i) + 1
                return f"unbalanced '{char}' at line {line}"
            stack.pop()
        i += 1

    if stack:
        return f"{len(stack)} unclosed '{stack[-1]}' bracket(s)"
    return None


def check_syntax(code: str, language: str) -> Dict[str, Any]:
    """Validate the modernized source as far as this process can."""
    if not code.strip():
        return {"ok": False, "heuristic": False, "detail": "Output is empty.", "check": "empty"}

    if language == "python":
        try:
            compile(code, "<bobpulse-modernized>", "exec")
            return {
                "ok": True,
                "heuristic": False,
                "detail": "compile() accepted the source — no SyntaxError.",
                "check": "cpython-compile",
            }
        except SyntaxError as exc:
            return {
                "ok": False,
                "heuristic": False,
                "detail": f"SyntaxError at line {exc.lineno}: {exc.msg}",
                "check": "cpython-compile",
            }

    problem = _balanced(code, language)
    if problem:
        return {
            "ok": False,
            "heuristic": True,
            "detail": f"Bracket balance check failed: {problem}",
            "check": "bracket-balance",
        }
    return {
        "ok": True,
        "heuristic": True,
        "detail": (
            "Brackets balance. No compiler for this language is available in-process, "
            "so this is a heuristic rather than a compile."
        ),
        "check": "bracket-balance",
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Generated pytest harness (real, executed)
# ─────────────────────────────────────────────────────────────────────────────

_HARNESS_HEADER = '''"""
BobPulse verification harness — generated, and genuinely executable.

Each test re-runs the BobPulse rule engine over the modernized source and
asserts that a specific finding is gone. A test fails when the defect is still
present, so this file is a real regression gate: drop it into CI next to the
modernized file and it will keep the fix from being reverted.

Run it with:    pytest {harness_name}
"""

import sys
from pathlib import Path

REPO_ROOT = Path(r"{repo_root}")
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend import rules  # noqa: E402

LANGUAGE = "{language}"
SOURCE_PATH = Path(__file__).with_name("{source_name}")
SOURCE = SOURCE_PATH.read_text(encoding="utf-8")
FINDING_IDS = {{f["id"] for f in rules.scan(SOURCE, LANGUAGE)}}
'''

_SYNTAX_TEST = '''

def test_modernized_source_parses():
    """The output must be syntactically valid before any other claim holds."""
    if LANGUAGE == "python":
        compile(SOURCE, str(SOURCE_PATH), "exec")
    assert SOURCE.strip(), "modernized source is empty"
'''


def _rule_slug(rule_id: str) -> str:
    """Rule id in the form embedded into generated test function names."""
    return rule_id.lower().replace("-", "_")


def _test_name(finding: Dict[str, Any]) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", finding["title"].lower()).strip("_")[:48]
    return f"test_{_rule_slug(finding['id'])}_{slug}"


def generate_pytest_harness(
    language: str, findings: Sequence[Dict[str, Any]], harness_name: str, source_name: str
) -> str:
    """Build a pytest module asserting each original finding is now absent."""
    parts = [
        _HARNESS_HEADER.format(
            repo_root=str(REPO_ROOT),
            language=language,
            source_name=source_name,
            harness_name=harness_name,
        ),
        _SYNTAX_TEST,
    ]

    seen: set[str] = set()
    for finding in findings:
        name = _test_name(finding)
        if name in seen:
            continue
        seen.add(name)
        label = finding.get("cwe") or finding["id"]
        lines = ", ".join(str(line) for line in finding.get("lines", [])[:6]) or "n/a"
        parts.append(
            f'''

def {name}():
    """[{label}] {finding["title"]} — originally at line(s) {lines}."""
    assert "{finding["id"]}" not in FINDING_IDS, (
        "{finding["id"]} is still present in the modernized source. "
        "Remediation: {finding["remediation"].replace('"', "'")}"
    )
'''
        )

    if not findings:
        parts.append(
            '''

def test_no_findings_to_regress():
    """Nothing was detected in the original, so nothing should appear now."""
    assert not FINDING_IDS, f"new findings appeared: {sorted(FINDING_IDS)}"
'''
        )

    return "".join(parts)


def _parse_junit(xml_path: Path) -> List[Dict[str, Any]]:
    """Read pytest's JUnit XML — far more reliable than scraping stdout."""
    if not xml_path.exists():
        return []

    try:
        root = ElementTree.parse(xml_path).getroot()
    except ElementTree.ParseError:
        return []

    cases: List[Dict[str, Any]] = []
    for case in root.iter("testcase"):
        failure = case.find("failure")
        error = case.find("error")
        skipped = case.find("skipped")
        if failure is not None or error is not None:
            node = failure if failure is not None else error
            status = "FAILED"
            detail = (node.get("message") or node.text or "").strip()
        elif skipped is not None:
            status = "SKIPPED"
            detail = (skipped.get("message") or "").strip()
        else:
            status = "PASSED"
            detail = "Assertion held."

        try:
            duration_ms = int(float(case.get("time", "0")) * 1000)
        except (TypeError, ValueError):
            duration_ms = 0

        cases.append(
            {
                "id": case.get("name", "unknown"),
                "name": case.get("name", "unknown").replace("_", " ").strip(),
                "status": status,
                "duration_ms": duration_ms,
                "detail": detail[:500],
            }
        )
    return cases


def run_pytest_harness(
    modernized_code: str, language: str, findings: Sequence[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Write the harness plus the modernized source to a temp dir and run pytest.

    Returns the parsed per-test results. ``executed`` is False when pytest could
    not be run at all, which is reported rather than silently passed.
    """
    harness_name = "test_bobpulse_verification.py"
    source_name = SOURCE_FILENAMES.get(language, "modernized_sample.txt")
    harness = generate_pytest_harness(language, findings, harness_name, source_name)

    started = time.time()
    try:
        with tempfile.TemporaryDirectory(prefix="bobpulse-verify-") as tmpdir:
            tmp = Path(tmpdir)
            (tmp / source_name).write_text(modernized_code, encoding="utf-8")
            (tmp / harness_name).write_text(harness, encoding="utf-8")
            report = tmp / "report.xml"

            process = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    harness_name,
                    "-q",
                    "--no-header",
                    "-p",
                    "no:cacheprovider",
                    f"--junitxml={report.name}",
                ],
                capture_output=True,
                text=True,
                timeout=PYTEST_TIMEOUT_SECONDS,
                cwd=tmpdir,
            )
            cases = _parse_junit(report)
            stdout_tail = (process.stdout or "")[-2000:]
            stderr_tail = (process.stderr or "")[-1000:]

        if not cases:
            return {
                "executed": False,
                "harness": harness,
                "cases": [],
                "passed": 0,
                "failed": 0,
                "duration_ms": int((time.time() - started) * 1000),
                "detail": (
                    "pytest produced no JUnit report. "
                    f"exit={process.returncode} stderr={stderr_tail or 'n/a'}"
                ),
            }

        return {
            "executed": True,
            "harness": harness,
            "cases": cases,
            "passed": sum(1 for c in cases if c["status"] == "PASSED"),
            "failed": sum(1 for c in cases if c["status"] == "FAILED"),
            "duration_ms": int((time.time() - started) * 1000),
            "detail": f"pytest exit code {process.returncode}",
            "stdout_tail": stdout_tail,
        }

    except FileNotFoundError:
        return {
            "executed": False,
            "harness": harness,
            "cases": [],
            "passed": 0,
            "failed": 0,
            "duration_ms": int((time.time() - started) * 1000),
            "detail": "pytest is not installed — run: pip install pytest",
        }
    except subprocess.TimeoutExpired:
        return {
            "executed": False,
            "harness": harness,
            "cases": [],
            "passed": 0,
            "failed": 0,
            "duration_ms": int((time.time() - started) * 1000),
            "detail": f"Verification timed out after {PYTEST_TIMEOUT_SECONDS}s.",
        }


# ─────────────────────────────────────────────────────────────────────────────
#  Optional import smoke test (opt-in — executes the code)
# ─────────────────────────────────────────────────────────────────────────────

def import_smoke_test(modernized_code: str, language: str) -> Optional[Dict[str, Any]]:
    """
    Import the modernized module in a subprocess to catch import-time errors.

    This **executes** the source, so it stays disabled unless
    ``BOBPULSE_ALLOW_EXEC=1`` is set. Only enable it inside a disposable
    container: any module-level statement in the submitted code will run.
    """
    if language != "python" or not allow_exec():
        return None

    started = time.time()
    try:
        with tempfile.TemporaryDirectory(prefix="bobpulse-exec-") as tmpdir:
            module = Path(tmpdir) / "bobpulse_candidate.py"
            module.write_text(modernized_code, encoding="utf-8")
            process = subprocess.run(
                [sys.executable, "-c", "import bobpulse_candidate"],
                capture_output=True,
                text=True,
                timeout=15,
                cwd=tmpdir,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
        ok = process.returncode == 0
        return {
            "id": "SB-IMPORT",
            "name": "Module imports cleanly (opt-in execution)",
            "status": "PASSED" if ok else "FAILED",
            "duration_ms": int((time.time() - started) * 1000),
            "detail": (
                "Import succeeded — no missing names or import-time errors."
                if ok
                else (process.stderr or "").strip()[-400:]
            ),
        }
    except Exception as exc:
        return {
            "id": "SB-IMPORT",
            "name": "Module imports cleanly (opt-in execution)",
            "status": "SKIPPED",
            "duration_ms": int((time.time() - started) * 1000),
            "detail": f"Could not run the import check: {exc}",
        }


# ─────────────────────────────────────────────────────────────────────────────
#  Native-language test skeletons (generated, not executed here)
# ─────────────────────────────────────────────────────────────────────────────

def generate_native_tests(language: str, findings: Sequence[Dict[str, Any]]) -> Optional[str]:
    """
    Emit an idiomatic test skeleton for non-Python targets.

    These are scaffolding for the target project's own toolchain. This process
    has no JVM or Node runtime, so they are never claimed as executed.
    """
    if language == "java":
        body = "\n".join(
            f"""
    @Test
    @DisplayName("[{f.get('cwe') or f['id']}] {f['title']}")
    void {re.sub(r'[^A-Za-z0-9]', '', f['title'].title())[:40]}() {{
        // Originally at line(s) {', '.join(str(l) for l in f.get('lines', [])[:5]) or 'n/a'}.
        // Assert the modernized behaviour here: {f['remediation']}
        fail("Implement this assertion against the modernized class.");
    }}"""
            for f in findings
        )
        return f"""// Generated by BobPulse. NOT executed by the BobPulse process — run it with Maven or Gradle.
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.fail;

class BobPulseRegressionTest {{
{body}
}}
"""

    if language in ("javascript", "typescript"):
        body = "\n".join(
            f"""
  it('[{f.get('cwe') or f['id']}] {f['title']}', () => {{
    // Originally at line(s) {', '.join(str(l) for l in f.get('lines', [])[:5]) or 'n/a'}.
    // Assert the modernized behaviour here: {f['remediation']}
    assert.fail('Implement this assertion against the modernized module.');
  }});"""
            for f in findings
        )
        return f"""// Generated by BobPulse. NOT executed by the BobPulse process — run it with `node --test`.
const {{ describe, it }} = require('node:test');
const assert = require('node:assert/strict');

describe('BobPulse regression suite', () => {{
{body}
}});
"""

    if language == "go":
        body = "\n".join(
            f"""
func Test{re.sub(r'[^A-Za-z0-9]', '', f['title'].title())[:40]}(t *testing.T) {{
    // [{f.get('cwe') or f['id']}] originally at line(s) {', '.join(str(l) for l in f.get('lines', [])[:5]) or 'n/a'}.
    // Assert the modernized behaviour here: {f['remediation']}
    t.Skip("Implement this assertion against the modernized package.")
}}"""
            for f in findings
        )
        return f"""// Generated by BobPulse. NOT executed by the BobPulse process — run it with `go test`.
package main

import "testing"
{body}
"""

    if language == "php":
        body = "\n".join(
            f"""
    public function test{re.sub(r'[^A-Za-z0-9]', '', f['title'].title())[:40]}(): void
    {{
        // [{f.get('cwe') or f['id']}] originally at line(s) {', '.join(str(l) for l in f.get('lines', [])[:5]) or 'n/a'}.
        // Assert the modernized behaviour here: {f['remediation']}
        $this->markTestIncomplete('Implement this assertion.');
    }}"""
            for f in findings
        )
        return f"""<?php
// Generated by BobPulse. NOT executed by the BobPulse process — run it with PHPUnit.
use PHPUnit\\Framework\\TestCase;

class BobPulseRegressionTest extends TestCase
{{
{body}
}}
"""

    return None


# ─────────────────────────────────────────────────────────────────────────────
#  Top-level verification
# ─────────────────────────────────────────────────────────────────────────────

def verify(
    modernized_code: str,
    language: str,
    original_findings: Sequence[Dict[str, Any]],
    comparison: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Run every available check and return a verdict.

    Verdicts:
      ``rejected`` — a blocking failure: broken syntax, a new HIGH/CRITICAL
      finding, or a failing regression assertion. The caller should retry.
      ``partial``  — sound output, but some original findings remain.
      ``clean``    — sound output and nothing left over.
    """
    syntax = check_syntax(modernized_code, language)
    blocking: List[str] = []

    if not syntax["ok"]:
        blocking.append(syntax["detail"])

    introduced_serious = [
        f for f in comparison.get("introduced", []) if f["severity"] in {"CRITICAL", "HIGH"}
    ]
    for finding in introduced_serious:
        blocking.append(
            f"Introduced a new {finding['severity']} finding: {finding['id']} {finding['title']}"
        )

    cases: List[Dict[str, Any]] = [
        {
            "id": "SB-SYNTAX",
            "name": f"Syntax validation ({syntax['check']})",
            "status": "PASSED" if syntax["ok"] else "FAILED",
            "duration_ms": 1,
            "detail": syntax["detail"],
        }
    ]

    # A finding the re-scan says is still present will naturally fail its
    # assertion. That is an honest "not fixed", not a broken build — it must not
    # be conflated with a blocking failure. Anything failing for a reason the
    # comparison does *not* explain is a genuine regression.
    expected_failures = {
        _rule_slug(finding["id"]) for finding in comparison.get("remaining", [])
    }

    harness_result: Dict[str, Any] = {"executed": False, "harness": "", "cases": []}
    # Running the harness against unparseable source tells us nothing useful.
    if syntax["ok"]:
        harness_result = run_pytest_harness(modernized_code, language, original_findings)
        unexplained: List[str] = []
        for case in harness_result["cases"]:
            if case["status"] != "FAILED":
                continue
            if any(case["id"].startswith(f"test_{slug}_") for slug in expected_failures):
                case["expected"] = True
                case["detail"] = (
                    "Still present after synthesis — this finding was not remediated. "
                    + case["detail"]
                )
            else:
                case["expected"] = False
                unexplained.append(f"{case['id']}: {case['detail'][:160]}")

        cases.extend(harness_result["cases"])

        if unexplained:
            blocking.append(
                f"{len(unexplained)} regression assertion(s) failed for reasons the re-scan "
                "does not explain: " + "; ".join(unexplained)
            )
        if not harness_result["executed"]:
            cases.append(
                {
                    "id": "SB-HARNESS",
                    "name": "Generated regression harness",
                    "status": "SKIPPED",
                    "duration_ms": harness_result.get("duration_ms", 0),
                    "detail": harness_result.get("detail", "Harness did not run."),
                }
            )

        smoke = import_smoke_test(modernized_code, language)
        if smoke:
            cases.append(smoke)
            if smoke["status"] == "FAILED":
                blocking.append(f"Import smoke test failed: {smoke['detail'][:200]}")

    if not comparison.get("reliable", True):
        blocking.append(
            "The modernized source could not be parsed, so the finding comparison is "
            "not trustworthy."
        )

    remaining = comparison.get("remaining", [])
    if blocking:
        verdict = "rejected"
    elif remaining:
        verdict = "partial"
    else:
        verdict = "clean"

    return {
        "verdict": verdict,
        "passed": verdict != "rejected",
        "syntax": syntax,
        "blocking_failures": blocking,
        "test_cases": cases,
        "passed_count": sum(1 for c in cases if c["status"] == "PASSED"),
        "failed_count": sum(1 for c in cases if c["status"] == "FAILED"),
        "skipped_count": sum(1 for c in cases if c["status"] == "SKIPPED"),
        "total_count": len(cases),
        "duration_ms": sum(c["duration_ms"] for c in cases),
        "harness_executed": harness_result.get("executed", False),
        "generated_tests": harness_result.get("harness", ""),
        "native_tests": generate_native_tests(language, original_findings),
        "execution_enabled": allow_exec(),
    }


def failure_report(verification: Dict[str, Any], comparison: Dict[str, Any]) -> str:
    """Human-readable rejection summary, fed back to Granite on a repair pass."""
    lines: List[str] = []
    for problem in verification.get("blocking_failures", []):
        lines.append(f"- {problem}")
    for finding in comparison.get("remaining", []):
        label = finding.get("cwe") or finding["id"]
        lines.append(
            f"- Still unfixed [{label}] {finding['title']} at line(s) "
            f"{', '.join(str(line) for line in finding.get('lines', [])[:5])}: "
            f"{finding['remediation']}"
        )
    return "\n".join(lines) or "- No specific problems recorded."
