"""
Git patch and pull-request payload generation.
==============================================

Builds the metadata and Markdown body for a PR from the *measured* results of a
run. Nothing here is hardcoded — the previous version always claimed
"100% Passed (4/4 assertions)" regardless of what happened.

This module does not talk to GitHub. It produces the payload and the unified
diff; opening the PR is left to the caller with their own credentials.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

VERDICT_SUMMARY = {
    "clean": "All detected findings were remediated and every check passed.",
    "partial": "The applied changes are sound, but some findings remain open.",
    "rejected": "The candidate output was rejected by verification and not applied.",
}


def _finding_lines(findings: Sequence[Dict[str, Any]]) -> str:
    if not findings:
        return "_None._\n"
    rows = []
    for finding in findings:
        label = finding.get("cwe") or finding["id"]
        lines = ", ".join(str(line) for line in finding.get("lines", [])[:6])
        location = f" (line{'s' if len(finding.get('lines', [])) != 1 else ''} {lines})" if lines else ""
        rows.append(
            f"- **[{label}]** `{finding['severity']}` {finding['title']}{location}  \n"
            f"  {finding['remediation']}"
        )
    return "\n".join(rows) + "\n"


def _checklist(verification: Dict[str, Any]) -> str:
    rows = []
    for case in verification.get("test_cases", []):
        mark = {"PASSED": "x", "FAILED": " ", "SKIPPED": "-"}.get(case["status"], " ")
        suffix = ""
        if case["status"] == "FAILED" and case.get("expected"):
            suffix = " _(known-unresolved finding)_"
        rows.append(f"- [{mark}] `{case['status']}` {case['name']}{suffix}")
    return "\n".join(rows) + "\n" if rows else "_No checks recorded._\n"


def generate_pull_request_payload(
    filename: str,
    diff_unified: str,
    metrics: Dict[str, Any],
    findings: Dict[str, Any],
    verification: Optional[Dict[str, Any]] = None,
    synthesis: Optional[Dict[str, Any]] = None,
    language: str = "python",
) -> Dict[str, Any]:
    """
    Assemble PR metadata and a Markdown body from a completed run.

    ``findings`` is the engine's ``findings`` block (``detected`` / ``resolved`` /
    ``remaining`` / ``introduced``). ``verification`` and ``synthesis`` are the
    corresponding engine blocks; both are optional so the payload can still be
    produced from a partial client-side state.
    """
    verification = verification or {}
    synthesis = synthesis or {}

    resolved = findings.get("resolved", [])
    remaining = findings.get("remaining", [])
    introduced = findings.get("introduced", [])

    verdict = verification.get("verdict", "unknown")
    engine_used = synthesis.get("engine", "unknown")

    initial = metrics.get("initial_debt_score", 0)
    residual = metrics.get("residual_debt_score", 0)
    reduction = metrics.get("debt_reduction_percent", 0)
    checks_passed = metrics.get("checks_passed", verification.get("passed_count", 0))
    checks_total = metrics.get("checks_total", verification.get("total_count", 0))

    slug = filename.replace(".", "-").replace("/", "-").replace("_", "-").lower()
    title = (
        f"refactor({slug}): remediate {len(resolved)} finding"
        f"{'s' if len(resolved) != 1 else ''}"
    )
    if len(title) > 70:
        title = title[:67] + "..."

    warnings: List[str] = []
    if introduced:
        warnings.append(
            f"> **{len(introduced)} new finding(s) were introduced by this change.** "
            "Review before merging."
        )
    if not metrics.get("comparison_reliable", True):
        warnings.append(
            "> **The before/after comparison is not reliable** — the modernized source "
            "could not be parsed, so resolution counts are unverified."
        )
    if verdict == "rejected":
        warnings.append(
            "> **Verification rejected this candidate.** The diff below may be empty "
            "because the original source was kept unchanged."
        )
    if not verification.get("harness_executed", True):
        warnings.append(
            "> The generated regression harness did not execute, so the assertions "
            "below were not run."
        )

    body = f"""## Automated modernization

{VERDICT_SUMMARY.get(verdict, 'Verification did not produce a verdict.')}

{chr(10).join(warnings) + chr(10) if warnings else ''}
### Measurements

| Metric | Value |
| :-- | :-- |
| Language | `{language}` |
| Synthesis engine | `{engine_used}` |
| Synthesis attempts | {synthesis.get('attempt_count', 'n/a')} |
| Verification verdict | `{verdict}` |
| Technical debt score | {initial} → {residual} (**{reduction}%** reduction) |
| Debt points | {metrics.get('initial_debt_points', 'n/a')} → {metrics.get('residual_debt_points', 'n/a')} |
| Rules evaluated | {metrics.get('rules_evaluated', 'n/a')} |
| Findings detected | {metrics.get('findings_detected', len(resolved) + len(remaining))} |
| Findings resolved | {len(resolved)} |
| Findings remaining | {len(remaining)} |
| Findings introduced | {len(introduced)} |
| Verification checks passed | {checks_passed}/{checks_total} |
| Diff | +{metrics.get('diff_lines_added', 0)} / -{metrics.get('diff_lines_removed', 0)} lines |

The debt score is `100 * points / (points + 60)` over the rule weights that
actually matched. Residual debt comes from re-scanning the modernized source with
the same rules, so a change that fixes nothing reports a 0% reduction.

### Resolved

{_finding_lines(resolved)}
### Still open

{_finding_lines(remaining)}"""

    if introduced:
        body += f"""
### Introduced by this change

{_finding_lines(introduced)}"""

    body += f"""
### Verification checks

{_checklist(verification)}
Estimated remediation effort avoided: **~{metrics.get('estimated_engineering_hours_saved', 0)} hours**
(severity-weighted estimate for resolved findings only, not a measurement).

---
Generated by BobPulse.
"""

    return {
        "title": title,
        "branch_from": f"bobpulse/modernize-{slug}",
        "branch_to": "main",
        "body_markdown": body,
        "diff_unified": diff_unified,
        "labels": _labels(resolved, remaining, introduced, verdict),
        "ready_to_merge": verdict == "clean" and not introduced,
    }


def _labels(
    resolved: Sequence[Dict[str, Any]],
    remaining: Sequence[Dict[str, Any]],
    introduced: Sequence[Dict[str, Any]],
    verdict: str,
) -> List[str]:
    labels = ["bobpulse", "automated"]
    if any(f["category"] == "vulnerability" for f in resolved):
        labels.append("security")
    if remaining:
        labels.append("partial-remediation")
    if introduced:
        labels.append("needs-review")
    if verdict == "clean" and not introduced:
        labels.append("verified")
    return labels
