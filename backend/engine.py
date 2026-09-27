"""
BobPulse pipeline orchestrator.
===============================

Five stages, one implementation. ``analyze`` takes an optional ``progress``
callback so the streaming endpoint can narrate the same run instead of
reimplementing it.

    1. Ingestion      — parse, measure structure
    2. Scan           — run the rule registry, score debt
    3. Plan           — order the work by severity
    4. Synthesis      — Granite if configured, otherwise the mechanical
                        transformer; retried against the verifier
    5. Verification   — compile, re-scan, execute the generated regression tests

The synthesis/verification pair is a genuine loop. A rejected attempt produces a
failure report which is fed back to the model on the next attempt, and if every
strategy is exhausted the original source is returned unchanged with
``modernization_applied: False`` rather than shipping something broken.
"""

from __future__ import annotations

import difflib
import hashlib
import os
import time
from typing import Any, Callable, Dict, List, Optional, Sequence

from backend import granite, metrics, rules, sandbox, transforms

ProgressCallback = Optional[Callable[[Dict[str, Any]], None]]

STAGES: Dict[int, str] = {
    1: "Ingestion & structural analysis",
    2: "Rule scan & debt scoring",
    3: "Remediation planning",
    4: "Code synthesis",
    5: "Verification",
}

#: Ceiling on synthesis attempts, override with BOBPULSE_MAX_ATTEMPTS.
DEFAULT_MAX_ATTEMPTS = 3

_VERDICT_RANK = {"clean": 0, "partial": 1, "rejected": 2}

#: Process-local cache of completed runs, keyed by content hash.
_RESULT_CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_LIMIT = 64


def cache_size() -> int:
    return len(_RESULT_CACHE)


def clear_cache() -> None:
    _RESULT_CACHE.clear()


def max_attempts() -> int:
    raw = os.getenv("BOBPULSE_MAX_ATTEMPTS", "").strip()
    if raw.isdigit() and 1 <= int(raw) <= 6:
        return int(raw)
    return DEFAULT_MAX_ATTEMPTS


# ─────────────────────────────────────────────────────────────────────────────
#  Diffing
# ─────────────────────────────────────────────────────────────────────────────

def compute_unified_diff(original: str, modernized: str, filename: str) -> str:
    return "\n".join(
        difflib.unified_diff(
            original.splitlines(),
            modernized.splitlines(),
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            lineterm="",
        )
    )


def compute_structured_diff(original: str, modernized: str) -> List[Dict[str, Any]]:
    """Row-aligned diff for the split-pane viewer."""
    left_lines = original.splitlines()
    right_lines = modernized.splitlines()
    matcher = difflib.SequenceMatcher(None, left_lines, right_lines, autojunk=False)

    rows: List[Dict[str, Any]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for offset in range(i2 - i1):
                rows.append(
                    {
                        "type": "equal",
                        "left_line": i1 + offset + 1,
                        "left_content": left_lines[i1 + offset],
                        "right_line": j1 + offset + 1,
                        "right_content": right_lines[j1 + offset],
                    }
                )
        elif tag == "replace":
            for offset in range(max(i2 - i1, j2 - j1)):
                left_index = i1 + offset
                right_index = j1 + offset
                rows.append(
                    {
                        "type": "replace",
                        "left_line": left_index + 1 if left_index < i2 else None,
                        "left_content": left_lines[left_index] if left_index < i2 else "",
                        "right_line": right_index + 1 if right_index < j2 else None,
                        "right_content": right_lines[right_index] if right_index < j2 else "",
                    }
                )
        elif tag == "delete":
            for offset in range(i2 - i1):
                rows.append(
                    {
                        "type": "delete",
                        "left_line": i1 + offset + 1,
                        "left_content": left_lines[i1 + offset],
                        "right_line": None,
                        "right_content": "",
                    }
                )
        elif tag == "insert":
            for offset in range(j2 - j1):
                rows.append(
                    {
                        "type": "insert",
                        "left_line": None,
                        "left_content": "",
                        "right_line": j1 + offset + 1,
                        "right_content": right_lines[j1 + offset],
                    }
                )
    return rows


def diff_stats(diff_rows: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    return {
        "lines_added": sum(
            1 for r in diff_rows if r["type"] in ("insert", "replace") and r["right_content"]
        ),
        "lines_removed": sum(
            1 for r in diff_rows if r["type"] in ("delete", "replace") and r["left_content"]
        ),
        "lines_unchanged": sum(1 for r in diff_rows if r["type"] == "equal"),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Planning
# ─────────────────────────────────────────────────────────────────────────────

def build_plan(
    findings: Sequence[Dict[str, Any]], structure: Dict[str, Any], language: str
) -> List[Dict[str, Any]]:
    """Order the remediation work. Severity first, then position in the file."""
    plan: List[Dict[str, Any]] = []

    for index, finding in enumerate(findings, start=1):
        plan.append(
            {
                "priority": index,
                "type": finding["category"],
                "rule_id": finding["id"],
                "cwe": finding.get("cwe"),
                "severity": finding["severity"],
                "lines": finding.get("lines", []),
                "action": finding["title"],
                "detail": finding["remediation"],
                "impact": f"{finding['severity']} — {finding['debt']} debt points",
                "status": "planned",
            }
        )

    if language == "python" and structure.get("parseable"):
        if not structure.get("has_type_annotations"):
            plan.append(
                {
                    "priority": len(plan) + 1,
                    "type": "modernization",
                    "rule_id": "STRUCT-TYPING",
                    "cwe": None,
                    "severity": "LOW",
                    "lines": [],
                    "action": "Add type annotations (PEP 484)",
                    "detail": (
                        "Annotate public signatures so mypy/pyright can check call sites. "
                        "Not applied mechanically — annotations need domain knowledge."
                    ),
                    "impact": "LOW — 5 debt points",
                    "status": "planned",
                }
            )
        if not structure.get("has_docstrings"):
            plan.append(
                {
                    "priority": len(plan) + 1,
                    "type": "documentation",
                    "rule_id": "STRUCT-DOCS",
                    "cwe": None,
                    "severity": "LOW",
                    "lines": [],
                    "action": "Document public APIs",
                    "detail": "Add module, class and function docstrings.",
                    "impact": "LOW — 3 debt points",
                    "status": "planned",
                }
            )

    return plan


def annotate_plan(plan: List[Dict[str, Any]], comparison: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Mark each step with what the run actually achieved."""
    resolved = {f["id"] for f in comparison.get("resolved", [])}
    remaining = {f["id"] for f in comparison.get("remaining", [])}

    for step in plan:
        rule_id = step["rule_id"]
        if rule_id in resolved:
            step["status"] = "resolved"
        elif rule_id in remaining:
            step["status"] = "unresolved"
        else:
            step["status"] = "not_attempted"
    return plan


# ─────────────────────────────────────────────────────────────────────────────
#  Synthesis strategies
# ─────────────────────────────────────────────────────────────────────────────

def _strategy_sequence() -> List[str]:
    """
    Which synthesis strategies to try, in order.

    With credentials: model first, then a repair pass informed by the verifier,
    then the mechanical transformer as a deterministic safety net. Without
    credentials there is exactly one strategy.
    """
    if granite.is_configured() and granite.SDK_AVAILABLE:
        return ["granite", "granite-repair", "transform"]
    return ["transform"]


def _better(candidate: Dict[str, Any], incumbent: Optional[Dict[str, Any]]) -> bool:
    """Prefer a sound verdict, then lower residual debt, then more resolved findings."""
    if incumbent is None:
        return True
    verdict_delta = _VERDICT_RANK[candidate["verification"]["verdict"]] - _VERDICT_RANK[
        incumbent["verification"]["verdict"]
    ]
    if verdict_delta != 0:
        return verdict_delta < 0
    residual_delta = (
        candidate["comparison"]["residual_debt_points"]
        - incumbent["comparison"]["residual_debt_points"]
    )
    if residual_delta != 0:
        return residual_delta < 0
    return (
        candidate["comparison"]["counts"]["resolved"]
        > incumbent["comparison"]["counts"]["resolved"]
    )


# ─────────────────────────────────────────────────────────────────────────────
#  Engine
# ─────────────────────────────────────────────────────────────────────────────

class BobPulseEngine:
    """Stateless orchestrator. Safe to share across requests."""

    def analyze(
        self,
        code: str,
        language: str = "python",
        filename: Optional[str] = None,
        progress: ProgressCallback = None,
        use_cache: bool = True,
    ) -> Dict[str, Any]:
        if language not in rules.SUPPORTED_LANGUAGES:
            raise ValueError(
                f"Unsupported language '{language}'. "
                f"Supported: {', '.join(rules.SUPPORTED_LANGUAGES)}"
            )
        if not code.strip():
            raise ValueError("Source code must not be empty.")

        cache_key = self._cache_key(code, language)
        if use_cache and cache_key in _RESULT_CACHE:
            cached = dict(_RESULT_CACHE[cache_key])
            cached["cached"] = True
            if progress:
                for stage in STAGES:
                    progress({"stage": stage, "label": STAGES[stage], "status": "done"})
            return cached

        started = time.time()
        target_filename = filename or f"source.{self._extension(language)}"
        agent_logs: List[Dict[str, Any]] = []

        def emit(stage: int, **extra: Any) -> None:
            if progress:
                progress({"stage": stage, "label": STAGES[stage], "status": "done", **extra})

        def log(stage: int, agent: str, detail: str) -> None:
            agent_logs.append(
                {
                    "stage": f"Stage {stage} — {STAGES[stage]}",
                    "agent": agent,
                    "timestamp": f"{round(time.time() - started, 3)}s",
                    "status": "completed",
                    "detail": detail,
                }
            )

        # ── Stage 1 + 2: assess the input ───────────────────────────────────
        before = metrics.assess(code, language)
        structure = before["structure"]
        findings = before["findings"]

        parse_note = ""
        if language == "python":
            if structure.get("parse_error"):
                parse_note = (
                    f" Source does not parse as Python 3 ({structure['parse_error']})"
                    + (
                        "; analysed after normalising Python 2 syntax."
                        if structure.get("normalised_for_parse")
                        else "; AST rules were skipped."
                    )
                )
            complexity_note = f"cyclomatic complexity {structure['cyclomatic_complexity']}"
        else:
            complexity_note = (
                f"estimated cyclomatic complexity {structure['cyclomatic_complexity']}"
            )

        log(
            1,
            "Structural analyser",
            f"Read {structure['num_lines']} lines of {language}. "
            f"{structure['num_classes']} class(es), {structure['num_functions']} function(s), "
            f"{complexity_note}.{parse_note}",
        )
        emit(1, lines=structure["num_lines"], parseable=structure["parseable"])

        rule_total = len(rules.rules_for(language))
        buckets = rules.split_findings(findings)
        log(
            2,
            "Rule scanner",
            f"Evaluated {rule_total} rules for {language}. "
            f"{len(buckets['vulnerabilities'])} security finding(s), "
            f"{len(buckets['deprecations'])} deprecation/quality finding(s). "
            f"Debt score {before['debt_score']}/100 from {before['debt_points']} points.",
        )
        emit(
            2,
            findings=len(findings),
            debt_score=before["debt_score"],
            rules_evaluated=rule_total,
        )

        # ── Stage 3: plan ───────────────────────────────────────────────────
        plan = build_plan(findings, structure, language)
        log(
            3,
            "Planner",
            f"Ordered {len(plan)} remediation step(s) by severity."
            if plan
            else "No findings — nothing to plan.",
        )
        emit(3, plan_steps=len(plan))

        # ── Stage 4 + 5: synthesise, verify, retry ──────────────────────────
        attempts: List[Dict[str, Any]] = []
        best: Optional[Dict[str, Any]] = None
        previous_code: Optional[str] = None
        failure_text: Optional[str] = None
        granite_calls: List[Dict[str, Any]] = []

        strategies = _strategy_sequence()[: max_attempts()]

        for attempt_number, strategy in enumerate(strategies, start=1):
            candidate: Optional[str] = None
            notes: List[str] = []
            engine_label = ""

            if strategy in ("granite", "granite-repair"):
                is_repair = strategy == "granite-repair"
                if is_repair and not (previous_code and failure_text):
                    continue  # nothing to repair
                result = granite.synthesize(
                    code,
                    language,
                    findings,
                    previous_attempt=previous_code if is_repair else None,
                    failure_report=failure_text if is_repair else None,
                )
                granite_calls.append(result.to_dict())
                if not result.ok:
                    attempts.append(
                        {
                            "attempt": attempt_number,
                            "strategy": strategy,
                            "succeeded": False,
                            "error": result.error,
                            "verdict": "error",
                        }
                    )
                    continue
                candidate = result.code
                engine_label = f"watsonx Granite ({result.model_id})"
                notes = [f"Synthesised by {engine_label} in {result.latency_ms}ms"]
            else:
                candidate, notes = transforms.apply_transformations(code, language)
                engine_label = "mechanical transformer"
                if candidate == code:
                    attempts.append(
                        {
                            "attempt": attempt_number,
                            "strategy": strategy,
                            "succeeded": False,
                            "error": "No transform applied cleanly to this source.",
                            "verdict": "no-change",
                        }
                    )
                    continue

            after = metrics.assess(candidate, language)
            comparison = metrics.compare(before, after)
            verification = sandbox.verify(candidate, language, findings, comparison)

            record = {
                "attempt": attempt_number,
                "strategy": strategy,
                "engine": engine_label,
                "succeeded": True,
                "verdict": verification["verdict"],
                "notes": notes,
                "code": candidate,
                "after": after,
                "comparison": comparison,
                "verification": verification,
                "resolved": comparison["counts"]["resolved"],
                "remaining": comparison["counts"]["remaining"],
                "residual_debt_score": comparison["residual_debt_score"],
            }
            attempts.append({k: v for k, v in record.items() if k not in ("code", "after")})

            if _better(record, best):
                best = record

            if verification["verdict"] == "clean":
                break

            previous_code = candidate
            failure_text = sandbox.failure_report(verification, comparison)

        # ── Assemble the outcome ────────────────────────────────────────────
        if best is None:
            # Nothing usable was produced. Return the input untouched rather than
            # emit broken code, and say so.
            after = before
            comparison = metrics.compare(before, before)
            verification = sandbox.verify(code, language, findings, comparison)
            modernized_code = code
            modernization_applied = False
            engine_used = "none"
            notes = []
            reason = (
                attempts[-1].get("error") if attempts else "No synthesis strategy was available."
            )
            log(
                4,
                "Synthesiser",
                f"No usable modernization produced — returning the source unchanged. "
                f"Reason: {reason}",
            )
        else:
            after = best["after"]
            comparison = best["comparison"]
            verification = best["verification"]
            modernized_code = best["code"]
            modernization_applied = True
            engine_used = best["engine"]
            notes = best["notes"]
            retry_note = (
                f" after {len(attempts)} attempt(s)" if len(attempts) > 1 else ""
            )
            log(
                4,
                "Synthesiser",
                f"Applied {engine_used}{retry_note}. "
                f"{len(modernized_code.splitlines())} line(s) out. "
                + ("Changes: " + "; ".join(notes) if notes else "No change notes recorded."),
            )

        emit(4, engine=engine_used, attempts=len(attempts))

        log(
            5,
            "Verifier",
            f"Verdict: {verification['verdict']}. "
            f"{verification['passed_count']}/{verification['total_count']} check(s) passed "
            f"in {verification['duration_ms']}ms. "
            f"Debt {comparison['initial_debt_score']} → {comparison['residual_debt_score']} "
            f"({comparison['debt_reduction_percent']}% reduction). "
            f"{comparison['counts']['resolved']} finding(s) resolved, "
            f"{comparison['counts']['remaining']} remaining, "
            f"{comparison['counts']['introduced']} introduced.",
        )
        emit(
            5,
            verdict=verification["verdict"],
            passed=verification["passed_count"],
            total=verification["total_count"],
        )

        plan = annotate_plan(plan, comparison)
        diff_rows = compute_structured_diff(code, modernized_code)
        stats = diff_stats(diff_rows)

        result: Dict[str, Any] = {
            "success": True,
            "cached": False,
            "language": language,
            "filename": target_filename,
            "elapsed_seconds": round(time.time() - started, 3),
            "original_code": code,
            "modernized_code": modernized_code,
            "modernization_applied": modernization_applied,
            "synthesis": {
                "engine": engine_used,
                "granite_configured": granite.is_configured(),
                "granite_sdk_installed": granite.SDK_AVAILABLE,
                "granite_calls": granite_calls,
                "attempts": attempts,
                "attempt_count": len(attempts),
                "change_notes": notes,
                "strategies_considered": strategies,
            },
            "structure": structure,
            "plan": plan,
            "metrics": {
                "initial_debt_score": comparison["initial_debt_score"],
                "residual_debt_score": comparison["residual_debt_score"],
                "initial_debt_points": comparison["initial_debt_points"],
                "residual_debt_points": comparison["residual_debt_points"],
                "debt_reduction_percent": comparison["debt_reduction_percent"],
                "rules_evaluated": rule_total,
                "findings_detected": comparison["counts"]["detected"],
                "findings_resolved": comparison["counts"]["resolved"],
                "findings_remaining": comparison["counts"]["remaining"],
                "findings_introduced": comparison["counts"]["introduced"],
                "vulnerabilities_detected": comparison["counts"]["vulnerabilities_detected"],
                "vulnerabilities_resolved": comparison["counts"]["vulnerabilities_resolved"],
                "vulnerabilities_remaining": comparison["counts"]["vulnerabilities_remaining"],
                "checks_passed": verification["passed_count"],
                "checks_total": verification["total_count"],
                "diff_lines_added": stats["lines_added"],
                "diff_lines_removed": stats["lines_removed"],
                "diff_lines_unchanged": stats["lines_unchanged"],
                "estimated_engineering_hours_saved": metrics.engineering_hours_saved(comparison),
                "comparison_reliable": comparison["reliable"],
            },
            "debt_breakdown": {
                "before": before["debt_breakdown"],
                "after": after["debt_breakdown"],
                "normalisation_k": metrics.NORMALISATION_K,
            },
            "findings": {
                "detected": findings,
                "resolved": comparison["resolved"],
                "remaining": comparison["remaining"],
                "introduced": comparison["introduced"],
            },
            # Kept for the split-pane audit view.
            "issues": rules.split_findings(findings),
            "verification": verification,
            "generated_tests": verification["generated_tests"],
            "native_tests": verification["native_tests"],
            "diff_unified": compute_unified_diff(code, modernized_code, target_filename),
            "diff_lines": diff_rows,
            "agent_logs": agent_logs,
        }

        if use_cache:
            if len(_RESULT_CACHE) >= CACHE_LIMIT:
                _RESULT_CACHE.pop(next(iter(_RESULT_CACHE)))
            _RESULT_CACHE[cache_key] = result

        return result

    # ── helpers ────────────────────────────────────────────────────────────

    def scan_only(self, code: str, language: str) -> Dict[str, Any]:
        """Stages 1-2 only, for live feedback while typing."""
        assessment = metrics.assess(code, language)
        buckets = rules.split_findings(assessment["findings"])
        return {
            "language": language,
            "structure": assessment["structure"],
            "debt_score": assessment["debt_score"],
            "debt_points": assessment["debt_points"],
            "debt_breakdown": assessment["debt_breakdown"],
            "findings": assessment["findings"],
            "issues": buckets,
            "rules_evaluated": len(rules.rules_for(language)),
            "scan_reliable": assessment["scan_reliable"],
        }

    def plan_only(self, code: str, language: str) -> Dict[str, Any]:
        assessment = metrics.assess(code, language)
        plan = build_plan(assessment["findings"], assessment["structure"], language)
        return {"plan": plan, "total_steps": len(plan)}

    def _cache_key(self, code: str, language: str) -> str:
        # Configuration is part of the key: the same input produces different
        # output once Granite is switched on.
        fingerprint = "|".join(
            [
                language,
                granite.configured_model() or "auto",
                "granite" if granite.is_configured() else "rules",
                "exec" if sandbox.allow_exec() else "noexec",
                code,
            ]
        )
        return hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:32]

    def _extension(self, language: str) -> str:
        return {
            "python": "py",
            "java": "java",
            "javascript": "js",
            "typescript": "ts",
            "go": "go",
            "php": "php",
        }.get(language, "txt")


engine = BobPulseEngine()
