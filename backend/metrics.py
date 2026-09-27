"""
Structural metrics and technical-debt scoring.
==============================================

The debt score is a deterministic function of things that were actually
detected. Every point is attributable to a named source, exposed in
``debt_breakdown``, so the number can be audited rather than trusted.

Residual debt is produced by running the *same* assessment over the modernized
output. It is a measurement, not an estimate — if a transform changed nothing,
the residual equals the initial score and the reported reduction is 0%.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List, Optional, Sequence, Tuple

from backend import rules
from backend.rules import ScanContext

#: Controls how raw debt points map onto 0-100. With K=60, 60 points of findings
#: reads as 50%. Chosen so a single critical vulnerability (40 points) lands at a
#: visible but not maximal 40%, and a pile of them saturates towards 100 without
#: ever clipping.
NORMALISATION_K = 60


# ─────────────────────────────────────────────────────────────────────────────
#  Structural inspection
# ─────────────────────────────────────────────────────────────────────────────

_BRANCHING_NODES = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Try,
    ast.ExceptHandler,
    ast.With,
    ast.AsyncWith,
    ast.BoolOp,
    ast.IfExp,
    ast.comprehension,
)

_BRANCH_KEYWORDS = (
    r"\bif\b",
    r"\bfor\b",
    r"\bwhile\b",
    r"\bcatch\b",
    r"\bcase\b",
    r"\belse\s+if\b",
    r"&&",
    r"\|\|",
)


def inspect_structure(code: str, language: str, ctx: Optional[ScanContext] = None) -> Dict[str, Any]:
    """
    Describe the shape of the source.

    For Python this is a real ``ast`` walk. For every other language it is a
    keyword-based estimate, and ``complexity_estimated`` is set to ``True`` so
    callers never present an estimate as a measurement.
    """
    context = ctx or rules.build_context(code, language)
    info: Dict[str, Any] = {
        "language": language,
        "parseable": False,
        "parse_error": context.parse_error,
        "normalised_for_parse": context.normalised_for_parse,
        "num_lines": len(code.splitlines()),
        "num_classes": 0,
        "num_functions": 0,
        "cyclomatic_complexity": 1,
        "complexity_estimated": language != "python",
        "has_type_annotations": False,
        "has_docstrings": False,
    }

    if language != "python":
        import re

        scannable = context.scannable
        estimate = 1 + sum(len(re.findall(kw, scannable)) for kw in _BRANCH_KEYWORDS)
        info["cyclomatic_complexity"] = estimate
        info["parseable"] = True
        # Rough, language-agnostic shape hints.
        info["num_functions"] = len(
            re.findall(r"\b(?:function|func|def)\s+\w+|\b\w+\s*\([^)]*\)\s*\{", scannable)
        )
        info["num_classes"] = len(re.findall(r"\b(?:class|record|interface|struct)\s+\w+", scannable))
        return info

    if context.tree is None:
        return info

    tree = context.tree
    info["parseable"] = context.parse_error is None

    classes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    functions = [
        n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    info["num_classes"] = len(classes)
    info["num_functions"] = len(functions)
    info["cyclomatic_complexity"] = 1 + sum(
        1 for node in ast.walk(tree) if isinstance(node, _BRANCHING_NODES)
    )
    info["has_type_annotations"] = any(
        func.returns is not None
        or any(arg.annotation is not None for arg in func.args.args)
        or any(arg.annotation is not None for arg in func.args.kwonlyargs)
        for func in functions
    )
    info["has_docstrings"] = any(
        ast.get_docstring(node) for node in [*classes, *functions] if node
    ) or bool(ast.get_docstring(tree) if isinstance(tree, ast.Module) else None)

    return info


# ─────────────────────────────────────────────────────────────────────────────
#  Debt scoring
# ─────────────────────────────────────────────────────────────────────────────

def debt_breakdown(
    findings: Sequence[Dict[str, Any]], structure: Dict[str, Any]
) -> Tuple[int, List[Dict[str, Any]]]:
    """
    Total debt points plus the itemised list they came from.

    Each finding contributes its rule weight once, regardless of how many times
    it matched. Repeat occurrences are reported separately (``occurrences``)
    rather than multiplying the score, which keeps one noisy pattern from
    dominating the total.
    """
    items: List[Dict[str, Any]] = []
    total = 0

    for finding in findings:
        points = int(finding.get("debt", 0))
        total += points
        items.append(
            {
                "source": finding["id"],
                "label": finding["title"],
                "severity": finding["severity"],
                "points": points,
                "occurrences": finding.get("occurrences", 1),
            }
        )

    complexity = structure.get("cyclomatic_complexity", 1)
    if complexity > 25:
        penalty = 12
    elif complexity > 15:
        penalty = 8
    elif complexity > 8:
        penalty = 4
    else:
        penalty = 0
    if penalty:
        total += penalty
        items.append(
            {
                "source": "STRUCT-COMPLEXITY",
                "label": f"Cyclomatic complexity {complexity}",
                "severity": "LOW",
                "points": penalty,
                "occurrences": 1,
            }
        )

    if structure.get("language") == "python" and structure.get("parseable"):
        if not structure.get("has_type_annotations"):
            total += 5
            items.append(
                {
                    "source": "STRUCT-TYPING",
                    "label": "No type annotations",
                    "severity": "LOW",
                    "points": 5,
                    "occurrences": 1,
                }
            )
        if not structure.get("has_docstrings"):
            total += 3
            items.append(
                {
                    "source": "STRUCT-DOCS",
                    "label": "No docstrings",
                    "severity": "LOW",
                    "points": 3,
                    "occurrences": 1,
                }
            )

    return total, items


def normalise(points: int) -> int:
    """Map raw debt points onto a bounded 0-100 score."""
    if points <= 0:
        return 0
    return round(100 * points / (points + NORMALISATION_K))


def assess(code: str, language: str) -> Dict[str, Any]:
    """Full assessment of one revision of the source."""
    context = rules.build_context(code, language)
    findings = rules.scan(code, language, context)
    structure = inspect_structure(code, language, context)
    points, breakdown = debt_breakdown(findings, structure)

    return {
        "language": language,
        "findings": findings,
        "structure": structure,
        "debt_points": points,
        "debt_score": normalise(points),
        "debt_breakdown": breakdown,
        "scan_reliable": language != "python" or context.tree is not None,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Before / after comparison
# ─────────────────────────────────────────────────────────────────────────────

def _by_id(findings: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {f["id"]: f for f in findings}


def compare(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    """
    Diff two assessments into resolved / still-present / newly-introduced.

    ``reliable`` is False when the modernized revision could not be parsed. That
    case matters: unparseable Python makes every AST rule return nothing, which
    would otherwise look like a clean sweep. Callers must not report resolutions
    from an unreliable comparison.
    """
    before_map = _by_id(before["findings"])
    after_map = _by_id(after["findings"])

    resolved_ids = sorted(set(before_map) - set(after_map))
    remaining_ids = sorted(set(before_map) & set(after_map))
    introduced_ids = sorted(set(after_map) - set(before_map))

    reliable = bool(after.get("scan_reliable"))

    initial_score = before["debt_score"]
    residual_score = after["debt_score"] if reliable else initial_score
    reduction = (
        round((initial_score - residual_score) / initial_score * 100)
        if initial_score > 0
        else 0
    )

    def _vulns(ids, source):
        return [source[i] for i in ids if source[i]["category"] == rules.CATEGORY_VULNERABILITY]

    return {
        "reliable": reliable,
        "initial_debt_score": initial_score,
        "residual_debt_score": residual_score,
        "initial_debt_points": before["debt_points"],
        "residual_debt_points": after["debt_points"] if reliable else before["debt_points"],
        "debt_reduction_percent": max(reduction, 0),
        "resolved": [before_map[i] for i in resolved_ids],
        "remaining": [after_map[i] for i in remaining_ids],
        "introduced": [after_map[i] for i in introduced_ids],
        "counts": {
            "detected": len(before_map),
            "resolved": len(resolved_ids),
            "remaining": len(remaining_ids),
            "introduced": len(introduced_ids),
            "vulnerabilities_detected": len(_vulns(before_map.keys(), before_map)),
            "vulnerabilities_resolved": len(_vulns(resolved_ids, before_map)),
            "vulnerabilities_remaining": len(_vulns(remaining_ids, after_map)),
        },
    }


def engineering_hours_saved(comparison: Dict[str, Any]) -> float:
    """
    Rough remediation-effort estimate for *resolved* findings only.

    Deliberately conservative and based on severity alone. This is an estimate
    and is labelled as one everywhere it is surfaced.
    """
    per_severity = {"CRITICAL": 3.0, "HIGH": 1.5, "MEDIUM": 0.75, "LOW": 0.25}
    return round(
        sum(per_severity.get(f["severity"], 0.25) for f in comparison["resolved"]), 2
    )
