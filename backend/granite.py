"""
IBM watsonx.ai Granite synthesis client.
========================================

Three things this module does that the previous implementation did not:

1. **Resolves the model at runtime.** Foundation models get withdrawn — the
   original hardcoded ``ibm/granite-20b-code-instruct`` was removed from the
   multitenant service in 2025, and every call 404'd. We ask the account which
   models it actually has and pick the first from a preference list.
2. **Reports failures.** Errors are returned as data, not swallowed by a bare
   ``except``. A silent fallback that still claims success is worse than no
   integration at all.
3. **Supports repair prompts.** The self-healing loop needs to send a failed
   attempt back with the verifier's complaint attached.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

try:  # The SDK is optional — the rule engine works without it.
    from ibm_watsonx_ai import APIClient, Credentials
    from ibm_watsonx_ai.foundation_models import ModelInference
    from ibm_watsonx_ai.metanames import GenTextParamsMetaNames as GenParams

    SDK_AVAILABLE = True
    SDK_IMPORT_ERROR: Optional[str] = None
except Exception as exc:  # pragma: no cover - depends on the environment
    SDK_AVAILABLE = False
    SDK_IMPORT_ERROR = str(exc)

DEFAULT_URL = "https://us-south.ml.cloud.ibm.com"

#: Tried in order against whatever the account exposes. Newest first.
MODEL_PREFERENCE: Sequence[str] = (
    "ibm/granite-3-3-8b-instruct",
    "ibm/granite-3-2-8b-instruct",
    "ibm/granite-3-8b-instruct",
    "ibm/granite-34b-code-instruct",
    "ibm/granite-8b-code-instruct",
    "ibm/granite-20b-code-instruct",
)

PLACEHOLDER_PREFIXES = ("your_", "changeme", "example", "placeholder", "<", "paste")


def _is_real(value: str) -> bool:
    """Reject the untouched .env.example values so they read as 'not configured'."""
    if not value:
        return False
    clean = value.strip().lower()
    if clean in {"", "none", "null", "todo"}:
        return False
    return not any(clean.startswith(prefix) for prefix in PLACEHOLDER_PREFIXES)


def api_key() -> str:
    value = os.getenv("IBM_WATSONX_APIKEY") or os.getenv("WATSONX_APIKEY") or ""
    return value.strip() if _is_real(value) else ""


def project_id() -> str:
    value = os.getenv("IBM_WATSONX_PROJECT_ID") or os.getenv("WATSONX_PROJECT_ID") or ""
    return value.strip() if _is_real(value) else ""


def service_url() -> str:
    value = os.getenv("IBM_WATSONX_URL") or os.getenv("WATSONX_URL") or ""
    return value.strip() if _is_real(value) else DEFAULT_URL


def configured_model() -> str:
    value = os.getenv("IBM_WATSONX_MODEL_ID") or ""
    return value.strip() if _is_real(value) else ""


def is_configured() -> bool:
    return bool(api_key() and project_id())


# ─────────────────────────────────────────────────────────────────────────────
#  Result type
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class GraniteResult:
    """Outcome of one synthesis attempt."""

    code: Optional[str] = None
    model_id: Optional[str] = None
    error: Optional[str] = None
    latency_ms: int = 0
    attempted: bool = False

    @property
    def ok(self) -> bool:
        return bool(self.code and self.code.strip())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "succeeded": self.ok,
            "model_id": self.model_id,
            "error": self.error,
            "latency_ms": self.latency_ms,
        }


# ─────────────────────────────────────────────────────────────────────────────
#  Model resolution
# ─────────────────────────────────────────────────────────────────────────────

_resolved_cache: Dict[str, Any] = {"model_id": None, "available": None, "error": None}


def _available_models(client: "APIClient") -> List[str]:
    """
    Best-effort listing of usable model ids.

    The SDK has moved this call around between versions, so try the known shapes
    and give up quietly — an empty list just means "skip validation".
    """
    for getter in (
        lambda: client.foundation_models.get_model_specs(),
        lambda: client.foundation_models.get_model_specs(limit=200),
    ):
        try:
            specs = getter()
        except Exception:
            continue
        if isinstance(specs, dict) and "resources" in specs:
            ids = [r.get("model_id") for r in specs["resources"] if r.get("model_id")]
            if ids:
                return ids
        if isinstance(specs, list):
            ids = [r.get("model_id") for r in specs if isinstance(r, dict) and r.get("model_id")]
            if ids:
                return ids
    return []


def resolve_model(client: "APIClient") -> tuple[Optional[str], List[str]]:
    """
    Pick a model id. An explicit IBM_WATSONX_MODEL_ID always wins.

    Otherwise walk :data:`MODEL_PREFERENCE` and take the first one the account
    actually offers. If the listing call is unavailable, fall back to the first
    preference and let the inference call surface any error.
    """
    override = configured_model()
    if override:
        return override, []

    if _resolved_cache["model_id"]:
        return _resolved_cache["model_id"], _resolved_cache["available"] or []

    available = _available_models(client)
    if not available:
        return MODEL_PREFERENCE[0], []

    for candidate in MODEL_PREFERENCE:
        if candidate in available:
            _resolved_cache["model_id"] = candidate
            _resolved_cache["available"] = available
            return candidate, available

    # Nothing from the preference list — take any Granite instruct model.
    granite = [m for m in available if "granite" in m and "instruct" in m]
    chosen = granite[0] if granite else (available[0] if available else None)
    _resolved_cache["model_id"] = chosen
    _resolved_cache["available"] = available
    return chosen, available


# ─────────────────────────────────────────────────────────────────────────────
#  Prompting
# ─────────────────────────────────────────────────────────────────────────────

SYNTHESIS_PROMPT = """You are a code modernization engine. Rewrite the {language} source below so that every listed finding is fixed.

Hard requirements:
- Output ONLY the rewritten {language} source. No prose, no explanation, no markdown fences.
- Preserve the public API: same class, function and method names, same call signatures.
- Preserve behaviour other than the defects being fixed.
- Do not leave TODO placeholders. Produce complete, runnable code.

Findings to fix:
{findings}

Source:
{code}
"""

REPAIR_PROMPT = """Your previous rewrite of this {language} source was rejected by an automated verifier.

Verifier report:
{failure}

Fix those specific problems. Output ONLY the corrected {language} source — no prose, no markdown fences.

Your previous attempt:
{previous}

Original source for reference:
{code}
"""

_FENCE = re.compile(r"^\s*```[\w+-]*\s*\n(?P<body>.*?)\n\s*```\s*$", re.DOTALL)


def strip_fences(text: str) -> str:
    """Remove a wrapping markdown code fence if the model added one anyway."""
    match = _FENCE.match(text)
    if match:
        return match.group("body")
    # A leading fence with no closing partner.
    cleaned = re.sub(r"^\s*```[\w+-]*\s*\n", "", text)
    cleaned = re.sub(r"\n\s*```\s*$", "", cleaned)
    return cleaned


def format_findings(findings: Sequence[Dict[str, Any]]) -> str:
    if not findings:
        return "- No automated findings; modernize idiomatically without changing behaviour."
    lines = []
    for finding in findings:
        label = finding.get("cwe") or finding["id"]
        where = ", ".join(str(line) for line in finding.get("lines", [])[:5])
        location = f" (line{'s' if len(finding.get('lines', [])) > 1 else ''} {where})" if where else ""
        lines.append(f"- [{label}] {finding['title']}{location}: {finding['remediation']}")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
#  Synthesis
# ─────────────────────────────────────────────────────────────────────────────

def synthesize(
    code: str,
    language: str,
    findings: Sequence[Dict[str, Any]],
    previous_attempt: Optional[str] = None,
    failure_report: Optional[str] = None,
    max_new_tokens: int = 2048,
) -> GraniteResult:
    """
    Ask Granite to rewrite ``code``.

    Pass ``previous_attempt`` and ``failure_report`` to request a repair of a
    rejected attempt instead of a fresh rewrite.
    """
    result = GraniteResult(attempted=True)

    if not SDK_AVAILABLE:
        result.error = (
            "ibm-watsonx-ai is not installed. Run: pip install ibm-watsonx-ai"
            + (f" ({SDK_IMPORT_ERROR})" if SDK_IMPORT_ERROR else "")
        )
        return result

    key, project = api_key(), project_id()
    if not key or not project:
        result.attempted = False
        result.error = "IBM_WATSONX_APIKEY and IBM_WATSONX_PROJECT_ID are not set."
        return result

    started = time.time()
    try:
        client = APIClient(
            credentials=Credentials(api_key=key, url=service_url()),
            project_id=project,
        )
        model_id, _available = resolve_model(client)
        if not model_id:
            result.error = "No usable foundation model found for this project."
            result.latency_ms = int((time.time() - started) * 1000)
            return result

        result.model_id = model_id

        if previous_attempt and failure_report:
            prompt = REPAIR_PROMPT.format(
                language=language,
                failure=failure_report,
                previous=previous_attempt,
                code=code,
            )
        else:
            prompt = SYNTHESIS_PROMPT.format(
                language=language,
                findings=format_findings(findings),
                code=code,
            )

        model = ModelInference(
            model_id=model_id,
            api_client=client,
            params={
                GenParams.DECODING_METHOD: "greedy",
                GenParams.MAX_NEW_TOKENS: max_new_tokens,
                GenParams.MIN_NEW_TOKENS: 1,
                GenParams.REPETITION_PENALTY: 1.0,
            },
        )

        response = model.generate_text(prompt=prompt)
        text = response if isinstance(response, str) else str(response)
        candidate = strip_fences(text).strip()

        result.latency_ms = int((time.time() - started) * 1000)

        if len(candidate) < 20:
            result.error = f"Model returned {len(candidate)} characters — too short to use."
            return result

        result.code = candidate
        return result

    except Exception as exc:
        result.latency_ms = int((time.time() - started) * 1000)
        result.error = f"{type(exc).__name__}: {exc}"
        return result


def status() -> Dict[str, Any]:
    """Credential and SDK state for /api/health. Never reports more than is true."""
    key, project = api_key(), project_id()
    configured = bool(key and project)
    return {
        "sdk_installed": SDK_AVAILABLE,
        "sdk_import_error": SDK_IMPORT_ERROR,
        "api_key_present": bool(key),
        "project_id_present": bool(project),
        "configured": configured,
        "service_url": service_url(),
        "model_id_override": configured_model() or None,
        "resolved_model_id": _resolved_cache.get("model_id"),
        "mode": "granite" if (configured and SDK_AVAILABLE) else "rule-engine",
    }
