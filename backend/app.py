"""
BobPulse HTTP API.
==================

Thin layer over :mod:`backend.engine`. The streaming endpoint runs the *same*
pipeline as the blocking one and forwards its progress callback over SSE — the
previous version reimplemented all five stages inline, so the two could drift.
"""

from __future__ import annotations

import asyncio
import json
import os
from queue import Empty, Queue
from typing import Any, Dict, List, Optional

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # dotenv is optional
    pass

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend import granite, rules, sandbox
from backend.engine import STAGES, cache_size, engine, max_attempts
from backend.patch_generator import generate_pull_request_payload
from backend.presets import example_summaries

API_VERSION = "3.0.0"

app = FastAPI(
    title="BobPulse API",
    version=API_VERSION,
    description=(
        "Static analysis and automated remediation for legacy code. Scans with a "
        "line-accurate rule engine, rewrites via IBM watsonx Granite when "
        "configured or a deterministic transformer otherwise, then verifies the "
        "result by re-scanning it and executing generated regression assertions."
    ),
)


def _allowed_origins() -> List[str]:
    """
    Same-origin by default: the UI is served by this app, so no CORS is needed.

    Set BOBPULSE_CORS_ORIGINS to a comma-separated list to allow a separately
    hosted frontend. A wildcard is not used by default — the previous
    ``allow_origins=["*"]`` combined with ``allow_credentials=True`` is a
    combination browsers reject anyway.
    """
    raw = os.getenv("BOBPULSE_CORS_ORIGINS", "").strip()
    if not raw:
        return []
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


_origins = _allowed_origins()
if _origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )


# ─────────────────────────────────────────────────────────────────────────────
#  Request models
# ─────────────────────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    code: str = Field(..., min_length=1, description="Source to analyse.")
    language: str = Field("python", description=f"One of: {', '.join(rules.SUPPORTED_LANGUAGES)}")
    filename: Optional[str] = Field(None, description="Used in the diff header and branch name.")
    use_cache: bool = Field(True, description="Reuse an identical previous run.")


class ScanRequest(BaseModel):
    code: str = Field(..., min_length=1)
    language: str = Field("python")


class PRExportRequest(BaseModel):
    filename: str
    diff_unified: str
    metrics: Dict[str, Any]
    findings: Dict[str, Any]
    verification: Optional[Dict[str, Any]] = None
    synthesis: Optional[Dict[str, Any]] = None
    language: str = "python"


def _validate_language(language: str) -> None:
    if language not in rules.SUPPORTED_LANGUAGES:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Unsupported language '{language}'. "
                f"Supported: {', '.join(rules.SUPPORTED_LANGUAGES)}"
            ),
        )


# ─────────────────────────────────────────────────────────────────────────────
#  Metadata
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/health", tags=["meta"])
def health() -> Dict[str, Any]:
    """
    Real state of the service. Every value is computed, nothing is asserted.

    In particular ``synthesis.mode`` reports ``rule-engine`` unless credentials
    *and* the SDK are both present — it never claims a model connection it does
    not have.
    """
    granite_status = granite.status()
    return {
        "status": "healthy",
        "version": API_VERSION,
        "synthesis": granite_status,
        "rules": {
            "total": rules.rule_count(),
            "by_language": {
                language: len(rules.rules_for(language))
                for language in rules.SUPPORTED_LANGUAGES
            },
        },
        "pipeline": {
            "stages": [{"number": n, "label": label} for n, label in STAGES.items()],
            "max_synthesis_attempts": max_attempts(),
        },
        "verification": {
            "regression_harness": "pytest subprocess over the re-scanned output",
            "code_execution_enabled": sandbox.allow_exec(),
            "code_execution_note": (
                "Set BOBPULSE_ALLOW_EXEC=1 to additionally import the modernized "
                "module. That executes the submitted source — only enable it in a "
                "disposable container."
            ),
        },
        "supported_languages": list(rules.SUPPORTED_LANGUAGES),
        "cached_runs": cache_size(),
    }


@app.get("/api/rules", tags=["meta"])
def list_rules(language: Optional[str] = None) -> Dict[str, Any]:
    """The rule registry, so findings can be cross-referenced."""
    if language:
        _validate_language(language)
        selected = rules.rules_for(language)
    else:
        selected = rules.ALL_RULES

    return {
        "count": len(selected),
        "rules": [
            {
                "id": rule.id,
                "cwe": rule.cwe,
                "severity": rule.severity,
                "category": rule.category,
                "title": rule.title,
                "description": rule.description,
                "remediation": rule.remediation,
                "debt_points": rule.debt_points,
                "languages": list(rule.languages),
            }
            for rule in selected
        ],
    }


@app.get("/api/examples", tags=["meta"])
def list_examples() -> Dict[str, Any]:
    """
    Example legacy sources.

    Inputs only — there is no stored "expected output". Loading an example and
    running it exercises exactly the same pipeline as pasted code.
    """
    return {"examples": example_summaries()}


# Previous name, kept so older clients keep working.
@app.get("/api/presets", include_in_schema=False)
def list_presets() -> Dict[str, Any]:
    return {"presets": example_summaries(), "examples": example_summaries()}


# ─────────────────────────────────────────────────────────────────────────────
#  Analysis
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/analyze", tags=["analysis"])
async def analyze(request: AnalyzeRequest) -> Dict[str, Any]:
    """
    Run the full pipeline on the submitted source.

    The response reflects the code in the request body. There is no path that
    substitutes a stored result for a named example.
    """
    _validate_language(request.language)
    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(
            None,
            lambda: engine.analyze(
                code=request.code,
                language=request.language,
                filename=request.filename,
                use_cache=request.use_cache,
            ),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover - unexpected engine failure
        raise HTTPException(status_code=500, detail=f"{type(exc).__name__}: {exc}") from exc


@app.post("/api/scan", tags=["analysis"])
async def scan(request: ScanRequest) -> Dict[str, Any]:
    """Scan and score only — no synthesis. Cheap enough for live feedback."""
    _validate_language(request.language)
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, lambda: engine.scan_only(request.code, request.language)
    )


@app.post("/api/scan-only", include_in_schema=False)
async def scan_only(request: ScanRequest) -> Dict[str, Any]:
    return await scan(request)


@app.post("/api/plan", tags=["analysis"])
async def plan(request: ScanRequest) -> Dict[str, Any]:
    """The remediation plan without running synthesis."""
    _validate_language(request.language)
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, lambda: engine.plan_only(request.code, request.language)
    )


_SENTINEL = object()


@app.post("/api/analyze/stream", tags=["analysis"])
async def analyze_stream(request: AnalyzeRequest) -> StreamingResponse:
    """
    Server-sent events for the same pipeline as ``/api/analyze``.

    The engine runs in a worker thread and pushes progress events into a queue;
    this coroutine drains the queue and forwards them. Stage narration and the
    final payload therefore always come from one implementation.
    """
    _validate_language(request.language)

    queue: "Queue[Any]" = Queue()

    def on_progress(event: Dict[str, Any]) -> None:
        queue.put({"type": "progress", **event})

    def run() -> None:
        try:
            result = engine.analyze(
                code=request.code,
                language=request.language,
                filename=request.filename,
                progress=on_progress,
                use_cache=request.use_cache,
            )
            queue.put({"type": "result", "payload": result})
        except Exception as exc:
            queue.put({"type": "error", "error": f"{type(exc).__name__}: {exc}"})
        finally:
            queue.put(_SENTINEL)

    async def event_stream():
        loop = asyncio.get_running_loop()
        task = loop.run_in_executor(None, run)

        total_stages = len(STAGES)
        yield _sse({"type": "start", "total_stages": total_stages})

        while True:
            try:
                item = await loop.run_in_executor(None, lambda: queue.get(timeout=0.25))
            except Empty:
                # Keep proxies from closing an idle connection mid-analysis.
                yield ": keep-alive\n\n"
                continue

            if item is _SENTINEL:
                break
            yield _sse(item)

        await task

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _sse(payload: Dict[str, Any]) -> str:
    return f"data: {json.dumps(payload)}\n\n"


# ─────────────────────────────────────────────────────────────────────────────
#  Export
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/export-pr", tags=["export"])
def export_pr(request: PRExportRequest) -> Dict[str, Any]:
    """
    Build PR metadata and a Markdown body from a run's measured results.

    This does not contact GitHub. Create the PR with your own credentials, e.g.
    ``gh pr create --title "<title>" --body-file body.md``.
    """
    return generate_pull_request_payload(
        filename=request.filename,
        diff_unified=request.diff_unified,
        metrics=request.metrics,
        findings=request.findings,
        verification=request.verification,
        synthesis=request.synthesis,
        language=request.language,
    )


@app.post("/api/download-patch", tags=["export"])
def download_patch(request: PRExportRequest) -> Response:
    """The unified diff as a downloadable ``.patch`` file."""
    if not request.diff_unified.strip():
        raise HTTPException(
            status_code=409,
            detail="There is no diff to export — the run produced no changes.",
        )
    safe_name = "".join(c if c.isalnum() or c in "-_." else "-" for c in request.filename)
    return Response(
        content=request.diff_unified,
        media_type="text/x-diff",
        headers={"Content-Disposition": f'attachment; filename="bobpulse-{safe_name}.patch"'},
    )


# ─────────────────────────────────────────────────────────────────────────────
#  Static frontend (mounted last so it cannot shadow the API)
# ─────────────────────────────────────────────────────────────────────────────

_frontend = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.isdir(_frontend):
    app.mount("/", StaticFiles(directory=_frontend, html=True), name="frontend")