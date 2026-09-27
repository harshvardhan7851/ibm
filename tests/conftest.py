"""Shared fixtures. Adds the repo root to sys.path so `backend` imports work."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.presets import EXAMPLES  # noqa: E402


@pytest.fixture(scope="session")
def examples():
    return EXAMPLES


@pytest.fixture(params=sorted(EXAMPLES), ids=sorted(EXAMPLES))
def example(request):
    """Each example legacy source, one per test invocation."""
    return EXAMPLES[request.param]


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch):
    """
    Keep tests independent of the developer's .env.

    Without this, a machine with real watsonx credentials would take the Granite
    path and the assertions about the deterministic transformer would fail.
    """
    for name in (
        "IBM_WATSONX_APIKEY",
        "WATSONX_APIKEY",
        "IBM_WATSONX_PROJECT_ID",
        "WATSONX_PROJECT_ID",
        "IBM_WATSONX_MODEL_ID",
        "BOBPULSE_ALLOW_EXEC",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def clear_engine_cache():
    from backend import engine as engine_module

    engine_module.clear_cache()
    yield
    engine_module.clear_cache()
