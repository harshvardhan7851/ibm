"""
BobPulse entrypoint.

Starts the API and the bundled UI on http://127.0.0.1:8000.

The startup banner is rendered from :func:`backend.granite.status`, the same
source /api/health uses, so the console cannot report a different synthesis mode
than the running service.
"""

from __future__ import annotations

import io
import os
import sys

# Windows consoles default to a legacy code page, which mangles the banner.
# line_buffering=True matters: without it the wrapper buffers, and the banner
# only appears once the server exits — which is never, in normal use.
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True
    )
    sys.stderr = io.TextIOWrapper(
        sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True
    )

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uvicorn  # noqa: E402

from backend import granite, rules, sandbox  # noqa: E402

HOST = os.getenv("BOBPULSE_HOST", "127.0.0.1")
PORT = int(os.getenv("BOBPULSE_PORT", "8000"))


def synthesis_line() -> str:
    """One line describing what will actually do the rewriting, and why."""
    status = granite.status()
    if status["mode"] == "granite":
        model = status["model_id_override"] or "resolved on first call"
        return f"watsonx Granite  ({model})"

    if not status["sdk_installed"]:
        reason = 'SDK missing — pip install "ibm-watsonx-ai>=1.0,<2.0"'
    elif not status["api_key_present"]:
        reason = "IBM_WATSONX_APIKEY not set"
    elif not status["project_id_present"]:
        reason = "IBM_WATSONX_PROJECT_ID not set"
    else:
        reason = "not configured"
    return f"deterministic transformer  ({reason})"


def main() -> None:
    width = 68
    print("=" * width)
    print("  BobPulse — legacy code scanner & automated remediation")
    print("-" * width)
    print(f"  UI          http://{HOST}:{PORT}")
    print(f"  API docs    http://{HOST}:{PORT}/docs")
    print(f"  Rules       {rules.rule_count()} across {len(rules.SUPPORTED_LANGUAGES)} languages")
    print(f"  Synthesis   {synthesis_line()}")
    if sandbox.allow_exec():
        print("  Execution   ENABLED — the modernized module will be imported.")
        print("              This runs the submitted source. Container use only.")
    else:
        print("  Execution   disabled (set BOBPULSE_ALLOW_EXEC=1 only in a container)")
    print("=" * width)

    uvicorn.run("backend.app:app", host=HOST, port=PORT, reload=False)


if __name__ == "__main__":
    main()
