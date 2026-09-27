"""
Manual smoke test against a *running* server.

This is not part of the pytest suite — it needs a live server and is here for
quick eyeballing during development:

    python run.py            # in one terminal
    python tools/smoke_test.py

For the real automated suite (no server required) run: pytest
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

BASE_URL = "http://127.0.0.1:8000"


def get(path: str):
    with urllib.request.urlopen(f"{BASE_URL}{path}", timeout=30) as response:
        return json.loads(response.read())


def post(path: str, payload: dict):
    request = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.loads(response.read())


def main() -> int:
    try:
        health = get("/api/health")
    except urllib.error.URLError as exc:
        print(f"Cannot reach {BASE_URL} — is the server running? ({exc})")
        return 1

    print(f"health      : {health['status']} v{health['version']}")
    print(f"synthesis   : {health['synthesis']['mode']}")
    print(f"rules       : {health['rules']['total']} across {len(health['supported_languages'])} languages")
    print(f"exec enabled: {health['verification']['code_execution_enabled']}")

    examples = get("/api/examples")["examples"]
    print(f"examples    : {', '.join(e['id'] for e in examples)}")

    for example in examples:
        run = post(
            "/api/analyze",
            {
                "code": example["original_code"],
                "language": example["language"],
                "filename": example["filename"],
                "use_cache": False,
            },
        )
        metrics = run["metrics"]
        print(
            f"\n{example['id']} ({example['language']})"
            f"\n  engine    : {run['synthesis']['engine']}"
            f"\n  verdict   : {run['verification']['verdict']}"
            f"\n  debt      : {metrics['initial_debt_score']} -> {metrics['residual_debt_score']}"
            f" ({metrics['debt_reduction_percent']}% reduction)"
            f"\n  findings  : {metrics['findings_resolved']}/{metrics['findings_detected']} resolved,"
            f" {metrics['findings_remaining']} remaining, {metrics['findings_introduced']} introduced"
            f"\n  checks    : {metrics['checks_passed']}/{metrics['checks_total']}"
            f"\n  elapsed   : {run['elapsed_seconds']}s"
        )

    # The property that matters most: output must follow the input.
    probe = post(
        "/api/analyze",
        {"code": "import md5\nSENTINEL = md5.new('x').hexdigest()\n", "language": "python"},
    )
    reflected = "SENTINEL" in probe["modernized_code"]
    print(f"\ninput reflected in output: {reflected}")
    if not reflected:
        print("FAIL — the pipeline is not analysing the submitted source.")
        return 1

    print("\nAll smoke checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
