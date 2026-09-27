"""
Pipeline orchestration tests.

The regression that motivated most of this file: the pipeline used to return a
stored "modernized" version of a named example and ignore the code it was given.
``test_output_follows_the_submitted_source`` is the guard against that returning.
"""

from __future__ import annotations

import pytest

from backend import engine as engine_module
from backend import granite, presets
from backend.engine import BobPulseEngine

engine = BobPulseEngine()


# ── The load-bearing regression ──────────────────────────────────────────────

@pytest.mark.slow
def test_output_follows_the_submitted_source():
    """Editing the input must change the output. No stored answers."""
    run = engine.analyze("import md5\nSENTINEL_TOKEN = md5.new('x').hexdigest()\n", "python")
    assert "SENTINEL_TOKEN" in run["modernized_code"]
    assert "hashlib.sha256" in run["modernized_code"]


@pytest.mark.slow
def test_two_different_inputs_give_two_different_outputs():
    first = engine.analyze("import md5\nA_MARKER = md5.new('x').hexdigest()\n", "python")
    second = engine.analyze("import md5\nB_MARKER = md5.new('y').hexdigest()\n", "python")
    assert first["modernized_code"] != second["modernized_code"]
    assert "A_MARKER" in first["modernized_code"]
    assert "B_MARKER" in second["modernized_code"]


def test_examples_carry_no_stored_output():
    """The golden-output cheat path must stay deleted."""
    for example in presets.EXAMPLES.values():
        assert "modernized_code" not in example
        assert "tests" not in example
    for summary in presets.example_summaries():
        assert "modernized_code" not in summary


# ── Validation ───────────────────────────────────────────────────────────────

def test_unsupported_language_is_rejected():
    with pytest.raises(ValueError, match="Unsupported language"):
        engine.analyze("x = 1", "cobol")


def test_empty_source_is_rejected():
    with pytest.raises(ValueError, match="must not be empty"):
        engine.analyze("   \n", "python")


# ── Shape of the result ──────────────────────────────────────────────────────

@pytest.mark.slow
def test_result_exposes_everything_the_ui_consumes(example):
    run = engine.analyze(
        example["original_code"], example["language"], filename=example["filename"]
    )

    for key in (
        "success",
        "metrics",
        "verification",
        "findings",
        "issues",
        "plan",
        "debt_breakdown",
        "structure",
        "agent_logs",
        "diff_lines",
        "diff_unified",
        "original_code",
        "modernized_code",
        "modernization_applied",
        "synthesis",
        "generated_tests",
        "native_tests",
    ):
        assert key in run, f"missing {key}"

    for key in (
        "initial_debt_score",
        "residual_debt_score",
        "debt_reduction_percent",
        "findings_detected",
        "findings_resolved",
        "findings_remaining",
        "findings_introduced",
        "checks_passed",
        "checks_total",
        "comparison_reliable",
    ):
        assert key in run["metrics"], f"missing metric {key}"


@pytest.mark.slow
def test_agent_log_covers_all_five_stages(example):
    run = engine.analyze(example["original_code"], example["language"])
    assert len(run["agent_logs"]) == len(engine_module.STAGES)
    for index, entry in enumerate(run["agent_logs"], start=1):
        assert entry["stage"].startswith(f"Stage {index}")
        assert entry["detail"]


@pytest.mark.slow
def test_progress_callback_reports_each_stage_once(example):
    seen = []
    engine.analyze(
        example["original_code"],
        example["language"],
        progress=lambda event: seen.append(event["stage"]),
        use_cache=False,
    )
    assert seen == sorted(engine_module.STAGES)


# ── Measured metrics ─────────────────────────────────────────────────────────

@pytest.mark.slow
def test_metrics_agree_with_the_finding_lists(example):
    run = engine.analyze(example["original_code"], example["language"])
    metrics = run["metrics"]
    findings = run["findings"]

    assert metrics["findings_detected"] == len(findings["detected"])
    assert metrics["findings_resolved"] == len(findings["resolved"])
    assert metrics["findings_remaining"] == len(findings["remaining"])
    assert metrics["findings_introduced"] == len(findings["introduced"])
    assert metrics["findings_detected"] == (
        metrics["findings_resolved"] + metrics["findings_remaining"]
    )


@pytest.mark.slow
def test_every_example_makes_measurable_progress(example):
    run = engine.analyze(example["original_code"], example["language"])
    assert run["metrics"]["findings_resolved"] > 0
    assert run["metrics"]["debt_reduction_percent"] > 0
    assert run["metrics"]["findings_introduced"] == 0
    assert run["verification"]["verdict"] in {"clean", "partial"}


@pytest.mark.slow
def test_plan_steps_are_annotated_with_the_outcome(example):
    run = engine.analyze(example["original_code"], example["language"])
    resolved = {f["id"] for f in run["findings"]["resolved"]}
    remaining = {f["id"] for f in run["findings"]["remaining"]}

    for step in run["plan"]:
        assert step["status"] in {"resolved", "unresolved", "not_attempted"}
        if step["rule_id"] in resolved:
            assert step["status"] == "resolved"
        elif step["rule_id"] in remaining:
            assert step["status"] == "unresolved"


@pytest.mark.slow
def test_source_with_no_findings_is_left_alone():
    clean = '"""Doc."""\n\n\ndef add(a: int, b: int) -> int:\n    """Add."""\n    return a + b\n'
    run = engine.analyze(clean, "python")
    assert run["metrics"]["initial_debt_score"] == 0
    assert run["metrics"]["findings_introduced"] == 0
    assert run["modernization_applied"] is False
    assert run["modernized_code"] == clean


# ── Synthesis strategy ───────────────────────────────────────────────────────

def test_without_credentials_only_the_transformer_is_considered():
    assert granite.is_configured() is False
    assert engine_module._strategy_sequence() == ["transform"]


def test_with_credentials_granite_is_tried_first_then_repair_then_transform(monkeypatch):
    monkeypatch.setenv("IBM_WATSONX_APIKEY", "real-looking-key")
    monkeypatch.setenv("IBM_WATSONX_PROJECT_ID", "11111111-2222-3333-4444-555555555555")
    monkeypatch.setattr(granite, "SDK_AVAILABLE", True)
    assert engine_module._strategy_sequence() == ["granite", "granite-repair", "transform"]


@pytest.mark.slow
def test_a_failing_model_falls_back_to_the_transformer_and_records_the_error(monkeypatch):
    monkeypatch.setenv("IBM_WATSONX_APIKEY", "real-looking-key")
    monkeypatch.setenv("IBM_WATSONX_PROJECT_ID", "11111111-2222-3333-4444-555555555555")
    monkeypatch.setattr(granite, "SDK_AVAILABLE", True)

    def failing_synthesize(*_args, **_kwargs):
        return granite.GraniteResult(attempted=True, error="Simulated 404: model withdrawn")

    monkeypatch.setattr(granite, "synthesize", failing_synthesize)

    run = engine.analyze("import md5\nd = md5.new('x').hexdigest()\n", "python", use_cache=False)

    assert run["synthesis"]["engine"] == "mechanical transformer"
    errors = [call["error"] for call in run["synthesis"]["granite_calls"] if call["error"]]
    assert any("Simulated 404" in error for error in errors), "the model error was swallowed"
    assert run["metrics"]["findings_resolved"] > 0


@pytest.mark.slow
def test_model_output_is_used_when_it_verifies(monkeypatch):
    monkeypatch.setenv("IBM_WATSONX_APIKEY", "real-looking-key")
    monkeypatch.setenv("IBM_WATSONX_PROJECT_ID", "11111111-2222-3333-4444-555555555555")
    monkeypatch.setattr(granite, "SDK_AVAILABLE", True)

    def good_synthesize(*_args, **_kwargs):
        return granite.GraniteResult(
            code='"""Fixed."""\nimport hashlib\n\n\ndef digest(value: bytes) -> str:\n    """Digest."""\n    return hashlib.sha256(value).hexdigest()\n',
            model_id="ibm/granite-test",
            attempted=True,
            latency_ms=42,
        )

    monkeypatch.setattr(granite, "synthesize", good_synthesize)

    run = engine.analyze("import md5\nd = md5.new('x').hexdigest()\n", "python", use_cache=False)

    assert "granite-test" in run["synthesis"]["engine"]
    assert run["verification"]["verdict"] == "clean"


@pytest.mark.slow
def test_broken_model_output_is_rejected_and_the_transformer_wins(monkeypatch):
    """The self-healing loop must not ship unparseable model output."""
    monkeypatch.setenv("IBM_WATSONX_APIKEY", "real-looking-key")
    monkeypatch.setenv("IBM_WATSONX_PROJECT_ID", "11111111-2222-3333-4444-555555555555")
    monkeypatch.setattr(granite, "SDK_AVAILABLE", True)

    calls = []

    def broken_synthesize(*_args, **kwargs):
        calls.append(kwargs)
        return granite.GraniteResult(
            code="def broken(:\n    this is not python\n",
            model_id="ibm/granite-test",
            attempted=True,
        )

    monkeypatch.setattr(granite, "synthesize", broken_synthesize)

    run = engine.analyze("import md5\nd = md5.new('x').hexdigest()\n", "python", use_cache=False)

    # A repair attempt was made, with the verifier's complaint attached.
    assert len(calls) >= 2
    assert any(call.get("failure_report") for call in calls)
    # And the deterministic transformer's sound output was preferred.
    assert run["synthesis"]["engine"] == "mechanical transformer"
    assert run["verification"]["verdict"] in {"clean", "partial"}
    compile(run["modernized_code"], "<result>", "exec")


# ── Caching ──────────────────────────────────────────────────────────────────

@pytest.mark.slow
def test_repeat_runs_are_served_from_cache():
    source = "import md5\nd = md5.new('x').hexdigest()\n"
    first = engine.analyze(source, "python")
    second = engine.analyze(source, "python")
    assert first["cached"] is False
    assert second["cached"] is True
    assert second["modernized_code"] == first["modernized_code"]


@pytest.mark.slow
def test_cache_can_be_bypassed():
    source = "import md5\nd = md5.new('x').hexdigest()\n"
    engine.analyze(source, "python")
    assert engine.analyze(source, "python", use_cache=False)["cached"] is False


@pytest.mark.slow
def test_cache_key_accounts_for_configuration(monkeypatch):
    """Switching Granite on must not serve the rule-engine result."""
    source = "import md5\nd = md5.new('x').hexdigest()\n"
    unconfigured = engine._cache_key(source, "python")

    monkeypatch.setenv("IBM_WATSONX_APIKEY", "real-looking-key")
    monkeypatch.setenv("IBM_WATSONX_PROJECT_ID", "11111111-2222-3333-4444-555555555555")
    assert engine._cache_key(source, "python") != unconfigured


# ── Diffing ──────────────────────────────────────────────────────────────────

def test_identical_input_produces_an_empty_diff():
    rows = engine_module.compute_structured_diff("a\nb\n", "a\nb\n")
    stats = engine_module.diff_stats(rows)
    assert stats["lines_added"] == 0
    assert stats["lines_removed"] == 0
    assert stats["lines_unchanged"] == 2


def test_diff_rows_carry_line_numbers_on_both_sides():
    rows = engine_module.compute_structured_diff("a\nb\n", "a\nc\n")
    replaced = [row for row in rows if row["type"] == "replace"]
    assert replaced
    assert replaced[0]["left_line"] == 2
    assert replaced[0]["right_line"] == 2


def test_insertions_have_no_left_line():
    rows = engine_module.compute_structured_diff("a\n", "a\nb\n")
    inserted = [row for row in rows if row["type"] == "insert"]
    assert inserted and inserted[0]["left_line"] is None


def test_unified_diff_names_the_file():
    diff = engine_module.compute_unified_diff("a\n", "b\n", "svc.py")
    assert "a/svc.py" in diff and "b/svc.py" in diff


# ── Scan and plan shortcuts ──────────────────────────────────────────────────

def test_scan_only_skips_synthesis(example):
    result = engine.scan_only(example["original_code"], example["language"])
    assert "modernized_code" not in result
    assert result["findings"]
    assert result["rules_evaluated"] > 0
    assert result["debt_score"] > 0


def test_plan_only_returns_ordered_steps(example):
    result = engine.plan_only(example["original_code"], example["language"])
    assert result["total_steps"] == len(result["plan"])
    priorities = [step["priority"] for step in result["plan"]]
    assert priorities == sorted(priorities)
