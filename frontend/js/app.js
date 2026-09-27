/**
 * BobPulse Studio client.
 *
 * Talks to the real API. Notable differences from the previous version:
 *
 *  - Examples are fetched from /api/examples. The ~300 lines of duplicated
 *    preset source that used to live here are gone.
 *  - No `preset_id` is sent. The server analyses exactly what is in the editor,
 *    so editing the code changes the result.
 *  - There is no offline "fallback render" that fabricates a successful run.
 *    If the backend is unreachable the UI says so.
 */

"use strict";

const STAGE_COUNT = 5;

const state = {
    examples: [],
    currentExampleId: null,
    run: null,
    running: false,
    health: null,
    scanDebounce: null,
};

// ── Boot ─────────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", async () => {
    wireTabs();
    wireControls();
    wireLiveScan();
    wireShortcuts();

    await loadHealth();
    await loadExamples();
});

function $(id) {
    return document.getElementById(id);
}

async function api(path, options = {}) {
    const response = await fetch(path, options);
    if (!response.ok) {
        let detail = `HTTP ${response.status}`;
        try {
            const body = await response.json();
            if (body && body.detail) detail = body.detail;
        } catch (_) {
            /* non-JSON error body */
        }
        throw new Error(detail);
    }
    return response.json();
}

// ── Health ───────────────────────────────────────────────────────────────────

async function loadHealth() {
    const dot = $("sidebarStatusDot");
    const label = $("sidebarStatusLabel");
    const meta = $("sidebarModelMeta");

    try {
        const health = await api("/api/health");
        state.health = health;
        $("versionTag").textContent = `v${health.version.split(".")[0]}`;

        const synth = health.synthesis;
        dot.classList.add("active");
        if (synth.mode === "granite") {
            dot.style.background = "var(--color-success)";
            label.textContent = "watsonx Granite active";
            meta.textContent = `${synth.resolved_model_id || synth.model_id_override || "model resolved on first call"} · ${health.rules.total} rules`;
        } else {
            dot.style.background = "var(--color-warning)";
            label.textContent = "Rule engine (deterministic)";
            const why = !synth.sdk_installed
                ? "SDK not installed"
                : !synth.api_key_present
                  ? "no API key"
                  : "no project id";
            meta.textContent = `${why} · ${health.rules.total} rules`;
        }
    } catch (err) {
        dot.style.background = "var(--color-error)";
        label.textContent = "Backend unreachable";
        meta.textContent = err.message;
    }
}

// ── Examples ─────────────────────────────────────────────────────────────────

async function loadExamples() {
    const container = $("presetsContainer");
    try {
        const data = await api("/api/examples");
        state.examples = data.examples || [];
    } catch (err) {
        container.innerHTML = `<div class="preset-empty">Could not load examples: ${escapeHtml(err.message)}</div>`;
        return;
    }

    const langClass = { python: "py", java: "java", javascript: "js", typescript: "js", go: "go", php: "php" };
    container.innerHTML = state.examples
        .map(
            (example) => `
        <button class="preset-btn" data-example="${escapeHtml(example.id)}" type="button">
            <span class="preset-lang ${langClass[example.language] || "py"}">${escapeHtml(
                example.language.slice(0, 4).toUpperCase()
            )}</span>
            <span class="preset-name">${escapeHtml(example.name)}</span>
        </button>`
        )
        .join("");

    container.querySelectorAll(".preset-btn").forEach((button) => {
        button.addEventListener("click", () => loadExample(button.dataset.example, true));
    });

    if (state.examples.length) loadExample(state.examples[0].id, false);
}

function loadExample(exampleId, autoRun) {
    const example = state.examples.find((e) => e.id === exampleId);
    if (!example) return;

    state.currentExampleId = exampleId;
    document.querySelectorAll(".preset-btn").forEach((b) => {
        b.classList.toggle("active", b.dataset.example === exampleId);
    });

    $("rawCodeInput").value = example.original_code;
    $("languageSelect").value = example.language;
    $("currentFileName").textContent = example.filename;
    updateLineCounts(example.original_code, null);
    liveScan();

    if (autoRun) runAnalysis();
}

// ── Wiring ───────────────────────────────────────────────────────────────────

function wireTabs() {
    document.querySelectorAll(".tab-btn").forEach((tab) => {
        tab.addEventListener("click", () => {
            document.querySelectorAll(".tab-btn").forEach((t) => t.classList.remove("active"));
            document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
            tab.classList.add("active");
            const target = $(tab.dataset.tab);
            if (target) target.classList.add("active");
        });
    });
}

function wireControls() {
    $("runAgentBtn").addEventListener("click", runAnalysis);

    $("resetSnippetBtn").addEventListener("click", () => {
        if (state.currentExampleId) loadExample(state.currentExampleId, false);
    });

    $("languageSelect").addEventListener("change", liveScan);

    $("copyModernCodeBtn").addEventListener("click", () => {
        if (!state.run) return toast("Run an analysis first.", "error");
        copy(state.run.modernized_code, "Output copied.");
    });

    $("downloadPatchBtn").addEventListener("click", downloadPatch);

    const prModal = $("prModal");
    $("openPRModalBtn").addEventListener("click", openPRModal);
    $("closePRModalBtn").addEventListener("click", () => prModal.classList.remove("active"));
    $("copyPRMarkdownBtn").addEventListener("click", () => copy($("prBodyTextarea").value, "Markdown copied."));
    $("confirmPRBtn").addEventListener("click", downloadPatch);

    const docsModal = $("docsModal");
    $("openDocsBtn").addEventListener("click", (event) => {
        event.preventDefault();
        docsModal.classList.add("active");
    });
    $("closeDocsModalBtn").addEventListener("click", () => docsModal.classList.remove("active"));

    [prModal, docsModal].forEach((modal) => {
        modal.addEventListener("click", (event) => {
            if (event.target === modal) modal.classList.remove("active");
        });
    });

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
            prModal.classList.remove("active");
            docsModal.classList.remove("active");
        }
    });

    $("copyLogsBtn").addEventListener("click", () => {
        if (!state.run) return toast("Run an analysis first.", "error");
        const text = state.run.agent_logs
            .map((l) => `[${l.timestamp}] ${l.stage} — ${l.agent}: ${l.detail}`)
            .join("\n");
        copy(text, "Log copied.");
    });
}

function wireShortcuts() {
    document.addEventListener("keydown", (event) => {
        if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
            event.preventDefault();
            runAnalysis();
        }
    });
}

function wireLiveScan() {
    $("rawCodeInput").addEventListener("input", () => {
        updateLineCounts($("rawCodeInput").value, null);
        clearTimeout(state.scanDebounce);
        state.scanDebounce = setTimeout(liveScan, 500);
    });
}

/** Cheap scan-only pass so the findings badge tracks the editor. */
async function liveScan() {
    const code = $("rawCodeInput").value.trim();
    if (code.length < 20) return;
    try {
        const result = await api("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code, language: $("languageSelect").value }),
        });
        const badge = $("issueCountBadge");
        badge.textContent = String(result.findings.length);
        badge.style.background = result.findings.length
            ? "var(--color-error)"
            : "var(--color-success)";
        if (!state.run) {
            $("debtBeforeVal").textContent = `${result.debt_score}`;
            renderStructure(result.structure);
            renderDebtBreakdown(result.debt_breakdown, null);
        }
    } catch (_) {
        /* live scan is best-effort */
    }
}

// ── Run ──────────────────────────────────────────────────────────────────────

async function runAnalysis() {
    if (state.running) return;

    const code = $("rawCodeInput").value;
    if (!code.trim()) return toast("Nothing to analyse.", "error");

    state.running = true;
    setRunning(true);
    resetStages();
    const startedAt = performance.now();

    try {
        const response = await fetch("/api/analyze/stream", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                code,
                language: $("languageSelect").value,
                filename: $("currentFileName").textContent,
                use_cache: true,
            }),
        });

        if (!response.ok || !response.body) {
            throw new Error(`stream unavailable (HTTP ${response.status})`);
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        let result = null;

        for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });

            const lines = buffer.split("\n");
            buffer = lines.pop();

            for (const line of lines) {
                if (!line.startsWith("data: ")) continue;
                let event;
                try {
                    event = JSON.parse(line.slice(6));
                } catch (_) {
                    continue;
                }
                if (event.type === "progress") {
                    markStage(event.stage, event.label);
                } else if (event.type === "result") {
                    result = event.payload;
                } else if (event.type === "error") {
                    throw new Error(event.error);
                }
            }
        }

        if (!result) throw new Error("stream ended without a result");

        state.run = result;
        render(result);
        $("pipelineTimer").textContent = result.cached
            ? `cached result (${result.elapsed_seconds}s original run)`
            : `${result.elapsed_seconds}s`;
    } catch (err) {
        showBanner("error", "Run failed", err.message);
        $("pipelineTimer").textContent = `failed after ${((performance.now() - startedAt) / 1000).toFixed(1)}s`;
        toast(`Analysis failed: ${err.message}`, "error");
    } finally {
        state.running = false;
        setRunning(false);
    }
}

function setRunning(running) {
    const button = $("runAgentBtn");
    button.disabled = running;
    button.classList.toggle("is-running", running);
    const label = button.querySelector("span");
    if (label) label.innerHTML = running ? "Analysing…" : 'Analyse <kbd>Ctrl+↵</kbd>';
}

function resetStages() {
    for (let i = 1; i <= STAGE_COUNT; i += 1) {
        const step = $(`step${i}`);
        step.classList.remove("completed", "active");
    }
    $("pipelineTimer").textContent = "running…";
}

function markStage(stageNumber, label) {
    const step = $(`step${stageNumber}`);
    if (!step) return;
    step.classList.add("completed");
    step.classList.remove("active");
    const next = $(`step${stageNumber + 1}`);
    if (next) next.classList.add("active");
    $("pipelineTimer").textContent = `stage ${stageNumber}/${STAGE_COUNT} — ${label}`;
}

// ── Render ───────────────────────────────────────────────────────────────────

function render(run) {
    renderBanner(run);
    renderMetrics(run);
    renderStructure(run.structure);
    renderDebtBreakdown(run.debt_breakdown.before, run.debt_breakdown.after);
    renderDiff(run);
    renderFindings(run);
    renderPlan(run.plan);
    renderVerification(run);
    renderLog(run.agent_logs);

    $("footerNote").textContent = run.modernization_applied
        ? `Output from ${run.synthesis.engine}`
        : "No change applied — original source returned unchanged";
}

function renderBanner(run) {
    const verdict = run.verification.verdict;
    const failedCalls = (run.synthesis.granite_calls || []).filter((c) => c.error);

    if (!run.modernization_applied) {
        return showBanner(
            "error",
            "No change applied",
            "Nothing could be rewritten safely, so the original source was returned unchanged. " +
                "The findings below still describe real defects."
        );
    }
    if (verdict === "rejected") {
        return showBanner(
            "error",
            "Verification rejected",
            run.verification.blocking_failures.join(" · ")
        );
    }

    let note = `Rewritten by ${run.synthesis.engine}.`;
    if (run.synthesis.attempt_count > 1) {
        note += ` ${run.synthesis.attempt_count} attempts.`;
    }
    if (failedCalls.length) {
        note += ` watsonx call failed (${failedCalls[0].error}) — fell back to the deterministic transformer.`;
        return showBanner("warn", "Granite unavailable", note);
    }
    if (verdict === "partial") {
        note += ` ${run.metrics.findings_remaining} finding(s) could not be fixed automatically.`;
        return showBanner("warn", "Partial remediation", note);
    }
    showBanner("ok", "All findings resolved", note);
}

function showBanner(kind, tag, text) {
    const banner = $("synthesisBanner");
    banner.hidden = false;
    banner.className = `synthesis-banner banner-${kind}`;
    $("synthesisBannerTag").textContent = tag;
    $("synthesisBannerText").textContent = text;
}

function renderMetrics(run) {
    const m = run.metrics;

    $("debtBeforeVal").textContent = String(m.initial_debt_score);
    $("debtAfterVal").textContent = String(m.residual_debt_score);
    const trend = $("debtTrendBadge");
    trend.textContent = `-${m.debt_reduction_percent}%`;
    trend.className = `carbon-tag ${m.debt_reduction_percent > 0 ? "tag-success" : "tag-warning"}`;

    $("vulnCountVal").textContent = `${m.findings_resolved} / ${m.findings_detected}`;
    const shield = $("vulnShieldBadge");
    shield.textContent = m.findings_introduced ? `${m.findings_introduced} new` : `${m.vulnerabilities_resolved} security`;
    shield.className = `carbon-tag ${m.findings_introduced ? "tag-error" : "tag-success"}`;
    $("findingsSubtext").textContent = m.comparison_reliable
        ? `${m.findings_remaining} remaining · ${m.rules_evaluated} rules evaluated`
        : "Comparison unreliable — output did not parse";

    $("testPassRateVal").textContent = `${m.checks_passed} / ${m.checks_total}`;
    const verdict = run.verification.verdict;
    const badge = $("testPassBadge");
    badge.textContent = verdict;
    badge.className = `carbon-tag ${
        verdict === "clean" ? "tag-success" : verdict === "partial" ? "tag-warning" : "tag-error"
    }`;
    $("verdictBadge").textContent = `${run.verification.duration_ms}ms`;
    $("harnessNote").textContent = run.verification.harness_executed
        ? "Compile check + executed regression assertions"
        : "Regression harness did not execute — see Verification tab";

    $("hoursSavedVal").textContent = `~${m.estimated_engineering_hours_saved} h`;
    $("testCountBadge").textContent = `${m.checks_passed}/${m.checks_total}`;
    $("issueCountBadge").textContent = String(m.findings_detected);
    $("planCountBadge").textContent = String(run.plan.length);
}

function renderStructure(structure) {
    if (!structure) return;
    const complexityLabel = structure.complexity_estimated
        ? "Complexity (est.)"
        : "Cyclomatic complexity";
    const rows = [
        ["Lines", structure.num_lines],
        ["Functions", structure.num_functions],
        ["Classes", structure.num_classes],
        [complexityLabel, structure.cyclomatic_complexity],
    ];
    if (structure.language === "python") {
        rows.push(["Type annotations", structure.has_type_annotations ? "present" : "absent"]);
        rows.push(["Docstrings", structure.has_docstrings ? "present" : "absent"]);
    }
    if (structure.parse_error) {
        rows.push([
            "Parse",
            structure.normalised_for_parse
                ? "Python 2 syntax — analysed after normalising"
                : `failed: ${structure.parse_error}`,
        ]);
    }

    $("astInfoPanel").innerHTML = rows
        .map(([label, value]) => {
            const bad = value === "absent" || String(label) === "Parse";
            return `<div class="ast-stat"><span class="ast-label">${escapeHtml(label)}</span><span class="ast-val${
                bad ? " bad" : ""
            }">${escapeHtml(String(value))}</span></div>`;
        })
        .join("");
}

function renderDebtBreakdown(before, after) {
    const afterPoints = new Map((after || []).map((item) => [item.source, item.points]));
    const rows = (before || []).map((item) => {
        const stillThere = after ? afterPoints.has(item.source) : null;
        const statusHtml =
            stillThere === null
                ? ""
                : stillThere
                  ? '<span class="chip chip-warn">still present</span>'
                  : '<span class="chip chip-ok">cleared</span>';
        return `<tr>
            <td><code>${escapeHtml(item.source)}</code></td>
            <td>${escapeHtml(item.label)}</td>
            <td class="num">${item.points}</td>
            <td class="num">${item.occurrences}×</td>
            <td>${statusHtml}</td>
        </tr>`;
    });

    const introduced = (after || [])
        .filter((item) => !(before || []).some((b) => b.source === item.source))
        .map(
            (item) => `<tr class="row-introduced">
            <td><code>${escapeHtml(item.source)}</code></td>
            <td>${escapeHtml(item.label)}</td>
            <td class="num">${item.points}</td>
            <td class="num">${item.occurrences}×</td>
            <td><span class="chip chip-bad">introduced</span></td>
        </tr>`
        );

    if (!rows.length && !introduced.length) {
        $("debtBreakdownList").innerHTML = '<p class="muted">No debt points recorded.</p>';
        return;
    }

    $("debtBreakdownList").innerHTML = `
        <table class="breakdown-table">
            <thead><tr><th>Source</th><th>Reason</th><th class="num">Points</th><th class="num">Hits</th><th>After</th></tr></thead>
            <tbody>${rows.join("")}${introduced.join("")}</tbody>
        </table>
        <p class="muted small">Score = 100 × points ÷ (points + 60).</p>`;
}

function renderDiff(run) {
    const m = run.metrics;
    $("diffStatsBar").innerHTML = `
        <span class="diff-stat added">+${m.diff_lines_added} added</span>
        <span class="diff-stat removed">-${m.diff_lines_removed} removed</span>
        <span class="diff-stat neutral">${m.diff_lines_unchanged} unchanged</span>
        <span class="diff-stat neutral">${m.rules_evaluated} rules evaluated</span>`;

    const rows = run.diff_lines
        .map((row) => {
            const cls = `diff-row diff-${row.type}`;
            return `<div class="${cls}">
                <span class="diff-gutter">${row.right_line ?? ""}</span>
                <span class="diff-code">${escapeHtml(row.right_content)}</span>
            </div>`;
        })
        .join("");

    $("diffTableView").innerHTML =
        rows || '<p class="muted pad">No differences — the source was returned unchanged.</p>';
    updateLineCounts(run.original_code, run.modernized_code);
}

function updateLineCounts(original, modernized) {
    $("leftLineCount").textContent = `${original ? original.split("\n").length : 0} lines`;
    $("rightLineCount").textContent =
        modernized == null ? "awaiting run" : `${modernized.split("\n").length} lines`;
}

function statusChip(finding, run) {
    const ids = (list) => new Set((list || []).map((f) => f.id));
    if (ids(run.findings.resolved).has(finding.id)) return '<span class="chip chip-ok">resolved</span>';
    if (ids(run.findings.remaining).has(finding.id)) return '<span class="chip chip-warn">still present</span>';
    return "";
}

function renderFindings(run) {
    const buckets = run.issues;
    const card = (finding) => {
        const lines = (finding.lines || []).slice(0, 6).join(", ");
        const snippets = (finding.snippets || [])
            .map(
                (s) =>
                    `<div class="snippet"><span class="snippet-line">${s.line}</span><code>${escapeHtml(
                        s.text
                    )}</code></div>`
            )
            .join("");
        return `<article class="audit-card sev-${finding.severity.toLowerCase()}">
            <header class="audit-card-head">
                <span class="carbon-tag tag-${sevTag(finding.severity)}">${finding.severity}</span>
                <span class="rule-id">${escapeHtml(finding.cwe || finding.id)}</span>
                ${statusChip(finding, run)}
            </header>
            <h5>${escapeHtml(finding.title)}</h5>
            <p class="audit-desc">${escapeHtml(finding.description)}</p>
            ${lines ? `<p class="audit-lines">Line${finding.lines.length > 1 ? "s" : ""} ${lines}</p>` : ""}
            ${snippets}
            <p class="audit-fix"><strong>Fix:</strong> ${escapeHtml(finding.remediation)}</p>
        </article>`;
    };

    $("vulnList").innerHTML = buckets.vulnerabilities.length
        ? buckets.vulnerabilities.map(card).join("")
        : '<p class="muted pad">No security findings.</p>';
    $("depList").innerHTML = buckets.deprecations.length
        ? buckets.deprecations.map(card).join("")
        : '<p class="muted pad">No deprecation or quality findings.</p>';

    if (run.findings.introduced.length) {
        $("vulnList").insertAdjacentHTML(
            "afterbegin",
            `<div class="callout callout-bad">
                <strong>${run.findings.introduced.length} finding(s) introduced by this change.</strong>
                ${run.findings.introduced.map((f) => escapeHtml(f.title)).join("; ")}
             </div>`
        );
    }
}

function sevTag(severity) {
    return { CRITICAL: "error", HIGH: "error", MEDIUM: "warning", LOW: "info" }[severity] || "info";
}

function renderPlan(plan) {
    if (!plan.length) {
        $("reasoningPlanList").innerHTML = '<p class="muted pad">Nothing to remediate.</p>';
        return;
    }
    const statusChips = {
        resolved: '<span class="chip chip-ok">resolved</span>',
        unresolved: '<span class="chip chip-warn">not fixed automatically</span>',
        not_attempted: '<span class="chip">manual</span>',
        planned: '<span class="chip">planned</span>',
    };

    $("reasoningPlanList").innerHTML = plan
        .map(
            (step) => `<div class="plan-step status-${step.status}">
            <div class="plan-step-num">${step.priority}</div>
            <div class="plan-step-body">
                <div class="plan-step-head">
                    <span class="carbon-tag tag-${sevTag(step.severity)}">${step.severity}</span>
                    <span class="rule-id">${escapeHtml(step.cwe || step.rule_id)}</span>
                    ${statusChips[step.status] || ""}
                </div>
                <h5>${escapeHtml(step.action)}</h5>
                <p>${escapeHtml(step.detail)}</p>
                ${
                    step.lines && step.lines.length
                        ? `<p class="audit-lines">Line${step.lines.length > 1 ? "s" : ""} ${step.lines
                              .slice(0, 6)
                              .join(", ")}</p>`
                        : ""
                }
            </div>
        </div>`
        )
        .join("");
}

function renderVerification(run) {
    const v = run.verification;
    const icon = $("sandboxStatusIcon");
    const ok = v.verdict === "clean";
    icon.textContent = ok ? "✔" : v.verdict === "partial" ? "!" : "✕";
    icon.className = `status-indicator-box ${ok ? "success" : v.verdict === "partial" ? "warning" : "error"}`;

    $("sandboxStatusTitle").textContent = {
        clean: "Verified — every detected finding is gone",
        partial: "Sound output, some findings remain",
        rejected: "Rejected — output was not accepted",
    }[v.verdict];

    const bits = [
        `${v.passed_count} passed`,
        `${v.failed_count} failed`,
        `${v.skipped_count} skipped`,
        `${v.duration_ms}ms`,
        v.harness_executed ? "harness executed" : "harness NOT executed",
    ];
    if (v.execution_enabled) bits.push("code execution enabled");
    $("sandboxMetaLine").innerHTML = bits.map((b) => `<span>${escapeHtml(b)}</span>`).join("<span>·</span>");

    $("testCasesGrid").innerHTML = v.test_cases
        .map((testCase) => {
            const cls = testCase.status.toLowerCase();
            const expected = testCase.expected ? '<span class="chip chip-warn">known-unresolved</span>' : "";
            return `<div class="test-case case-${cls}">
                <div class="test-case-head">
                    <span class="case-status ${cls}">${testCase.status}</span>
                    <span class="case-time">${testCase.duration_ms}ms</span>
                    ${expected}
                </div>
                <div class="case-name">${escapeHtml(testCase.name)}</div>
                <div class="case-detail">${escapeHtml(testCase.detail || "")}</div>
            </div>`;
        })
        .join("");

    const harness = v.generated_tests || "";
    $("testCodeDisplay").textContent = harness || "No harness generated.";
    $("testCodeLabel").textContent = v.harness_executed
        ? "Generated regression harness (executed)"
        : "Generated regression harness (not executed this run)";

    if (run.native_tests) {
        $("testCodeNote").textContent =
            `A ${run.language} test skeleton was also generated for your own toolchain. ` +
            "It is not executed here — this process has no runtime for it.";
    }

    if (window.hljs) {
        try {
            window.hljs.highlightElement($("testCodeDisplay"));
        } catch (_) {
            /* highlighting is cosmetic */
        }
    }
}

function renderLog(logs) {
    $("logStream").innerHTML = logs
        .map(
            (entry) => `<div class="log-line">
            <span class="log-time">${escapeHtml(entry.timestamp)}</span>
            <span class="log-stage">${escapeHtml(entry.stage)}</span>
            <span class="log-agent">${escapeHtml(entry.agent)}</span>
            <span class="log-detail">${escapeHtml(entry.detail)}</span>
        </div>`
        )
        .join("");
}

// ── Export ───────────────────────────────────────────────────────────────────

function prRequestBody() {
    const run = state.run;
    return {
        filename: run.filename,
        diff_unified: run.diff_unified,
        metrics: run.metrics,
        findings: run.findings,
        verification: run.verification,
        synthesis: run.synthesis,
        language: run.language,
    };
}

async function openPRModal() {
    if (!state.run) return toast("Run an analysis first.", "error");
    try {
        const payload = await api("/api/export-pr", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(prRequestBody()),
        });
        $("prTitleInput").value = payload.title;
        $("prBranchInput").value = payload.branch_from;
        $("prBaseInput").value = payload.branch_to;
        $("prBodyTextarea").value = payload.body_markdown;
        const tag = $("prReadyTag");
        tag.textContent = payload.ready_to_merge ? "verified" : "needs review";
        tag.className = `carbon-tag ${payload.ready_to_merge ? "tag-success" : "tag-warning"}`;
        $("prModal").classList.add("active");
    } catch (err) {
        toast(`Could not build the payload: ${err.message}`, "error");
    }
}

async function downloadPatch() {
    if (!state.run) return toast("Run an analysis first.", "error");
    if (!state.run.diff_unified.trim()) return toast("No diff to export — nothing changed.", "error");

    try {
        const response = await fetch("/api/download-patch", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(prRequestBody()),
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `bobpulse-${state.run.filename}.patch`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
        toast("Patch downloaded.");
    } catch (err) {
        toast(`Download failed: ${err.message}`, "error");
    }
}

// ── Utilities ────────────────────────────────────────────────────────────────

function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function copy(text, message) {
    navigator.clipboard
        .writeText(text)
        .then(() => toast(message))
        .catch(() => toast("Clipboard unavailable.", "error"));
}

function toast(message, kind = "success") {
    const stack = $("toastStack");
    const element = document.createElement("div");
    element.className = `toast toast-${kind}`;
    element.textContent = message;
    stack.appendChild(element);
    setTimeout(() => element.classList.add("visible"), 10);
    setTimeout(() => {
        element.classList.remove("visible");
        setTimeout(() => element.remove(), 300);
    }, 3600);
}
