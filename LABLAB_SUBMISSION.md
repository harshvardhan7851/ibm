# LabLab.ai submission copy

Draft text for the submission form, plus a demo script.

**Every figure below is reproducible.** Run `python run.py`, then
`python tools/smoke_test.py`, and you will get the numbers quoted here. If you
change the rules or transforms, re-run it and update this file — a judge who
pastes their own code and gets a different story than the write-up promised is
the fastest way to lose credibility.

Sections marked **[FILL IN]** need your own facts. Do not ship them as-is.

---

## 1. Problem & solution (~330 words)

### The problem

Legacy code is expensive because the risky part is not writing the fix, it is
proving the fix is safe. A team looking at a Python 2 service with SQL injection,
MD5 password hashing and a removed HTTP library faces three separate problems:

1. **Finding everything.** Grep-level searches miss defects that only appear
   structurally — a query assembled in one statement and executed in another.
2. **Fixing without breaking.** Manual refactors introduce regressions, and the
   reviewer has no cheap way to tell a real fix from a plausible-looking one.
3. **Trusting the tooling.** AI code generators emit rewrites with no evidence.
   "Here is your modernized file" is not a claim anyone can verify, and confident
   tools that are quietly wrong are worse than no tool.

### The solution: BobPulse

BobPulse scans legacy source, rewrites what it safely can, and then **verifies
its own output**. The design constraint throughout was that the tool must not be
able to overstate what it did.

1. **Line-accurate scanning.** 33 rules across 6 languages. Python defects are
   found with a real AST — SQL injection detection tracks a query through an
   intermediate variable to the cursor. Python 2 files are normalised first so
   they still parse. Comment bodies are blanked before matching, so a file that
   merely mentions `urllib2` in a note is not reported as importing it.
2. **Deterministic or model-driven rewriting.** With IBM watsonx credentials,
   synthesis goes through IBM Granite; without them a deterministic transformer
   runs. Either way the output is treated as a candidate, not an answer.
3. **Verification that can fail.** The output is compiled, re-scanned, and run
   against a generated pytest harness with one assertion per original finding.
   Those assertions genuinely fail when a fix did not land.
4. **A retry loop.** A rejected candidate goes back to the model with the
   verifier's report attached. If no attempt survives, BobPulse returns the
   original source unchanged and says so.
5. **Measured reporting.** Residual debt comes from re-scanning the output. A
   rewrite that fixes nothing reports a 0% reduction. Anything the rewrite breaks
   is reported as newly introduced.

Reproducible results on the five bundled examples: Java 5/5 findings resolved,
PHP 4/4, Node.js 2/2, Python 6/7, TypeScript 2/5. The last two are honest
partials — the unresolved findings need judgement the transformer does not have,
and BobPulse reports them as open rather than claiming them.

---

## 2. IBM Bob usage statement (~300 words)

> **[FILL IN]** — this section must describe what *you* actually did. The notes
> below are a truthful skeleton; replace the bracketed parts with specifics and
> delete anything that did not happen. Do not claim integrations the repository
> does not contain.

### Building BobPulse with IBM Bob 2.0

**[FILL IN: where you used Bob during development.]** For example: which files
you scaffolded with it, which bugs you diagnosed with it, which refactors it
performed. Be specific and concrete — "used Bob to scaffold the FastAPI routing
layer and to work through the bracket-matching logic in `source_utils.py`" is
worth more than a round hours-saved figure you cannot substantiate.

### IBM watsonx Granite at runtime

BobPulse integrates IBM watsonx.ai as its synthesis engine (`backend/granite.py`).
Three details of that integration are worth calling out:

- **The model is resolved at runtime.** Foundation models get withdrawn; an
  earlier revision of this project hardcoded `ibm/granite-20b-code-instruct`,
  which was removed from the multitenant service and made every call fail
  silently. BobPulse now queries the models the account actually exposes and
  selects from a preference list, with `IBM_WATSONX_MODEL_ID` as an override.
- **Failures are reported, not swallowed.** A failed call surfaces in the API
  response as `synthesis.granite_calls[].error` and in the UI as a banner. The
  run then falls back to the deterministic transformer and labels itself
  accordingly.
- **The model is inside a verification loop.** Granite output is compiled,
  re-scanned and tested before it is accepted. A rejected rewrite is sent back
  with the specific complaint — the failing assertion or the syntax error — which
  is what makes the "self-healing" description literal rather than decorative.

### Honest scope

BobPulse does not use MCP, does not open pull requests, and does not execute
generated code unless explicitly enabled. Those are absent from the repository
and therefore absent from this statement.

---

## 3. Demo script (~2:40)

Run `python run.py` first. Recording with no `.env` is fine and arguably better —
it shows the tool works standalone. If you record with credentials, show the
Granite model id in the sidebar.

| Time | On screen | Narration |
| :-- | :-- | :-- |
| **0:00–0:18** | Title, then the BobPulse UI | "BobPulse scans legacy code, rewrites what it can, and then verifies its own output. The interesting part is that last step — it is built so it cannot overstate what it fixed." |
| **0:18–0:42** | Load *Python 2 user service*. Hover the findings tab. | "A Python 2 service. Seven findings, each with line numbers: SQL injection built by string formatting on line 16 and executed on 17, MD5 hashing, `urllib2`, a mutable default, a bare `except`, a print statement. Debt score 71 — and the breakdown panel shows exactly which rule contributed each point." |
| **0:42–1:05** | Click **Analyse**. Let the five stages run. | "Five stages: parse, scan, plan, synthesise, verify. No credentials here, so the deterministic transformer does the rewriting. With watsonx configured this step goes to IBM Granite instead." |
| **1:05–1:32** | Side-by-side diff, then the findings tab. | "The SQL is parameterised and the arguments moved into `execute`. MD5 became SHA-256. `urllib2` became `requests` with a timeout, and the response API was adapted. Debt 71 down to 30 — and that 30 is measured by re-scanning the output, not estimated." |
| **1:32–2:00** | Verification tab. Point at the failed assertion. | "Here is the part I want to show you. Eight of nine checks pass. One fails — the SSRF finding is still there, because validating a URL needs to know which hosts are legitimate. So the verdict is *partial*, the assertion is red, and it is labelled known-unresolved. The tool is telling on itself." |
| **2:00–2:20** | Paste your own snippet. Analyse. | "And it is analysing real input, not replaying a canned demo. Here is code I just pasted — different findings, different diff, different numbers." |
| **2:20–2:40** | PR modal, then closing slide. | "The pull request body is generated from those measurements, including what is still open. BobPulse doesn't open the PR — it has no credentials — it hands you the payload and the patch. Thanks for watching." |

The `partial` result at 1:32 is the strongest moment in the demo. A tool that
reports 100% every time is a tool nobody should trust.

---

## 4. Evidence checklist

Screenshots to attach:

1. **Findings tab** — line numbers and source snippets per finding.
2. **Debt breakdown panel** — every point attributed to a named source.
3. **Verification tab** — the passing checks *and* the known-unresolved failure.
4. **Run log** — the five stage entries with real timings.
5. **Sidebar status** — Granite model id if you configured credentials, or
   "Rule engine (deterministic)" if you did not. Either is fine; both are true.
6. **PR modal** — the generated body with the "Still open" section visible.

Also worth including, since it is unusual for a hackathon entry:

7. **`pytest` output** — 247 tests passing, including regressions proving that
   unparseable output is rejected and that a model failure is surfaced rather
   than hidden.

Do **not** screenshot a claim the software does not make. There is no
"connected" badge to capture, because the UI reports `rule-engine` unless
credentials are actually present.

---

## 5. Pre-submission checks

```bash
pytest                      # 247 tests
python run.py               # then, in another terminal:
python tools/smoke_test.py  # confirms every example and that input drives output
```

- [ ] Numbers in this file match `tools/smoke_test.py` output
- [ ] README example table matches too
- [ ] `.env` is not committed (it is in `.gitignore`)
- [ ] Demo recorded with code you paste live, not only a bundled example
- [ ] MIT `LICENSE` present
- [ ] **[FILL IN]** section 2 replaced with your actual usage
