# BobPulse

Scans legacy source for security and maintainability defects, rewrites what it
can, and then **verifies its own output** by re-scanning it and executing
generated regression assertions.

The distinguishing property is that every number it reports is measured. Residual
technical debt comes from re-running the scan over the generated code, not from a
formula applied to the input. If a rewrite fixes nothing, the reported reduction
is 0%. If the output does not parse, the run is rejected rather than credited.

---

## What it does

```
source in
   │
   ├─ 1. Ingestion      real AST for Python (Python 2 files are normalised so
   │                    they still parse); keyword-based structural estimate for
   │                    the other languages, labelled as an estimate
   │
   ├─ 2. Rule scan      33 rules across 6 languages. Every finding carries the
   │                    line numbers where it matched and the source snippet
   │
   ├─ 3. Plan           findings ordered by severity, each with its remediation
   │
   ├─ 4. Synthesis      IBM watsonx Granite when credentials are present,
   │                    otherwise a deterministic source-to-source transformer
   │
   └─ 5. Verification   compile the output, re-scan it, diff the findings, and
                        run a generated pytest harness in a subprocess
                             │
                             ├─ rejected → feed the failure report back to the
                             │             model and retry (max 3 attempts)
                             └─ accepted → diff, metrics, PR payload
```

If no attempt survives verification, the original source is returned unchanged
with `modernization_applied: false`. It will not emit code it could not validate.

---

## Quickstart

Requires Python 3.10+ (tested on 3.13).

```bash
git clone https://github.com/MANGAJJAR/IBM-Hackathon.git
cd IBM-Hackathon
pip install -r requirements.txt
python run.py
```

- UI: <http://localhost:8000>
- OpenAPI docs: <http://localhost:8000/docs>

No credentials needed. Without them the deterministic transformer runs and every
analysis feature works.

### Optional: model-driven synthesis

```bash
pip install "ibm-watsonx-ai>=1.0,<2.0"
cp .env.example .env     # then fill in the two required values
```

| Variable | Where to get it |
| :-- | :-- |
| `IBM_WATSONX_APIKEY` | [IBM Cloud → API keys](https://cloud.ibm.com/iam/apikeys) — shown once, copy it |
| `IBM_WATSONX_PROJECT_ID` | [watsonx projects](https://dataplatform.cloud.ibm.com/projects) → your project → Manage → General |
| `IBM_WATSONX_URL` | Regional endpoint matching your project (default: Dallas) |

A watsonx.ai Runtime instance must be **associated with the project**, otherwise
inference returns 403. That step is easy to miss.

The model id is resolved at runtime against the models your account exposes, in
preference order. Pinning one is supported (`IBM_WATSONX_MODEL_ID`) but not
required — foundation models get withdrawn, and a hardcoded id eventually starts
returning 404.

Check what happened with `GET /api/health`:

```json
{ "synthesis": { "mode": "granite", "resolved_model_id": "ibm/granite-3-3-8b-instruct" } }
```

`mode` reads `rule-engine` whenever credentials or the SDK are missing. It never
claims a connection it does not have, and a failed model call is surfaced in the
response as `synthesis.granite_calls[].error` instead of being swallowed.

---

## How the numbers are produced

**Debt score.** Each rule carries a weight. The weights of matched rules are
summed, structural penalties are added (cyclomatic complexity; for Python, absent
type annotations or docstrings), and the total is normalised:

```
score = 100 × points ÷ (points + 60)
```

The full itemised breakdown ships in every response as `debt_breakdown`, so no
point in the score is unattributable.

**Residual debt and reduction.** The generated output goes back through the same
assessment. `debt_reduction_percent` is the difference between two measurements.
A finding counts as resolved only when it is absent from the re-scan, and
anything the rewrite *adds* is reported as `findings_introduced`.

**Verification.**

- Python output is compiled with `compile()`. Other languages get a bracket
  balance check, reported with `heuristic: true` because that is what it is.
- A pytest module is generated with one assertion per original finding and
  executed in a subprocess; results are read from pytest's JUnit XML. These
  assertions genuinely fail when a fix did not land — drop the harness into CI
  and it will keep the fix from being reverted.
- An assertion failing because a finding is genuinely unresolved is marked
  `expected` and yields a `partial` verdict, not a broken build.
- If the output does not parse, the comparison is flagged unreliable and **no
  resolutions are claimed**. This matters: unparseable Python makes every AST
  rule match nothing, which would otherwise look like a clean sweep.

**Effort avoided** is a severity-weighted estimate over resolved findings. It is
labelled as an estimate everywhere it appears.

---

## Example results

Produced by the deterministic transformer with no credentials configured, from
the bundled examples. Reproduce with `python tools/smoke_test.py`.

| Example | Language | Findings | Debt | Verdict |
| :-- | :-- | :-- | :-- | :-- |
| Java 8 batch processor | Java | 5 of 5 resolved | 67 → 0 (-100%) | `clean` |
| PHP 5 admin lookup | PHP | 4 of 4 resolved | 69 → 0 (-100%) | `clean` |
| Node.js upload handler | JavaScript | 2 of 2 resolved | 51 → 0 (-100%) | `clean` |
| Python 2 user service | Python | 6 of 7 resolved | 71 → 30 (-58%) | `partial` |
| TypeScript API route | TypeScript | 2 of 5 resolved | 63 → 48 (-24%) | `partial` |

The two `partial` rows are the interesting ones, and they are in the table
because leaving them out would misrepresent what the tool does.

For Python the transformer parameterises the SQL, replaces MD5, ports `urllib2`
to `requests`, narrows the bare `except`, guards the mutable default and converts
the `print` statement. It does not fix the SSRF, because validating a URL means
knowing which hosts are legitimate. That finding stays open, its assertion stays
red, and the plan says why.

For TypeScript it parameterises the template-literal SQL and replaces `var`,
then stops. The `eval()` needs a real dispatch table, the missing `.catch()`
needs an error destination the transformer cannot infer, and replacing `any`
needs actual types. Three findings, all left open and reported.

This is the case where a model earns its keep: with watsonx credentials
configured, these rewrites go to Granite first, and a rejected attempt comes back
with the verifier's report attached.

---

## API

| Endpoint | Purpose |
| :-- | :-- |
| `GET /api/health` | Computed service state: rule counts, synthesis mode, execution gate |
| `GET /api/rules` | The rule registry (`?language=` to filter) |
| `GET /api/examples` | Example legacy sources — inputs only, no stored outputs |
| `POST /api/scan` | Scan and score only. Cheap enough for live feedback |
| `POST /api/plan` | Remediation plan without synthesis |
| `POST /api/analyze` | Full pipeline |
| `POST /api/analyze/stream` | Same pipeline, progress as server-sent events |
| `POST /api/export-pr` | PR title, branch and Markdown body from measured results |
| `POST /api/download-patch` | Unified diff as a `.patch` attachment |

```bash
curl -s localhost:8000/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"code":"import md5\nd = md5.new(pw).hexdigest()\n","language":"python"}' \
  | python -m json.tool
```

The response reflects the code in the request. There is no path that substitutes
a stored answer for a named example.

---

## Rule coverage

33 rules. `GET /api/rules` returns the authoritative list with descriptions,
remediations, CWE ids and weights.

| Language | Rules | Examples |
| :-- | --: | :-- |
| Python | 12 | SQL injection via interpolation (AST-based, tracks the query through a variable), MD5/SHA-1, SSRF, hardcoded credentials, `shell=True`, unsafe deserialisation, `urllib2`, Python 2 `print`, mutable defaults, bare `except`, swallowed exceptions, missing HTTP timeout |
| Java | 6 | Concatenated SQL, thread-unsafe `SimpleDateFormat`, `Runtime.exec` concatenation, unbounded platform threads, JDBC leak, `printStackTrace` |
| JavaScript | 7 | `createCipher`, `eval`/`new Function`, template-literal SQL, shell interpolation, nested error-first callbacks, unhandled rejection, `var` |
| TypeScript | 8 | All JavaScript rules plus explicit `any` |
| Go | 3 | `Sprintf` SQL, MD5/SHA-1, unbounded goroutine fan-out |
| PHP | 4 | Interpolated query, command injection, MD5/SHA-1 passwords, `mysql_*` extension |

Rules never match inside comments — comment bodies are blanked before matching,
with offsets preserved so line numbers stay correct. String literals are kept,
because SQL text and hardcoded secrets live in them.

---

## What the transformer actually rewrites

Only changes it can apply safely. Anything else is left in place and reported as
unresolved — it will not claim a fix it did not make.

- **Python** — `%`-formatted SQL to `?` placeholders with the arguments moved
  into `execute()`; `md5`/`sha1` to `sha256`; `urllib2` to `requests` with a
  timeout and the response API adapted; bare `except` narrowed; mutable defaults
  to `None` plus an in-body guard (placed after any docstring); Python 2 `print`;
  missing HTTP timeouts.
- **Java** — `SimpleDateFormat` field to a `static final DateTimeFormatter`;
  concatenated `executeUpdate`/`executeQuery` to a `PreparedStatement` with
  positional setters; `new Thread(new Runnable(){…})` to
  `Executors.newVirtualThreadPerTaskExecutor()` inside try-with-resources; a
  `Connection` declared first in a `try` block promoted into its resource list;
  `printStackTrace` to structured logging.
- **JavaScript/TypeScript** — `createCipher` to `createCipheriv('aes-256-gcm')`
  with a scrypt-derived key, random IV and auth tag; template-literal SQL to
  positional placeholders with a values array; error-first `fs` callbacks
  flattened to `await fs.promises.*` with the body wrapped in try/catch
  delegating to `next(err)`; `var` to `let`.
- **Go** — `crypto/md5` and `crypto/sha1` to `crypto/sha256`; `Sprintf` queries
  to numbered placeholders.
- **PHP** — `mysql_connect`/`mysql_select_db` to a PDO handle; concatenated
  queries to `prepare`/`execute` with named parameters; `mysql_*` result helpers
  to PDO statement methods; `md5`/`sha1` to `password_hash` or explicit
  `hash('sha256', …)`; shell arguments wrapped in `escapeshellarg()`.

---

## Tests

```bash
pip install -r requirements-dev.txt
pytest                   # 247 tests, ~2.5 min (spawns real pytest subprocesses)
pytest -m "not slow"     # 196 tests, ~3 s
```

The suite covers rule detection against every example, explicit regressions for
each false positive that was fixed, the debt and comparison arithmetic, transform
correctness and stability, harness execution (including that it *fails* when a
finding survives), and every endpoint via `TestClient`.

Three properties are pinned down because they are the ones worth breaking a build
over:

- editing the input changes the output — no stored answers,
- unparseable output is rejected and claims no resolutions,
- a model failure is surfaced, not swallowed.

There is also `python tools/smoke_test.py`, which needs a running server and
prints a summary for every bundled example.

---

## Layout

```
backend/
  app.py              FastAPI routes; SSE wraps the same engine as /api/analyze
  engine.py           5-stage orchestrator, synthesis/verify retry loop, diffing
  rules.py            rule registry, AST + regex detectors, comment blanking
  transforms.py       deterministic source-to-source rewrites per language
  metrics.py          structural inspection, debt scoring, before/after compare
  granite.py          watsonx client: model resolution, repair prompts, errors
  sandbox.py          syntax checks, harness generation, subprocess execution
  patch_generator.py  PR payload built from measured results
  presets.py          example legacy sources (inputs only)
  source_utils.py     bracket matching and top-level splitting
frontend/             single-page UI (no build step, no framework)
samples/              the example sources as standalone files
tests/                pytest suite
tools/smoke_test.py   manual check against a running server
```

---

## Limits

Worth knowing before trusting a report:

- The scanner is rule-based. It finds patterns it knows about, not every defect,
  and it is not a substitute for a dedicated SAST tool.
- Only Python gets a real parse tree. Complexity and structure figures for the
  other five languages are keyword estimates, flagged as
  `complexity_estimated: true`.
- Transform coverage is uneven. Python, PHP and the specific Java and JavaScript
  shapes above are handled well; Go is thin.
- Generated JUnit / `node:test` / PHPUnit files are scaffolding for your own
  toolchain and are **never executed here** — this process has no JVM or Node
  runtime.
- The output is not executed unless `BOBPULSE_ALLOW_EXEC=1`, which runs the
  submitted source and should only be enabled in a container.
- There is no authentication or rate limiting. It is built to run locally; do not
  expose it as-is.
- Pull requests are not opened for you. BobPulse produces the payload and the
  patch; you create the PR with your own credentials.

---

## Licence

MIT — see [LICENSE](LICENSE).
