"""
BobPulse rule registry and scanner.
===================================

Every rule reports the *line numbers* where it matched, so findings can be
mapped back onto the source instead of being a file-level yes/no verdict.

Python rules are AST-based wherever the pattern is structural (SQL string
interpolation reaching a cursor, mutable default arguments, bare except
handlers). The remaining languages use anchored regular expressions.

Adding a rule
-------------
Append a :class:`Rule` to the module-level list for its language. ``detect``
receives a :class:`ScanContext` and returns the 1-based line numbers of every
occurrence. Return an empty list for "not present".
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from backend.source_utils import (
    call_arguments,
    is_string_literal,
    literal_body,
    match_bracket,
    split_top_level,
)

SUPPORTED_LANGUAGES: Tuple[str, ...] = (
    "python",
    "java",
    "javascript",
    "typescript",
    "go",
    "php",
)

#: Ordering used when sorting findings for display.
SEVERITY_RANK: Dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

#: Points contributed to the raw debt total, per severity, when a rule omits an
#: explicit ``debt`` weight.
DEFAULT_SEVERITY_DEBT: Dict[str, int] = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 14,
    "LOW": 8,
}

CATEGORY_VULNERABILITY = "vulnerability"
CATEGORY_DEPRECATION = "deprecation"
CATEGORY_QUALITY = "quality"


# ─────────────────────────────────────────────────────────────────────────────
#  Scan context
# ─────────────────────────────────────────────────────────────────────────────

_LINE_COMMENT_MARKERS: Dict[str, Tuple[str, ...]] = {
    "python": ("#",),
    "java": ("//",),
    "javascript": ("//",),
    "typescript": ("//",),
    "go": ("//",),
    "php": ("//", "#"),
}

_BLOCK_COMMENT_MARKERS: Dict[str, Tuple[str, str]] = {
    "java": ("/*", "*/"),
    "javascript": ("/*", "*/"),
    "typescript": ("/*", "*/"),
    "go": ("/*", "*/"),
    "php": ("/*", "*/"),
}


def blank_comments(code: str, language: str) -> str:
    """
    Return ``code`` with comment *bodies* replaced by spaces.

    Length, line count and every character offset are preserved, so line numbers
    computed against the result still refer to the original source.

    String literals are deliberately left intact: several rules need to look
    inside them (SQL text, hardcoded secrets). Comments are the only thing
    removed, because matching a rule against commented-out or explanatory text is
    always a false positive — a file that merely mentions ``urllib2`` in a note
    is not importing it.
    """
    line_markers = _LINE_COMMENT_MARKERS.get(language, ())
    block = _BLOCK_COMMENT_MARKERS.get(language)
    quote_chars = "\"'" + ("`" if language in ("javascript", "typescript") else "")

    out = list(code)
    i = 0
    length = len(code)

    def _blank(start: int, stop: int) -> None:
        for index in range(start, min(stop, length)):
            if out[index] != "\n":
                out[index] = " "

    while i < length:
        if language == "python" and (code.startswith('"""', i) or code.startswith("'''", i)):
            marker = code[i : i + 3]
            end = code.find(marker, i + 3)
            i = length if end == -1 else end + 3
            continue

        char = code[i]
        if char in quote_chars:
            i += 1
            while i < length:
                if code[i] == "\\":
                    i += 2
                    continue
                if code[i] == char:
                    i += 1
                    break
                if code[i] == "\n" and char != "`":
                    break
                i += 1
            continue

        if block and code.startswith(block[0], i):
            end = code.find(block[1], i + len(block[0]))
            stop = length if end == -1 else end + len(block[1])
            _blank(i, stop)
            i = stop
            continue

        matched_line_comment = False
        for marker in line_markers:
            if code.startswith(marker, i):
                end = code.find("\n", i)
                stop = length if end == -1 else end
                _blank(i, stop)
                i = stop
                matched_line_comment = True
                break
        if matched_line_comment:
            continue

        i += 1

    return "".join(out)


@dataclass
class ScanContext:
    """Everything a detector needs: the source, and a parsed tree when possible."""

    code: str
    language: str
    tree: Optional[ast.AST] = None
    parse_error: Optional[str] = None
    normalised_for_parse: bool = False
    _lines: Optional[List[str]] = field(default=None, repr=False)
    _scannable: Optional[str] = field(default=None, repr=False)

    @property
    def lines(self) -> List[str]:
        if self._lines is None:
            self._lines = self.code.splitlines()
        return self._lines

    @property
    def scannable(self) -> str:
        """The source with comment bodies blanked, offsets preserved."""
        if self._scannable is None:
            self._scannable = blank_comments(self.code, self.language)
        return self._scannable


_PY2_PRINT = re.compile(r"^(?P<indent>[ \t]*)print[ \t]+(?P<arg>[^(\s=][^\n]*?)[ \t]*$", re.MULTILINE)
_PY2_EXCEPT_COMMA = re.compile(r"^(?P<indent>[ \t]*)except[ \t]+(?P<exc>[\w.]+)[ \t]*,[ \t]*(?P<name>\w+)[ \t]*:", re.MULTILINE)


def normalise_python2(code: str) -> Tuple[str, bool]:
    """
    Rewrite the two Python 2 constructs that make ``ast.parse`` fail outright,
    so the rest of the AST rules still have a tree to work with.

    This rewrite is used for *analysis only* — it never becomes output.
    Returns ``(code, changed)``.
    """
    lifted = _PY2_PRINT.sub(lambda m: f"{m.group('indent')}print({m.group('arg')})", code)
    lifted = _PY2_EXCEPT_COMMA.sub(
        lambda m: f"{m.group('indent')}except {m.group('exc')} as {m.group('name')}:", lifted
    )
    return lifted, lifted != code


def build_context(code: str, language: str) -> ScanContext:
    """Parse ``code`` when it is Python, falling back to a Python 2 lift."""
    ctx = ScanContext(code=code, language=language)
    if language != "python":
        return ctx

    try:
        ctx.tree = ast.parse(code)
        return ctx
    except SyntaxError as exc:
        ctx.parse_error = f"line {exc.lineno}: {exc.msg}"

    lifted, changed = normalise_python2(code)
    if changed:
        try:
            ctx.tree = ast.parse(lifted)
            ctx.normalised_for_parse = True
        except SyntaxError:
            pass
    return ctx


# ─────────────────────────────────────────────────────────────────────────────
#  Rule definition
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    category: str
    title: str
    description: str
    remediation: str
    detect: Callable[[ScanContext], List[int]]
    languages: Tuple[str, ...]
    cwe: Optional[str] = None
    debt: Optional[int] = None

    @property
    def debt_points(self) -> int:
        if self.debt is not None:
            return self.debt
        return DEFAULT_SEVERITY_DEBT.get(self.severity, 10)


def _line_of(code: str, offset: int) -> int:
    return code.count("\n", 0, offset) + 1


def regex_detector(pattern: str, flags: int = 0) -> Callable[[ScanContext], List[int]]:
    """
    Build a detector that reports the line of every regex match.

    Matches against :attr:`ScanContext.scannable`, i.e. the source with comments
    blanked out, so explanatory prose never triggers a rule.
    """
    compiled = re.compile(pattern, flags)

    def _detect(ctx: ScanContext) -> List[int]:
        return sorted({_line_of(ctx.scannable, m.start()) for m in compiled.finditer(ctx.scannable)})

    return _detect


def absent(pattern: str, flags: int = 0) -> Callable[[ScanContext], List[int]]:
    """
    A guard detector: truthy only when ``pattern`` does **not** appear anywhere.

    Used with :func:`all_of` to express "X is present but Y is missing". The
    returned line number is a sentinel and is never reported on its own.
    """
    compiled = re.compile(pattern, flags)

    def _detect(ctx: ScanContext) -> List[int]:
        return [] if compiled.search(ctx.scannable) else [1]

    return _detect


def at_least(count: int, detector: Callable[[ScanContext], List[int]]) -> Callable[[ScanContext], List[int]]:
    """Only report when ``detector`` matched at least ``count`` times."""

    def _detect(ctx: ScanContext) -> List[int]:
        lines = detector(ctx)
        return lines if len(lines) >= count else []

    return _detect


def all_of(*detectors: Callable[[ScanContext], List[int]]) -> Callable[[ScanContext], List[int]]:
    """
    Report the *first* detector's lines, but only when every detector matches.

    Later detectors act as guards, so put the line-producing detector first.
    """

    def _detect(ctx: ScanContext) -> List[int]:
        results = [d(ctx) for d in detectors]
        if all(results):
            return results[0]
        return []

    return _detect


# ─────────────────────────────────────────────────────────────────────────────
#  Python AST detectors
# ─────────────────────────────────────────────────────────────────────────────

_SQL_MARKERS = ("SELECT ", "INSERT INTO", "UPDATE ", "DELETE FROM", "DROP TABLE")
_EXECUTE_METHODS = {"execute", "executemany", "executescript", "raw", "query"}
_HTTP_CALLS = {"urlopen", "get", "post", "put", "delete", "patch", "head", "request"}


def _unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover - defensive
        return ""


def _is_interpolated_string(node: ast.AST) -> bool:
    """True when ``node`` builds a string dynamically rather than as a literal."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(part, ast.FormattedValue) for part in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in {"format", "join"}:
            return True
    return False


def _looks_like_sql(node: ast.AST) -> bool:
    source = _unparse(node).upper()
    return any(marker in source for marker in _SQL_MARKERS)


def _looks_like_url(node: ast.AST) -> bool:
    source = _unparse(node).lower()
    return "http://" in source or "https://" in source


def _tainted_assignments(
    tree: ast.AST, predicate: Callable[[ast.AST], bool]
) -> Dict[str, int]:
    """Map variable name -> line, for names assigned an interpolated string."""
    tainted: Dict[str, int] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            continue
        value = node.value
        if value is None or not _is_interpolated_string(value) or not predicate(value):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                tainted[target.id] = node.lineno
    return tainted


def _called_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return node.func.id
    return ""


def detect_python_sql_injection(ctx: ScanContext) -> List[int]:
    """
    Flag SQL built by interpolation that reaches a cursor.

    Covers both the inline form ``cursor.execute("... %s" % user)`` and the
    two-step form where the query is assigned to a variable first.
    """
    if ctx.tree is None:
        return []

    tainted = _tainted_assignments(ctx.tree, _looks_like_sql)
    hits: set[int] = set()

    for node in ast.walk(ctx.tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        if _called_name(node) not in _EXECUTE_METHODS:
            continue
        first = node.args[0]
        if _is_interpolated_string(first) and _looks_like_sql(first):
            hits.add(node.lineno)
        elif isinstance(first, ast.Name) and first.id in tainted:
            # Report where the unsafe string was built and where it executes.
            hits.add(tainted[first.id])
            hits.add(node.lineno)

    return sorted(hits)


def detect_python_ssrf(ctx: ScanContext) -> List[int]:
    """Flag HTTP calls whose target URL is assembled from non-literal parts."""
    if ctx.tree is None:
        return []

    tainted = _tainted_assignments(ctx.tree, _looks_like_url)
    hits: set[int] = set()

    for node in ast.walk(ctx.tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        if _called_name(node) not in _HTTP_CALLS:
            continue
        target = node.args[0]
        if _is_interpolated_string(target) and _looks_like_url(target):
            hits.add(node.lineno)
        elif isinstance(target, ast.Name) and target.id in tainted:
            hits.add(node.lineno)

    return sorted(hits)


def detect_python_mutable_default(ctx: ScanContext) -> List[int]:
    """Flag ``def f(x={})`` / ``def f(x=[])`` style shared-state bugs."""
    if ctx.tree is None:
        return []

    hits: set[int] = set()
    for node in ast.walk(ctx.tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        defaults = list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]
        for default in defaults:
            if isinstance(default, (ast.Dict, ast.List, ast.Set)):
                hits.add(default.lineno)
            elif (
                isinstance(default, ast.Call)
                and isinstance(default.func, ast.Name)
                and default.func.id in {"dict", "list", "set"}
            ):
                hits.add(default.lineno)
    return sorted(hits)


def detect_python_bare_except(ctx: ScanContext) -> List[int]:
    """
    Flag ``except:`` only.

    ``except Exception:`` is deliberately *not* flagged here — it is a
    legitimate pattern at process boundaries and flagging it produced constant
    false positives.
    """
    if ctx.tree is None:
        return regex_detector(r"^[ \t]*except[ \t]*:", re.MULTILINE)(ctx)
    return sorted(
        {
            node.lineno
            for node in ast.walk(ctx.tree)
            if isinstance(node, ast.ExceptHandler) and node.type is None
        }
    )


def detect_python_swallowed_exception(ctx: ScanContext) -> List[int]:
    """Flag handlers whose entire body is ``pass`` — the error vanishes."""
    if ctx.tree is None:
        return []
    hits: set[int] = set()
    for node in ast.walk(ctx.tree):
        if isinstance(node, ast.ExceptHandler):
            if node.body and all(isinstance(stmt, ast.Pass) for stmt in node.body):
                hits.add(node.lineno)
    return sorted(hits)


def detect_python_request_without_timeout(ctx: ScanContext) -> List[int]:
    """Flag ``requests.get(...)`` / ``httpx.get(...)`` with no timeout kwarg."""
    if ctx.tree is None:
        return []

    hits: set[int] = set()
    for node in ast.walk(ctx.tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in {"get", "post", "put", "delete", "patch", "head", "request"}:
            continue
        root = node.func.value
        module = root.id if isinstance(root, ast.Name) else getattr(root, "attr", "")
        if module not in {"requests", "httpx", "session"}:
            continue
        if not any(kw.arg == "timeout" for kw in node.keywords):
            hits.add(node.lineno)
    return sorted(hits)


def detect_python_py2_print(ctx: ScanContext) -> List[int]:
    """Flag Python 2 ``print`` statements (a hard SyntaxError on Python 3)."""
    return regex_detector(
        r"^[ \t]*print[ \t]+(?![(=])", re.MULTILINE
    )(ctx)


# ─────────────────────────────────────────────────────────────────────────────
#  Python rules
# ─────────────────────────────────────────────────────────────────────────────

PY = ("python",)

PYTHON_RULES: List[Rule] = [
    Rule(
        id="PY-SEC-001",
        cwe="CWE-89",
        severity="CRITICAL",
        category=CATEGORY_VULNERABILITY,
        title="SQL injection via string interpolation",
        description=(
            "A SQL statement is assembled with %-formatting, an f-string, .format() or "
            "concatenation and then handed to a database cursor. Any user-controlled "
            "value in that string is executed as SQL."
        ),
        remediation=(
            "Pass values as parameters: cursor.execute('... WHERE id = ?', (user_id,)). "
            "Never build SQL with string formatting."
        ),
        debt=40,
        detect=detect_python_sql_injection,
        languages=PY,
    ),
    Rule(
        id="PY-SEC-002",
        cwe="CWE-327",
        severity="HIGH",
        category=CATEGORY_VULNERABILITY,
        title="Broken hash algorithm (MD5 / SHA-1)",
        description=(
            "MD5 and SHA-1 are collision-broken and far too fast for password storage. "
            "Digests are recoverable with commodity hardware."
        ),
        remediation=(
            "For passwords use a KDF such as hashlib.scrypt or argon2. For integrity "
            "use hashlib.sha256."
        ),
        debt=30,
        detect=regex_detector(
            r"hashlib\.(?:md5|sha1)\s*\(|^\s*import\s+md5\b|\bmd5\.new\s*\(", re.MULTILINE
        ),
        languages=PY,
    ),
    Rule(
        id="PY-SEC-003",
        cwe="CWE-918",
        severity="MEDIUM",
        category=CATEGORY_VULNERABILITY,
        title="Request URL assembled from untrusted input (SSRF)",
        description=(
            "The target URL of an outbound HTTP call is built at runtime. Without an "
            "allowlist an attacker can redirect the request at internal services."
        ),
        remediation=(
            "Validate the host against an allowlist before the call, and pin the base "
            "URL instead of concatenating user input into it."
        ),
        debt=18,
        detect=detect_python_ssrf,
        languages=PY,
    ),
    Rule(
        id="PY-SEC-004",
        cwe="CWE-798",
        severity="HIGH",
        category=CATEGORY_VULNERABILITY,
        title="Hardcoded credential",
        description=(
            "A password, token or API key is embedded in source. It stays recoverable "
            "in git history long after the line is deleted."
        ),
        remediation="Read the value from the environment or a secrets manager at runtime.",
        debt=30,
        # `\w*` before the keyword matters: real secrets are named DB_PASSWORD,
        # STRIPE_API_KEY, JWT_SECRET. A plain \b anchor misses all of them,
        # because the underscore is itself a word character.
        detect=regex_detector(
            r"(?i)\b\w*(?:password|passwd|secret|api_?key|access_?token|auth_?token)\s*"
            r"=\s*[\"'](?!your_|changeme|example|placeholder|\s*$)[^\"'\n]{6,}[\"']"
        ),
        languages=PY,
    ),
    Rule(
        id="PY-SEC-005",
        cwe="CWE-78",
        severity="CRITICAL",
        category=CATEGORY_VULNERABILITY,
        title="Shell command execution with shell=True",
        description=(
            "subprocess with shell=True passes the command through a shell, so any "
            "interpolated value can chain extra commands."
        ),
        remediation=(
            "Drop shell=True and pass the command as a list of arguments: "
            "subprocess.run(['git', 'log', ref])."
        ),
        debt=35,
        detect=regex_detector(r"shell\s*=\s*True"),
        languages=PY,
    ),
    Rule(
        id="PY-SEC-006",
        cwe="CWE-502",
        severity="HIGH",
        category=CATEGORY_VULNERABILITY,
        title="Unsafe deserialisation (yaml.load / pickle)",
        description=(
            "yaml.load without a safe loader, and pickle, both construct arbitrary "
            "Python objects. Loading untrusted data is remote code execution."
        ),
        remediation="Use yaml.safe_load(). For untrusted data interchange use JSON.",
        debt=28,
        detect=regex_detector(
            r"yaml\.load\s*\((?![^)]*Loader\s*=)|pickle\.loads?\s*\("
        ),
        languages=PY,
    ),
    Rule(
        id="PY-DEP-001",
        severity="HIGH",
        category=CATEGORY_DEPRECATION,
        title="urllib2 was removed in Python 3",
        description=(
            "urllib2 does not exist on any supported Python. The module also lacks "
            "connection pooling and sane TLS defaults."
        ),
        remediation="Use requests.Session() or httpx.Client() with an explicit timeout.",
        debt=20,
        detect=regex_detector(r"\burllib2\b"),
        languages=PY,
    ),
    Rule(
        id="PY-DEP-002",
        severity="LOW",
        category=CATEGORY_DEPRECATION,
        title="Python 2 print statement",
        description=(
            "`print x` is a SyntaxError on Python 3. The file cannot be imported at all "
            "until it is converted."
        ),
        remediation="Convert to the print() function.",
        debt=10,
        detect=detect_python_py2_print,
        languages=PY,
    ),
    Rule(
        id="PY-QUAL-001",
        severity="MEDIUM",
        category=CATEGORY_QUALITY,
        title="Mutable default argument",
        description=(
            "A dict/list/set default is created once at definition time and shared by "
            "every call, so state leaks between unrelated callers."
        ),
        remediation="Default to None and build the container inside the function body.",
        debt=15,
        detect=detect_python_mutable_default,
        languages=PY,
    ),
    Rule(
        id="PY-QUAL-002",
        severity="MEDIUM",
        category=CATEGORY_QUALITY,
        title="Bare except clause",
        description=(
            "`except:` also catches KeyboardInterrupt and SystemExit, so the process "
            "becomes impossible to interrupt and real bugs are hidden."
        ),
        remediation="Catch the specific exception types the block can actually handle.",
        debt=12,
        detect=detect_python_bare_except,
        languages=PY,
    ),
    Rule(
        id="PY-QUAL-003",
        severity="LOW",
        category=CATEGORY_QUALITY,
        title="Exception silently discarded",
        description="The handler body is only `pass`, so the failure leaves no trace at all.",
        remediation="Log the exception with logging.exception() or re-raise it.",
        debt=8,
        detect=detect_python_swallowed_exception,
        languages=PY,
    ),
    Rule(
        id="PY-QUAL-004",
        severity="MEDIUM",
        category=CATEGORY_QUALITY,
        title="HTTP call without a timeout",
        description=(
            "requests and httpx block forever by default. One slow upstream is enough "
            "to exhaust the worker pool."
        ),
        remediation="Always pass timeout=<seconds>.",
        debt=12,
        detect=detect_python_request_without_timeout,
        languages=PY,
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
#  Java rules
# ─────────────────────────────────────────────────────────────────────────────

JAVA = ("java",)

JAVA_RULES: List[Rule] = [
    Rule(
        id="JAVA-SEC-001",
        cwe="CWE-89",
        severity="CRITICAL",
        category=CATEGORY_VULNERABILITY,
        title="SQL injection via concatenated statement",
        description=(
            "A query string is concatenated and passed to Statement.execute*(), so "
            "interpolated values are parsed as SQL."
        ),
        remediation=(
            "Use PreparedStatement with ? placeholders and setString/setLong for each value."
        ),
        debt=40,
        detect=regex_detector(
            r"execute(?:Update|Query|)\s*\(\s*\"[^\"]*\"\s*\+|"
            r"execute(?:Update|Query|)\s*\([^;]*\+\s*\w+\s*\)"
        ),
        languages=JAVA,
    ),
    Rule(
        id="JAVA-SEC-002",
        cwe="CWE-362",
        severity="HIGH",
        category=CATEGORY_VULNERABILITY,
        title="Thread-unsafe SimpleDateFormat",
        description=(
            "SimpleDateFormat keeps mutable parsing state. Shared between threads it "
            "silently produces wrong dates or throws under load."
        ),
        remediation=(
            "Use java.time: a static final DateTimeFormatter is immutable and thread-safe."
        ),
        debt=28,
        detect=regex_detector(r"\bSimpleDateFormat\b"),
        languages=JAVA,
    ),
    Rule(
        id="JAVA-SEC-003",
        cwe="CWE-78",
        severity="CRITICAL",
        category=CATEGORY_VULNERABILITY,
        title="Command execution with concatenated arguments",
        description="Runtime.exec / ProcessBuilder is invoked with a concatenated string.",
        remediation="Pass an argument array and validate each element against an allowlist.",
        debt=35,
        detect=regex_detector(r"(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\([^)]*\+"),
        languages=JAVA,
    ),
    Rule(
        id="JAVA-DEP-001",
        severity="HIGH",
        category=CATEGORY_DEPRECATION,
        title="Unbounded platform thread creation",
        description=(
            "`new Thread(...)` per task maps one OS thread per unit of work. Under load "
            "this exhausts kernel threads and stalls the JVM."
        ),
        remediation=(
            "Use Executors.newVirtualThreadPerTaskExecutor() on Java 21+, or a bounded "
            "thread pool on older runtimes."
        ),
        debt=25,
        detect=regex_detector(r"new\s+Thread\s*\("),
        languages=JAVA,
    ),
    Rule(
        id="JAVA-QUAL-001",
        severity="HIGH",
        category=CATEGORY_QUALITY,
        title="JDBC resource leak",
        description=(
            "A Connection is obtained without try-with-resources, so a thrown exception "
            "leaks the connection and eventually drains the pool."
        ),
        remediation="Acquire Connection and Statement inside a try-with-resources block.",
        debt=20,
        # The guard must check that the *connection itself* is a try-with-resources
        # resource. Merely finding `try (` somewhere in the file is not enough —
        # an unrelated try-with-resources elsewhere would mask a real leak.
        detect=all_of(
            regex_detector(r"getConnection\s*\("),
            absent(r"try\s*\([^)]*getConnection|try\s*\(\s*(?:final\s+)?Connection\b"),
        ),
        languages=JAVA,
    ),
    Rule(
        id="JAVA-QUAL-002",
        severity="LOW",
        category=CATEGORY_QUALITY,
        title="printStackTrace() instead of structured logging",
        description=(
            "Stack traces on stderr are invisible to log aggregation and carry no "
            "correlation context."
        ),
        remediation="Log through the application logger with the request context attached.",
        debt=8,
        detect=regex_detector(r"\.printStackTrace\s*\("),
        languages=JAVA,
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
#  JavaScript / TypeScript rules
# ─────────────────────────────────────────────────────────────────────────────

JSTS = ("javascript", "typescript")

JS_RULES: List[Rule] = [
    Rule(
        id="JS-SEC-001",
        cwe="CWE-327",
        severity="CRITICAL",
        category=CATEGORY_VULNERABILITY,
        title="Deprecated crypto.createCipher()",
        description=(
            "createCipher derives the key with a single unsalted MD5 pass and uses a "
            "zero IV, so identical plaintexts produce identical ciphertexts."
        ),
        remediation=(
            "Use crypto.createCipheriv('aes-256-gcm', key, crypto.randomBytes(12)) with "
            "a scrypt-derived key, and store the auth tag."
        ),
        debt=40,
        detect=regex_detector(r"createCipher\s*\(|createDecipher\s*\("),
        languages=JSTS,
    ),
    Rule(
        id="JS-SEC-002",
        cwe="CWE-95",
        severity="HIGH",
        category=CATEGORY_VULNERABILITY,
        title="Dynamic code execution via eval / new Function",
        description="Evaluating strings as code turns any injected value into execution.",
        remediation="Parse data with JSON.parse; replace dynamic dispatch with a lookup map.",
        debt=30,
        detect=regex_detector(r"\beval\s*\(|new\s+Function\s*\("),
        languages=JSTS,
    ),
    Rule(
        id="JS-SEC-003",
        cwe="CWE-89",
        severity="CRITICAL",
        category=CATEGORY_VULNERABILITY,
        title="SQL injection via template literal or concatenation",
        description=(
            "A query is built with a `${}` template literal or + concatenation and then "
            "executed, so interpolated values are parsed as SQL."
        ),
        remediation="Use parameterised queries: db.query('… WHERE id = $1', [id]).",
        debt=40,
        detect=all_of(
            regex_detector(r"\.(?:query|execute|run|all|get)\s*\("),
            regex_detector(r"(?i)(?:select |insert into|update |delete from)"),
            regex_detector(r"\$\{|\"\s*\+|'\s*\+"),
        ),
        languages=JSTS,
    ),
    Rule(
        id="JS-SEC-004",
        cwe="CWE-78",
        severity="CRITICAL",
        category=CATEGORY_VULNERABILITY,
        title="Shell execution with interpolated input",
        description="child_process.exec runs its argument through a shell.",
        remediation="Use execFile/spawn with an argument array instead of exec.",
        debt=35,
        detect=regex_detector(r"(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)"),
        languages=JSTS,
    ),
    Rule(
        id="JS-DEP-001",
        severity="HIGH",
        category=CATEGORY_DEPRECATION,
        title="Nested error-first callbacks",
        description=(
            "Stacked callbacks cannot be wrapped in try/catch, so each level needs its "
            "own error branch and one missed branch loses the failure."
        ),
        remediation="Convert to async/await over fs.promises or util.promisify.",
        debt=22,
        # A single error-first callback is idiomatic; two or more nested ones are
        # what makes error handling unreliable, so require at least two.
        detect=at_least(
            2, regex_detector(r"function\s*\(\s*\w*(?:err|error)\w*\b", re.IGNORECASE)
        ),
        languages=JSTS,
    ),
    Rule(
        id="JS-QUAL-001",
        severity="MEDIUM",
        category=CATEGORY_QUALITY,
        title="Promise chain without rejection handling",
        description=(
            "A .then() with no .catch() produces an unhandled rejection, which "
            "terminates the process on modern Node."
        ),
        remediation="Append .catch(), or await inside try/catch.",
        debt=16,
        detect=all_of(
            regex_detector(r"\.then\s*\("),
            absent(r"\.catch\s*\(|await\s"),
        ),
        languages=JSTS,
    ),
    Rule(
        id="JS-QUAL-002",
        severity="LOW",
        category=CATEGORY_QUALITY,
        title="var declaration",
        description="var is function-scoped and hoisted, which leaks bindings out of blocks.",
        remediation="Use const, or let where reassignment is required.",
        debt=8,
        detect=regex_detector(r"^\s*var\s+\w", re.MULTILINE),
        languages=JSTS,
    ),
    Rule(
        id="TS-QUAL-001",
        severity="LOW",
        category=CATEGORY_QUALITY,
        title="Explicit any annotation",
        description="`any` opts the value out of type checking entirely.",
        remediation="Use a concrete type, or `unknown` plus narrowing.",
        debt=10,
        detect=regex_detector(r":\s*any\b"),
        languages=("typescript",),
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
#  Go rules
# ─────────────────────────────────────────────────────────────────────────────

GO = ("go",)

GO_RULES: List[Rule] = [
    Rule(
        id="GO-SEC-001",
        cwe="CWE-89",
        severity="CRITICAL",
        category=CATEGORY_VULNERABILITY,
        title="SQL injection via fmt.Sprintf",
        description="Formatting a query with Sprintf splices values straight into SQL.",
        remediation="Use db.QueryContext(ctx, '… WHERE id = $1', id) with placeholders.",
        debt=40,
        detect=all_of(
            regex_detector(r"fmt\.Sprintf\s*\("),
            regex_detector(r"(?i)(?:select |insert into|update |delete from)"),
        ),
        languages=GO,
    ),
    Rule(
        id="GO-SEC-002",
        cwe="CWE-327",
        severity="HIGH",
        category=CATEGORY_VULNERABILITY,
        title="Broken hash algorithm (MD5 / SHA-1)",
        description="crypto/md5 and crypto/sha1 are collision-broken.",
        remediation="Use crypto/sha256, or golang.org/x/crypto/bcrypt for passwords.",
        debt=28,
        detect=regex_detector(r"crypto/(?:md5|sha1)|\bmd5\.(?:New|Sum)\b"),
        languages=GO,
    ),
    Rule(
        id="GO-QUAL-001",
        severity="LOW",
        category=CATEGORY_QUALITY,
        title="Unbounded goroutine fan-out",
        description=(
            "Launching a goroutine per item with no limit lets a large input exhaust "
            "memory and downstream connections."
        ),
        remediation="Bound concurrency with errgroup.SetLimit or a semaphore channel.",
        debt=10,
        detect=regex_detector(r"go\s+func\s*\("),
        languages=GO,
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
#  PHP rules
# ─────────────────────────────────────────────────────────────────────────────

PHP = ("php",)

_PHP_QUERY_CALL = re.compile(r"(?:mysql_query|mysqli_query|pg_query|pg_send_query|->query)\s*\(")
_PHP_SHELL_CALL = re.compile(r"\b(?:exec|system|shell_exec|passthru|popen|proc_open)\s*\(")
_PHP_VARIABLE = re.compile(r"\$\w+|\$_(?:GET|POST|REQUEST|COOKIE)\b")


def _php_unsafe_parts(arguments: str) -> bool:
    """
    True when any concatenated part of ``arguments`` is an unescaped variable.

    Parts already wrapped in an escaping/binding helper are treated as safe, so
    a fixed call stops matching. A rule that can never be satisfied is worse
    than no rule.
    """
    for part in split_top_level(arguments, "."):
        stripped = part.strip()
        if not _PHP_VARIABLE.search(stripped):
            # Also catch "text $var text" double-quoted interpolation.
            if is_string_literal(stripped) and stripped.startswith('"'):
                if _PHP_VARIABLE.search(literal_body(stripped)):
                    return True
            continue
        if re.match(r"(?:escapeshellarg|escapeshellcmd|intval|floatval|\(int\))\s*\(?", stripped):
            continue
        return True
    return False


def _php_call_detector(pattern: re.Pattern) -> Callable[[ScanContext], List[int]]:
    """Flag calls matching ``pattern`` whose arguments interpolate a variable."""

    def _detect(ctx: ScanContext) -> List[int]:
        source = ctx.scannable
        hits: List[int] = []
        for match in pattern.finditer(source):
            arguments = call_arguments(source, match.start())
            if arguments and _php_unsafe_parts(arguments):
                hits.append(_line_of(source, match.start()))
        return sorted(set(hits))

    return _detect


PHP_RULES: List[Rule] = [
    Rule(
        id="PHP-SEC-001",
        cwe="CWE-89",
        severity="CRITICAL",
        category=CATEGORY_VULNERABILITY,
        title="SQL injection via interpolated query",
        description=(
            "A query string is built by concatenating or interpolating a PHP "
            "variable and then executed directly, so request data is parsed as SQL."
        ),
        remediation=(
            "Use PDO::prepare() with named parameters and pass values through "
            "execute(), so the query text never contains user data."
        ),
        debt=45,
        detect=_php_call_detector(_PHP_QUERY_CALL),
        languages=PHP,
    ),
    Rule(
        id="PHP-SEC-002",
        cwe="CWE-78",
        severity="CRITICAL",
        category=CATEGORY_VULNERABILITY,
        title="Command execution with interpolated input",
        description=(
            "A shell helper receives a string containing an unescaped PHP "
            "variable, so the value can terminate the command and start another."
        ),
        remediation=(
            "Avoid shell helpers. Where unavoidable, wrap every interpolated "
            "value in escapeshellarg()."
        ),
        debt=40,
        detect=_php_call_detector(_PHP_SHELL_CALL),
        languages=PHP,
    ),
    Rule(
        id="PHP-SEC-003",
        cwe="CWE-916",
        severity="HIGH",
        category=CATEGORY_VULNERABILITY,
        title="Password hashed with md5 / sha1",
        description="Fast general-purpose hashes are unsuitable for credential storage.",
        remediation="Use password_hash($pw, PASSWORD_DEFAULT) and password_verify().",
        debt=25,
        detect=regex_detector(r"\b(?:md5|sha1)\s*\("),
        languages=PHP,
    ),
    Rule(
        id="PHP-DEP-001",
        severity="HIGH",
        category=CATEGORY_DEPRECATION,
        title="mysql_* extension removed in PHP 7",
        description="The original mysql_ extension no longer exists on any supported PHP.",
        remediation="Migrate to PDO or mysqli with prepared statements.",
        debt=25,
        detect=regex_detector(r"\bmysql_(?:query|connect|fetch_\w+|real_escape_string)\s*\("),
        languages=PHP,
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
#  Registry
# ─────────────────────────────────────────────────────────────────────────────

ALL_RULES: List[Rule] = [
    *PYTHON_RULES,
    *JAVA_RULES,
    *JS_RULES,
    *GO_RULES,
    *PHP_RULES,
]

RULES_BY_LANGUAGE: Dict[str, List[Rule]] = {
    language: [rule for rule in ALL_RULES if language in rule.languages]
    for language in SUPPORTED_LANGUAGES
}


def rules_for(language: str) -> List[Rule]:
    return RULES_BY_LANGUAGE.get(language, [])


def rule_count() -> int:
    """Number of distinct rules in the registry."""
    return len(ALL_RULES)


def finding_dict(rule: Rule, lines: Sequence[int], source_lines: Sequence[str]) -> Dict:
    """Serialise a match into the shape the API and UI consume."""
    snippets = []
    for line_no in list(lines)[:5]:
        index = line_no - 1
        if 0 <= index < len(source_lines):
            snippets.append({"line": line_no, "text": source_lines[index].rstrip()[:200]})
    return {
        "id": rule.id,
        "cwe": rule.cwe,
        "severity": rule.severity,
        "category": rule.category,
        "title": rule.title,
        "description": rule.description,
        "remediation": rule.remediation,
        "debt": rule.debt_points,
        "lines": list(lines),
        "occurrences": len(lines),
        "snippets": snippets,
    }


def scan(code: str, language: str, ctx: Optional[ScanContext] = None) -> List[Dict]:
    """
    Run every rule registered for ``language`` against ``code``.

    Returns findings sorted by severity then by first line, each carrying the
    line numbers where it matched.
    """
    context = ctx or build_context(code, language)
    source_lines = context.lines
    findings: List[Dict] = []

    for rule in rules_for(language):
        try:
            lines = rule.detect(context)
        except Exception:  # a broken rule must not take down the scan
            continue
        if lines:
            findings.append(finding_dict(rule, lines, source_lines))

    findings.sort(
        key=lambda f: (SEVERITY_RANK.get(f["severity"], 9), f["lines"][0] if f["lines"] else 0)
    )
    return findings


def split_findings(findings: Sequence[Dict]) -> Dict[str, List[Dict]]:
    """
    Split a finding list into the two buckets the UI renders.

    Vulnerabilities are security findings; deprecations covers removed APIs and
    code-quality debt.
    """
    return {
        "vulnerabilities": [f for f in findings if f["category"] == CATEGORY_VULNERABILITY],
        "deprecations": [f for f in findings if f["category"] != CATEGORY_VULNERABILITY],
    }
