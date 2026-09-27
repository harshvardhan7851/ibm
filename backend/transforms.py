"""
BobPulse mechanical transformer.
================================

Deterministic, local source-to-source fixes. No model involved.

Design rule: a transform either applies cleanly or does nothing. It never
guesses at a partial rewrite, because the output is re-scanned afterwards and a
half-applied transform would report as a resolved finding while leaving the
defect in place.

Anything this module cannot fix stays in the source and is reported as an
unresolved finding. Structural refactors (splitting monoliths, restructuring
control flow across many call sites) are deliberately out of scope here — that
is what the Granite synthesis path is for.

Every function returns ``(code, notes)`` where ``notes`` describes what was
actually changed, so the pipeline can report real work instead of a fixed
script.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

from backend.rules import normalise_python2

# Re-exported so callers and tests can reach them from this module too.
from backend.source_utils import (  # noqa: F401
    indent_of as _indent_of,
    is_string_literal,
    literal_body,
    match_bracket,
    split_top_level,
)

Notes = List[str]


# ─────────────────────────────────────────────────────────────────────────────
#  Python
# ─────────────────────────────────────────────────────────────────────────────

# Deliberately single-line (no DOTALL): the SQL literal and the `%` operand must
# sit on one logical line. A DOTALL version here is greedy across the whole file.
#
# Stops at the `%` rather than requiring `% (`, because the single-argument form
# `"… %s" % name` has no parentheses and is at least as common as the tuple form.
_SQL_ASSIGN_HEAD = re.compile(
    r"^(?P<indent>[ \t]*)(?P<var>\w+)\s*=\s*"
    r"(?P<quote>\"|')(?P<sql>(?:(?!(?P=quote)).)*?)(?P=quote)"
    r"\s*%\s*",
    re.MULTILINE,
)

_SQL_MARKERS = ("SELECT", "INSERT INTO", "UPDATE ", "DELETE FROM")
_PLACEHOLDER = re.compile(r"'%[sdfr]'|\"%[sdfr]\"|%[sdfr]")


def _python_parameterise_sql(code: str) -> Tuple[str, Notes]:
    """
    Turn ``q = "... '%s'" % (a, b)`` plus ``execute(q)`` into a parameterised pair.

    Placeholders become ``?`` and the formatting arguments move into the
    ``execute`` call, which is what actually removes the injection.
    """
    notes: Notes = []
    params: Dict[str, str] = {}
    updated = code
    search_from = 0

    while True:
        match = _SQL_ASSIGN_HEAD.search(updated, search_from)
        if not match:
            break

        sql = match.group("sql")
        if not any(marker in sql.upper() for marker in _SQL_MARKERS) or not _PLACEHOLDER.search(sql):
            search_from = match.end()
            continue

        operand_start = match.end()
        if operand_start < len(updated) and updated[operand_start] == "(":
            # Tuple form: "… %s, %s" % (a, b)
            close_index = match_bracket(updated, operand_start)
            if close_index == -1:
                search_from = match.end()
                continue
            arguments = updated[operand_start + 1 : close_index].strip()
            statement_end = close_index + 1
        else:
            # Single-argument form: "… %s" % name
            newline = updated.find("\n", operand_start)
            statement_end = len(updated) if newline == -1 else newline
            arguments = updated[operand_start:statement_end]
            # Drop a trailing comment so it does not become part of the operand.
            arguments = re.sub(r"\s+#.*$", "", arguments).strip()
            if not arguments:
                search_from = match.end()
                continue
            statement_end = operand_start + len(updated[operand_start:statement_end])

        var = match.group("var")
        quote = match.group("quote")
        params[var] = arguments
        safe_sql = _PLACEHOLDER.sub("?", sql)
        replacement = f"{match.group('indent')}{var} = {quote}{safe_sql}{quote}"

        updated = updated[: match.start()] + replacement + updated[statement_end:]
        search_from = match.start() + len(replacement)
        notes.append(f"Rewrote SQL in `{var}` to use ? placeholders")

    if not params:
        return code, notes

    for var, args in params.items():
        arg_list = [a.strip() for a in split_top_level(args, ",") if a.strip()]
        tuple_src = f"({arg_list[0]},)" if len(arg_list) == 1 else f"({', '.join(arg_list)})"
        pattern = re.compile(
            r"(?P<call>\.\s*(?:execute|executemany|executescript)\s*\(\s*)"
            + re.escape(var)
            + r"\s*\)"
        )
        updated, count = pattern.subn(lambda m: f"{m.group('call')}{var}, {tuple_src})", updated)
        if count:
            notes.append(f"Bound {len(arg_list)} parameter(s) at the execute() call for `{var}`")

    return updated, notes


def _python_weak_hash(code: str) -> Tuple[str, Notes]:
    notes: Notes = []
    updated = code

    if re.search(r"^\s*import\s+md5\b", updated, re.MULTILINE):
        updated = re.sub(r"^(\s*)import\s+md5\b", r"\1import hashlib", updated, flags=re.MULTILINE)
        notes.append("Replaced `import md5` with `import hashlib`")

    def _md5_new(match: re.Match) -> str:
        return f'hashlib.sha256(str({match.group(1)}).encode("utf-8")).hexdigest()'

    updated, n = re.subn(r"md5\.new\(([^()]*)\)\.hexdigest\(\)", _md5_new, updated)
    if n:
        notes.append(f"Replaced {n} md5.new() digest(s) with hashlib.sha256()")

    updated, n = re.subn(r"hashlib\.(?:md5|sha1)\(", "hashlib.sha256(", updated)
    if n:
        notes.append(f"Upgraded {n} hashlib.md5/sha1 call(s) to sha256")

    if notes and "scrypt" not in updated:
        notes.append(
            "Note: sha256 clears the broken-algorithm finding but is still fast; "
            "credentials should move to hashlib.scrypt or argon2"
        )
    return updated, notes


def _python_urllib2(code: str) -> Tuple[str, Notes]:
    if "urllib2" not in code:
        return code, []

    notes: Notes = []
    updated = re.sub(r"^(\s*)import\s+urllib2\b.*$", r"\1import requests", code, flags=re.MULTILINE)

    response_vars: List[str] = []

    def _urlopen(match: re.Match) -> str:
        args = match.group("args")
        if "timeout" not in args:
            args = f"{args}, timeout=10" if args.strip() else "timeout=10"
        return f"requests.get({args})"

    for match in list(
        re.finditer(r"(?P<var>\w+)\s*=\s*urllib2\.urlopen\s*\(", updated)
    ):
        response_vars.append(match.group("var"))

    def _rewrite_urlopen(text: str) -> Tuple[str, int]:
        count = 0
        while True:
            match = re.search(r"urllib2\.urlopen\s*\(", text)
            if not match:
                return text, count
            open_index = text.index("(", match.start())
            close_index = match_bracket(text, open_index)
            if close_index == -1:
                return text, count
            args = text[open_index + 1 : close_index]
            if "timeout" not in args:
                args = f"{args}, timeout=10" if args.strip() else "timeout=10"
            text = text[: match.start()] + f"requests.get({args})" + text[close_index + 1 :]
            count += 1

    updated, replaced = _rewrite_urlopen(updated)
    if replaced:
        notes.append(f"Converted {replaced} urllib2.urlopen() call(s) to requests.get() with a timeout")

    for var in response_vars:
        updated, n = re.subn(rf"\b{re.escape(var)}\.read\(\)", f"{var}.text", updated)
        if n:
            notes.append(f"Adapted `{var}.read()` to the requests response API (`.text`)")

    updated, n = re.subn(
        r"urllib2\.(?:URLError|HTTPError)", "requests.RequestException", updated
    )
    if n:
        notes.append("Mapped urllib2 error types to requests.RequestException")

    updated, n = re.subn(r"\burllib2\.", "requests.", updated)
    if n:
        notes.append("Rewrote remaining urllib2 references onto requests")

    return updated, notes


def _python_bare_except(code: str) -> Tuple[str, Notes]:
    updated, count = re.subn(
        r"^(?P<indent>[ \t]*)except[ \t]*:",
        lambda m: (
            f"{m.group('indent')}except Exception as exc:"
            "  # BOBPULSE: narrow this to the exception types this block handles"
        ),
        code,
        flags=re.MULTILINE,
    )
    if count:
        return updated, [f"Narrowed {count} bare `except:` clause(s) to `except Exception`"]
    return code, []


def _python_py2_print(code: str) -> Tuple[str, Notes]:
    updated, changed = normalise_python2(code)
    return (updated, ["Converted Python 2 print statements to print() calls"]) if changed else (code, [])


_MUTABLE_LITERALS = {
    ast.Dict: "{}",
    ast.List: "[]",
    ast.Set: "set()",
}


def _python_mutable_defaults(code: str) -> Tuple[str, Notes]:
    """Swap mutable defaults for None and add a guard as the first body statement."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return code, []

    lines = code.splitlines(keepends=True)
    edits: List[Tuple[int, int, List[Tuple[str, str]]]] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        positional = list(zip(node.args.args[len(node.args.args) - len(node.args.defaults) :], node.args.defaults))
        keyword = [
            (arg, default)
            for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults)
            if default is not None
        ]

        mutable: List[Tuple[str, str]] = []
        for arg, default in positional + keyword:
            literal: Optional[str] = None
            for node_type, replacement in _MUTABLE_LITERALS.items():
                if isinstance(default, node_type):
                    literal = replacement
                    break
            if (
                literal is None
                and isinstance(default, ast.Call)
                and isinstance(default.func, ast.Name)
                and default.func.id in {"dict", "list", "set"}
            ):
                literal = f"{default.func.id}()"
            if literal is not None:
                mutable.append((arg.arg, literal))

        if not mutable:
            continue

        body = node.body
        insert_before = body[0].lineno
        # Keep a docstring first.
        if (
            isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            insert_before = (body[0].end_lineno or body[0].lineno) + 1

        edits.append((node.lineno, insert_before, mutable))

    if not edits:
        return code, []

    notes: Notes = []
    # Apply bottom-up so earlier line numbers stay valid.
    for def_line, insert_before, mutable in sorted(edits, key=lambda e: e[1], reverse=True):
        header_end = min(insert_before, len(lines))
        for index in range(def_line - 1, header_end):
            for arg_name, literal in mutable:
                lines[index] = re.sub(
                    rf"(\b{re.escape(arg_name)})\s*=\s*{re.escape(literal)}",
                    r"\1=None",
                    lines[index],
                )

        body_indent = _indent_of(lines[insert_before - 1]) if insert_before - 1 < len(lines) else "    "
        guard = "".join(
            f"{body_indent}if {arg_name} is None:\n{body_indent}    {arg_name} = {literal}\n"
            for arg_name, literal in mutable
        )
        lines.insert(insert_before - 1, guard)
        notes.append(
            "Replaced mutable default(s) "
            + ", ".join(name for name, _ in mutable)
            + " with None plus an in-body guard"
        )

    return "".join(lines), notes


def _python_request_timeouts(code: str) -> Tuple[str, Notes]:
    """Add ``timeout=10`` to requests/httpx calls that omit it."""
    pattern = re.compile(r"\b(?:requests|httpx|session)\.(?:get|post|put|patch|delete|head|request)\s*\(")
    updated = code
    added = 0
    search_from = 0

    while True:
        match = pattern.search(updated, search_from)
        if not match:
            break
        open_index = updated.index("(", match.start())
        close_index = match_bracket(updated, open_index)
        if close_index == -1:
            break
        args = updated[open_index + 1 : close_index]
        if "timeout" in args:
            search_from = open_index + 1
            continue
        injected = f"{args.rstrip()}, timeout=10" if args.strip() else "timeout=10"
        updated = updated[: open_index + 1] + injected + updated[close_index:]
        added += 1
        search_from = open_index + 1 + len(injected) + 1

    if added:
        return updated, [f"Added an explicit timeout to {added} outbound HTTP call(s)"]
    return code, []


def transform_python(code: str) -> Tuple[str, Notes]:
    notes: Notes = []
    for step in (
        _python_py2_print,
        _python_parameterise_sql,
        _python_weak_hash,
        _python_urllib2,
        _python_bare_except,
        _python_mutable_defaults,
        _python_request_timeouts,
    ):
        code, step_notes = step(code)
        notes.extend(step_notes)
    return code, notes


# ─────────────────────────────────────────────────────────────────────────────
#  Java
# ─────────────────────────────────────────────────────────────────────────────

def _java_date_api(code: str) -> Tuple[str, Notes]:
    if "SimpleDateFormat" not in code:
        return code, []

    notes: Notes = []
    updated = code.replace(
        "import java.text.SimpleDateFormat;",
        "import java.time.Instant;\nimport java.time.format.DateTimeFormatter;",
    )

    # Field declaration -> immutable static formatter.
    updated, n = re.subn(
        r"(?P<indent>[ \t]*)(?P<mods>(?:private|protected|public)?\s*(?:static\s+)?(?:final\s+)?)"
        r"SimpleDateFormat\s+(?P<name>\w+)\s*=\s*new\s+SimpleDateFormat\s*\([^;]*\);",
        lambda m: (
            f"{m.group('indent')}private static final DateTimeFormatter "
            f"{m.group('name')} = DateTimeFormatter.ISO_INSTANT;"
            "  // immutable, safe to share between threads"
        ),
        updated,
    )
    if n:
        notes.append(f"Replaced {n} SimpleDateFormat field(s) with a static final DateTimeFormatter")

    updated, n = re.subn(r"(\w+)\.format\(\s*new\s+Date\(\)\s*\)", r"\1.format(Instant.now())", updated)
    if n:
        notes.append("Switched date formatting to java.time.Instant.now()")

    if "new Date(" not in updated and "Date " not in updated:
        updated = re.sub(r"^\s*import\s+java\.util\.Date;\s*\n", "", updated, flags=re.MULTILINE)

    if "SimpleDateFormat" not in updated:
        notes.append("All SimpleDateFormat usage removed — date handling is now thread-safe")
    return updated, notes


def _java_virtual_threads(code: str) -> Tuple[str, Notes]:
    """
    Convert ``new Thread(new Runnable(){ public void run(){ … } }).start();``
    into a virtual-thread executor submission, and wrap the enclosing loop in
    try-with-resources so the executor is closed.

    Only fires on the anonymous-Runnable shape. Anything else is left alone.
    """
    match = re.search(r"new\s+Thread\s*\(\s*new\s+Runnable\s*\(\s*\)\s*\{", code)
    if not match:
        return code, []

    run_match = re.search(r"public\s+void\s+run\s*\(\s*\)\s*\{", code[match.start() :])
    if not run_match:
        return code, []

    run_open = match.start() + run_match.end() - 1
    run_close = match_bracket(code, run_open)
    if run_close == -1:
        return code, []

    body = code[run_open + 1 : run_close]

    # `.start();` follows the anonymous class and its enclosing Thread(...) call.
    tail_match = re.compile(r"\}\s*\)\s*\.start\s*\(\s*\)\s*;").search(code, run_close)
    if not tail_match:
        return code, []

    # Locate the enclosing for-loop header so the executor can own its lifetime.
    for_match = None
    for candidate in re.finditer(r"(?P<indent>[ \t]*)for\s*\(", code[: match.start()]):
        for_match = candidate
    if for_match is None:
        return code, []

    for_open = code.index("(", for_match.start())
    for_header_close = match_bracket(code, for_open)
    if for_header_close == -1:
        return code, []
    brace_index = code.find("{", for_header_close)
    if brace_index == -1:
        return code, []
    for_body_close = match_bracket(code, brace_index)
    if for_body_close == -1:
        return code, []

    indent = for_match.group("indent")
    inner_indent = indent + "    "
    body_indent = inner_indent + "    "

    # Re-indent the runnable body one level deeper than the submit call.
    body_lines = [line for line in body.strip("\n").splitlines()]
    common = min(
        (len(line) - len(line.lstrip()) for line in body_lines if line.strip()),
        default=0,
    )
    rebodied = "\n".join(
        (body_indent + "    " + line[common:]) if line.strip() else "" for line in body_lines
    )

    header = code[for_match.start() : brace_index + 1]
    header = header.replace(indent, inner_indent, 1)
    # Drop the now-unnecessary `final` on the loop variable.
    header = re.sub(r"for\s*\(\s*final\s+", "for (", header)

    replacement = (
        f"{indent}// Virtual threads: one per task, no platform-thread ceiling (Java 21+)\n"
        f"{indent}try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {{\n"
        f"{header}\n"
        f"{body_indent}executor.submit(() -> {{\n"
        f"{rebodied}\n"
        f"{body_indent}}});\n"
        f"{inner_indent}}}\n"
        f"{indent}}}"
    )

    updated = code[: for_match.start()] + replacement + code[for_body_close + 1 :]

    if "import java.util.concurrent.Executors;" not in updated:
        updated = re.sub(
            r"^(import\s+java\.util\.List;)",
            r"\1\nimport java.util.concurrent.Executors;",
            updated,
            count=1,
            flags=re.MULTILINE,
        )
        if "import java.util.concurrent.Executors;" not in updated:
            updated = re.sub(
                r"^(import\s+[^\n]+;)",
                r"import java.util.concurrent.Executors;\n\1",
                updated,
                count=1,
                flags=re.MULTILINE,
            )

    return updated, [
        "Replaced per-task `new Thread(...)` with Executors.newVirtualThreadPerTaskExecutor() "
        "inside try-with-resources"
    ]


def _java_prepared_statement(code: str) -> Tuple[str, Notes]:
    """
    Convert ``stmt.executeUpdate("… '" + a + "' …" + b)`` into a
    PreparedStatement with ``?`` placeholders and positional setters.
    """
    pattern = re.compile(r"(?P<indent>[ \t]*)(?P<stmt>\w+)\.(?P<method>executeUpdate|executeQuery)\s*\(")
    match = pattern.search(code)
    if not match:
        return code, []

    open_index = code.index("(", match.end() - 1)
    close_index = match_bracket(code, open_index)
    if close_index == -1:
        return code, []

    args = code[open_index + 1 : close_index]
    tokens = [t.strip() for t in split_top_level(args, "+")]
    if len(tokens) < 2:
        return code, []

    sql_parts: List[str] = []
    params: List[str] = []
    for token in tokens:
        if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
            sql_parts.append(token[1:-1])
        else:
            sql_parts.append("?")
            params.append(token)

    if not params:
        return code, []

    sql = "".join(sql_parts)
    # `= '" + x + "'` collapses to `= '?'`; the quotes belong to the literal.
    sql = sql.replace("'?'", "?").replace('"?"', "?")

    indent = match.group("indent")
    setters = "\n".join(
        f"{indent}    ps.setObject({i + 1}, {param});" for i, param in enumerate(params)
    )
    terminator_end = close_index + 1
    while terminator_end < len(code) and code[terminator_end] in " \t;":
        terminator_end += 1

    block = (
        f'{indent}final String sql = "{sql}";\n'
        f"{indent}try (PreparedStatement ps = conn.prepareStatement(sql)) {{\n"
        f"{setters}\n"
        f"{indent}    ps.{match.group('method')}();\n"
        f"{indent}}}"
    )

    updated = code[: match.start()] + block + code[terminator_end:]

    # The plain Statement is now unused.
    updated = re.sub(
        r"^[ \t]*Statement\s+" + re.escape(match.group("stmt")) + r"\s*=\s*\w+\.createStatement\(\);[ \t]*\n",
        "",
        updated,
        flags=re.MULTILINE,
    )
    updated = updated.replace("import java.sql.Statement;", "import java.sql.PreparedStatement;")
    if "import java.sql.PreparedStatement;" not in updated:
        updated = re.sub(
            r"^(import\s+java\.sql\.[^\n]+;)",
            r"\1\nimport java.sql.PreparedStatement;",
            updated,
            count=1,
            flags=re.MULTILINE,
        )

    return updated, [
        f"Converted {match.group('method')} to a PreparedStatement with "
        f"{len(params)} bound parameter(s)"
    ]


def _java_try_with_resources(code: str) -> Tuple[str, Notes]:
    """
    Promote a Connection declared as the first statement of a ``try { … }`` block
    into that block's resource list, so it is always closed.

    Only this shape is handled. Rewriting a bare declaration would mean guessing
    where the connection's scope ends, and a brace inserted in the wrong place is
    worse than an unresolved finding.
    """
    pattern = re.compile(
        r"(?P<indent>[ \t]*)try\s*\{[ \t]*\n"
        r"(?P<inner>[ \t]*)Connection\s+(?P<name>\w+)\s*=\s*(?P<init>[^;\n]*getConnection\([^;\n]*\));[ \t]*\n",
    )
    match = pattern.search(code)
    if not match:
        return code, []

    replacement = (
        f"{match.group('indent')}try (Connection {match.group('name')} = {match.group('init')}) {{\n"
    )
    updated = code[: match.start()] + replacement + code[match.end() :]
    return updated, [
        "Moved the JDBC Connection into the try-with-resources header so it is "
        "closed on every path"
    ]


def _java_logging(code: str) -> Tuple[str, Notes]:
    updated, n = re.subn(
        r"(?P<indent>[ \t]*)(?P<var>\w+)\.printStackTrace\(\s*\);",
        lambda m: (
            f'{m.group("indent")}LOGGER.log(java.util.logging.Level.SEVERE, '
            f'"Operation failed", {m.group("var")});'
        ),
        code,
    )
    if not n:
        return code, []

    if "Logger LOGGER" not in updated:
        updated = re.sub(
            r"(public\s+(?:class|record)\s+\w+[^\{]*\{)",
            r"\1\n    private static final java.util.logging.Logger LOGGER ="
            r"\n        java.util.logging.Logger.getLogger("
            r"MethodHandles.lookup().lookupClass().getName());",
            updated,
            count=1,
        )
        updated = updated.replace(
            "MethodHandles.lookup().lookupClass().getName()",
            '"BobPulseModernized"',
        )
    return updated, [f"Replaced {n} printStackTrace() call(s) with structured logging"]


def transform_java(code: str) -> Tuple[str, Notes]:
    notes: Notes = []
    for step in (
        _java_date_api,
        _java_prepared_statement,
        _java_virtual_threads,
        _java_try_with_resources,
        _java_logging,
    ):
        code, step_notes = step(code)
        notes.extend(step_notes)
    return code, notes


# ─────────────────────────────────────────────────────────────────────────────
#  JavaScript / TypeScript
# ─────────────────────────────────────────────────────────────────────────────

def _js_authenticated_cipher(code: str) -> Tuple[str, Notes]:
    """Replace createCipher with createCipheriv + scrypt key + random IV + auth tag."""
    match = re.search(
        r"(?P<indent>[ \t]*)(?P<decl>(?:const|let|var)\s+(?P<name>\w+)\s*=\s*)"
        r"(?P<crypto>\w+)\.createCipher\s*\(",
        code,
    )
    if not match:
        return code, []

    open_index = code.index("(", match.end() - 1)
    close_index = match_bracket(code, open_index)
    if close_index == -1:
        return code, []

    args = [a.strip() for a in split_top_level(code[open_index + 1 : close_index], ",")]
    secret = args[1] if len(args) > 1 else "process.env.APP_SECRET"

    indent = match.group("indent")
    name = match.group("name")
    crypto_ns = match.group("crypto")

    terminator = close_index + 1
    while terminator < len(code) and code[terminator] in " \t;":
        terminator += 1

    block = (
        f"{indent}// AES-256-GCM: random IV per message plus an authentication tag\n"
        f"{indent}const key = {crypto_ns}.scryptSync({secret}, 'bobpulse-kdf-salt', 32);\n"
        f"{indent}const iv = {crypto_ns}.randomBytes(12);\n"
        f"{indent}const {name} = {crypto_ns}.createCipheriv('aes-256-gcm', key, iv);"
    )

    updated = code[: match.start()] + block + code[terminator:]

    # Expose the auth tag after the cipher is finalised, otherwise the
    # ciphertext cannot be verified on the way back in.
    final_match = re.search(rf"^(?P<indent>[ \t]*).*{re.escape(name)}\.final\([^)]*\);[ \t]*$", updated, re.MULTILINE)
    if final_match and "getAuthTag" not in updated:
        insert_at = final_match.end()
        updated = (
            updated[:insert_at]
            + f"\n{final_match.group('indent')}const authTag = {name}.getAuthTag().toString('hex');"
            + updated[insert_at:]
        )

    return updated, [
        "Replaced createCipher with createCipheriv('aes-256-gcm') using a scrypt-derived "
        "key, a random IV and an authentication tag"
    ]


_FS_CALLBACK = re.compile(
    r"(?P<indent>[ \t]*)fs\.(?P<method>readFile|writeFile|appendFile|readdir|stat|unlink|mkdir)\s*\(",
)


def _js_promisify_fs(code: str) -> Tuple[str, Notes]:
    """
    Flatten ``fs.x(args, function (err, result) { if (err) {…} else {…} })`` into
    ``const result = await fs.promises.x(args);`` followed by the success branch.

    Runs repeatedly so nested callbacks unwind from the outside in. Bails out on
    any shape it does not fully recognise.
    """
    notes: Notes = []
    converted = 0
    updated = code

    while True:
        match = _FS_CALLBACK.search(updated)
        if not match:
            break

        open_index = updated.index("(", match.end() - 1)
        close_index = match_bracket(updated, open_index)
        if close_index == -1:
            break

        call_args = split_top_level(updated[open_index + 1 : close_index], ",")
        callback = call_args[-1].strip()
        cb_match = re.match(
            r"function\s*\(\s*(?P<err>\w+)\s*(?:,\s*(?P<result>\w+)\s*)?\)\s*\{", callback
        )
        if not cb_match:
            break

        cb_open = callback.index("{", cb_match.end() - 1)
        cb_close = match_bracket(callback, cb_open)
        if cb_close == -1:
            break

        cb_body = callback[cb_open + 1 : cb_close]
        err_name = cb_match.group("err")
        result_name = cb_match.group("result")

        # Expect `if (err) { … } else { … }` and keep only the success branch.
        if_match = re.search(rf"if\s*\(\s*{re.escape(err_name)}\s*\)\s*{{", cb_body)
        if not if_match:
            break
        if_open = cb_body.index("{", if_match.end() - 1)
        if_close = match_bracket(cb_body, if_open)
        if if_close == -1:
            break
        else_match = re.match(r"\s*else\s*\{", cb_body[if_close + 1 :])
        if not else_match:
            break
        else_open = if_close + 1 + else_match.end() - 1
        else_close = match_bracket(cb_body, else_open)
        if else_close == -1:
            break

        success = cb_body[else_open + 1 : else_close]

        indent = match.group("indent")
        leading = [a.strip() for a in call_args[:-1]]
        assignment = f"const {result_name} = " if result_name else ""
        promise_call = (
            f"{indent}{assignment}await fs.promises.{match.group('method')}"
            f"({', '.join(leading)});"
        )

        success_lines = [line for line in success.strip("\n").splitlines()]
        common = min(
            (len(line) - len(line.lstrip()) for line in success_lines if line.strip()),
            default=0,
        )
        rebodied = "\n".join(
            (indent + line[common:]) if line.strip() else "" for line in success_lines
        )

        statement_end = close_index + 1
        while statement_end < len(updated) and updated[statement_end] in " \t;":
            statement_end += 1

        updated = (
            updated[: match.start()]
            + promise_call
            + ("\n" + rebodied if rebodied.strip() else "")
            + updated[statement_end:]
        )
        converted += 1

    if not converted:
        return code, []

    notes.append(f"Flattened {converted} error-first fs callback(s) into await fs.promises.*")

    # The enclosing function now contains `await`, so it has to be async, and the
    # discarded error branches need a real destination.
    func_match = re.search(r"^(?P<indent>[ \t]*)(?P<kw>function)\s+(?P<name>\w+)\s*\(", updated, re.MULTILINE)
    if func_match and "async function" not in updated:
        updated = (
            updated[: func_match.start("kw")] + "async function" + updated[func_match.end("kw") :]
        )
        notes.append(f"Marked {func_match.group('name')}() async")

    updated, wrapped_notes = _js_wrap_try_catch(updated)
    notes.extend(wrapped_notes)
    return updated, notes


def _js_wrap_try_catch(code: str) -> Tuple[str, Notes]:
    """Wrap the body of an async function containing await in try/catch."""
    match = re.search(r"(?P<indent>[ \t]*)async\s+function\s+(?P<name>\w+)\s*\([^)]*\)\s*\{", code)
    if not match or "try {" in code:
        return code, []

    open_index = code.index("{", match.end() - 1)
    close_index = match_bracket(code, open_index)
    if close_index == -1:
        return code, []

    body = code[open_index + 1 : close_index]
    if "await " not in body:
        return code, []

    indent = match.group("indent")
    inner = indent + "    "
    body_lines = body.strip("\n").splitlines()
    rebodied = "\n".join((inner + line) if line.strip() else "" for line in body_lines)

    wrapped = (
        f"\n{inner}try {{\n"
        f"{rebodied}\n"
        f"{inner}}} catch (err) {{\n"
        f"{inner}    return next(err);  // centralised error handling\n"
        f"{inner}}}\n{indent}"
    )

    # Give the handler a `next` to delegate to.
    signature_start = match.start()
    signature = code[signature_start : open_index + 1]
    if "next" not in signature:
        signature = re.sub(r"\(([^)]*)\)", lambda m: f"({m.group(1)}, next)", signature, count=1)

    return (
        code[:signature_start] + signature + wrapped + code[close_index:],
        ["Wrapped the async body in try/catch delegating to next(err)"],
    )


def _js_modern_declarations(code: str) -> Tuple[str, Notes]:
    updated, n = re.subn(r"^(?P<indent>[ \t]*)var\s+(?=\w)", r"\g<indent>let ", code, flags=re.MULTILINE)
    if n:
        return updated, [f"Replaced {n} `var` declaration(s) with `let`"]
    return code, []


_JS_QUERY_CALL = re.compile(r"\.(?P<method>query|execute|run|all|get)\s*\(")
_JS_SQL_KEYWORD = re.compile(r"(?i)\b(?:select|insert into|update|delete from)\b")
_JS_INTERPOLATION = re.compile(r"\$\{([^{}]*)\}")


def _js_parameterise_sql(code: str) -> Tuple[str, Notes]:
    """
    Turn ``db.query(`SELECT … WHERE id = ${id}`)`` into a parameterised call.

    Interpolations become positional placeholders and move into a values array,
    which is what removes the injection — escaping the value would leave it
    inside the query text.

    ``$1``-style placeholders are emitted (PostgreSQL / `pg`). Drivers in the
    MySQL and SQLite families expect ``?``; a note records that so the swap is
    not silent.
    """
    notes: Notes = []
    updated = code
    search_from = 0
    converted = 0

    while True:
        match = _JS_QUERY_CALL.search(updated, search_from)
        if not match:
            break

        open_index = updated.index("(", match.end() - 1)
        close_index = match_bracket(updated, open_index)
        if close_index == -1:
            search_from = match.end()
            continue

        arguments = updated[open_index + 1 : close_index]
        parts = split_top_level(arguments, ",")
        first = parts[0].strip()

        is_template = first.startswith("`") and first.endswith("`")
        if not is_template or not _JS_SQL_KEYWORD.search(first) or "${" not in first:
            # Resume just past the opening paren, not past the whole call: an
            # outer `router.get(...)` must not hide a `db.query(...)` inside it.
            search_from = match.end()
            continue

        values: List[str] = []

        def _placeholder(inner: "re.Match[str]") -> str:
            values.append(inner.group(1).strip())
            return f"${len(values)}"

        sql = _JS_INTERPOLATION.sub(_placeholder, first[1:-1])
        if not values:
            search_from = match.end()
            continue

        # `= '$1'` — the quotes belonged to the literal, not the value.
        for index in range(1, len(values) + 1):
            sql = sql.replace(f"'${index}'", f"${index}").replace(f'"${index}"', f"${index}")

        quote = '"' if "'" in sql else "'"
        remaining = [part.strip() for part in parts[1:] if part.strip()]
        rebuilt = f"{quote}{sql}{quote}, [{', '.join(values)}]"
        if remaining:
            rebuilt += ", " + ", ".join(remaining)

        updated = updated[: open_index + 1] + rebuilt + updated[close_index:]
        search_from = open_index + 1 + len(rebuilt)
        converted += 1

    if converted:
        notes.append(
            f"Parameterised {converted} template-literal quer{'y' if converted == 1 else 'ies'} "
            "using $1-style placeholders (switch to ? for MySQL/SQLite drivers)"
        )
    return updated, notes


def transform_js(code: str) -> Tuple[str, Notes]:
    notes: Notes = []
    for step in (
        _js_authenticated_cipher,
        _js_parameterise_sql,
        _js_promisify_fs,
        _js_modern_declarations,
    ):
        code, step_notes = step(code)
        notes.extend(step_notes)
    return code, notes


# ─────────────────────────────────────────────────────────────────────────────
#  Go
# ─────────────────────────────────────────────────────────────────────────────

def transform_go(code: str) -> Tuple[str, Notes]:
    notes: Notes = []
    updated = code

    if "crypto/md5" in updated or "crypto/sha1" in updated:
        updated = updated.replace('"crypto/md5"', '"crypto/sha256"').replace(
            '"crypto/sha1"', '"crypto/sha256"'
        )
        updated = re.sub(r"\bmd5\.New\(\)", "sha256.New()", updated)
        updated = re.sub(r"\bmd5\.Sum\(", "sha256.Sum256(", updated)
        updated = re.sub(r"\bsha1\.New\(\)", "sha256.New()", updated)
        notes.append("Upgraded crypto/md5 and crypto/sha1 usage to crypto/sha256")

    def _sprintf_to_params(match: re.Match) -> str:
        query = match.group("query")
        args = [a.strip() for a in split_top_level(match.group("args"), ",") if a.strip()]
        placeholders = re.findall(r"'%[sdv]'|%[sdv]", query)
        for index in range(len(placeholders)):
            query = re.sub(r"'%[sdv]'|%[sdv]", f"${index + 1}", query, count=1)
        joined = ", ".join(args)
        return f'"{query}", {joined}'

    updated, n = re.subn(
        r"fmt\.Sprintf\(\s*\"(?P<query>[^\"]*(?:SELECT|INSERT|UPDATE|DELETE)[^\"]*)\"\s*,\s*(?P<args>[^)]*)\)",
        _sprintf_to_params,
        updated,
        flags=re.IGNORECASE,
    )
    if n:
        notes.append(f"Converted {n} Sprintf-built quer{'y' if n == 1 else 'ies'} to numbered placeholders")

    return updated, notes


# ─────────────────────────────────────────────────────────────────────────────
#  PHP
# ─────────────────────────────────────────────────────────────────────────────

_PHP_QUERY_ASSIGN = re.compile(
    r"(?P<indent>[ \t]*)(?:(?P<target>\$\w+)\s*=\s*)?"
    r"(?:mysql_query|mysqli_query|pg_query|\$\w+->query)\s*\("
)

_PHP_SHELL = re.compile(r"\b(?P<fn>exec|system|shell_exec|passthru|popen|proc_open)\s*\(")

_PHP_VAR = re.compile(r"\$\w+")


def _php_pdo_connection(code: str) -> Tuple[str, Notes]:
    """Replace the removed mysql_connect/mysql_select_db pair with a PDO handle."""
    connect = re.search(
        r"(?P<indent>[ \t]*)(?:(?P<target>\$\w+)\s*=\s*)?mysql_connect\s*\((?P<args>[^)]*)\)\s*;",
        code,
    )
    if not connect:
        return code, []

    args = [a.strip() for a in split_top_level(connect.group("args"), ",")]
    host = args[0] if args else '"localhost"'
    user = args[1] if len(args) > 1 else '""'
    password = args[2] if len(args) > 2 else '""'

    select = re.search(r"mysql_select_db\s*\(\s*(?P<db>[^,)]+)[^;]*\)\s*;", code)
    database = select.group("db").strip() if select else '"app"'

    host_body = literal_body(host) if is_string_literal(host) else None
    database_body = literal_body(database) if is_string_literal(database) else None
    if host_body is not None and database_body is not None:
        dsn = f'"mysql:host={host_body};dbname={database_body};charset=utf8mb4"'
    else:
        dsn = f'"mysql:host=" . {host} . ";dbname=" . {database} . ";charset=utf8mb4"'

    indent = connect.group("indent")
    replacement = (
        f"{indent}$pdo = new PDO({dsn}, {user}, {password}, [\n"
        f"{indent}    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,\n"
        f"{indent}    PDO::ATTR_EMULATE_PREPARES => false,\n"
        f"{indent}]);"
    )

    updated = code[: connect.start()] + replacement + code[connect.end() :]
    updated = re.sub(r"[ \t]*mysql_select_db\s*\([^;]*\)\s*;[ \t]*\n?", "", updated, count=1)
    return updated, ["Replaced the removed mysql_connect/mysql_select_db pair with a PDO handle"]


def _php_parameterise_queries(code: str) -> Tuple[str, Notes]:
    """
    Rewrite a concatenated query call into a PDO prepared statement.

    ``$r = mysql_query("SELECT … WHERE u = '" . $name . "'")`` becomes a
    prepare/execute pair with a named placeholder. Escaping alone would leave the
    value inside the query text; binding it is what removes the injection.
    """
    notes: Notes = []
    updated = code
    search_from = 0
    converted = 0

    while True:
        match = _PHP_QUERY_ASSIGN.search(updated, search_from)
        if not match:
            break

        open_index = updated.index("(", match.end() - 1)
        close_index = match_bracket(updated, open_index)
        if close_index == -1:
            search_from = match.end()
            continue

        # mysqli_query($link, $sql) puts the query last.
        query_expression = split_top_level(updated[open_index + 1 : close_index], ",")[-1]

        fragments: List[str] = []
        params: List[str] = []

        def _lift(inner: "re.Match[str]") -> str:
            params.append(inner.group(0))
            return f":p{len(params)}"

        for token in split_top_level(query_expression, "."):
            stripped = token.strip()
            if is_string_literal(stripped):
                body = literal_body(stripped)
                if stripped.startswith('"') and _PHP_VAR.search(body):
                    body = _PHP_VAR.sub(_lift, body)
                fragments.append(body)
            elif _PHP_VAR.search(stripped):
                params.append(stripped)
                fragments.append(f":p{len(params)}")
            else:
                fragments.append(stripped)

        if not params:
            # Resume past the opening paren so a nested query call is still seen.
            search_from = match.end()
            continue

        sql = "".join(fragments)
        # `= '" . $v . "'` collapses to `= ':p1'` — those quotes were the literal's.
        for index in range(1, len(params) + 1):
            sql = sql.replace(f"':p{index}'", f":p{index}").replace(f'":p{index}"', f":p{index}")

        indent = match.group("indent")
        target = match.group("target")
        bindings = ", ".join(f'":p{i + 1}" => {param}' for i, param in enumerate(params))

        statement_end = close_index + 1
        while statement_end < len(updated) and updated[statement_end] in " \t;":
            statement_end += 1

        block = (
            f'{indent}$stmt = $pdo->prepare("{sql}");\n'
            f"{indent}$stmt->execute([{bindings}]);"
        )
        if target:
            block += f"\n{indent}{target} = $stmt;"

        updated = updated[: match.start()] + block + updated[statement_end:]
        search_from = match.start() + len(block)
        converted += 1

    if converted:
        notes.append(
            f"Converted {converted} concatenated quer{'y' if converted == 1 else 'ies'} "
            "to PDO prepared statements with bound parameters"
        )
    return updated, notes


def _php_result_api(code: str) -> Tuple[str, Notes]:
    """Port the remaining mysql_* result helpers onto PDO statement methods."""
    replacements = [
        (r"mysql_fetch_assoc\s*\(\s*(\$\w+)\s*\)", r"\1->fetch(PDO::FETCH_ASSOC)"),
        (r"mysql_fetch_array\s*\(\s*(\$\w+)\s*\)", r"\1->fetch(PDO::FETCH_BOTH)"),
        (r"mysql_fetch_row\s*\(\s*(\$\w+)\s*\)", r"\1->fetch(PDO::FETCH_NUM)"),
        (r"mysql_num_rows\s*\(\s*(\$\w+)\s*\)", r"\1->rowCount()"),
        (r"mysql_close\s*\(\s*\$\w+\s*\)", r"$pdo = null"),
        (r"mysql_real_escape_string\s*\(\s*(\$[\w\[\]'\"]+)\s*\)", r"\1"),
    ]

    updated = code
    total = 0
    for pattern, replacement in replacements:
        updated, count = re.subn(pattern, replacement, updated)
        total += count

    if total:
        return updated, [f"Ported {total} mysql_* result call(s) to the PDO statement API"]
    return code, []


def _php_password_hashing(code: str) -> Tuple[str, Notes]:
    """
    Replace md5/sha1 hashing.

    Password-looking arguments move to ``password_hash``; anything else becomes an
    explicit sha256 ``hash()`` call.
    """
    notes: Notes = []
    updated = code
    passwords = 0
    digests = 0
    search_from = 0

    while True:
        match = re.search(r"\b(?:md5|sha1)\s*\(", updated[search_from:])
        if not match:
            break
        start = search_from + match.start()
        open_index = search_from + match.end() - 1
        close_index = match_bracket(updated, open_index)
        if close_index == -1:
            search_from = open_index + 1
            continue

        argument = updated[open_index + 1 : close_index].strip()
        if re.search(r"pass|pwd|secret|credential", argument, re.IGNORECASE):
            replacement = f"password_hash({argument}, PASSWORD_DEFAULT)"
            passwords += 1
        else:
            replacement = f"hash('sha256', {argument})"
            digests += 1

        updated = updated[:start] + replacement + updated[close_index + 1 :]
        search_from = start + len(replacement)

    if passwords:
        notes.append(
            f"Replaced {passwords} md5/sha1 password hash(es) with password_hash(). "
            "Comparisons must move to password_verify() — a salted hash is not "
            "equality-comparable"
        )
    if digests:
        notes.append(f"Replaced {digests} md5/sha1 digest(s) with hash('sha256', …)")
    return updated, notes


def _php_escape_shell(code: str) -> Tuple[str, Notes]:
    """Wrap every interpolated part of a shell call in escapeshellarg()."""
    updated = code
    search_from = 0
    wrapped = 0

    while True:
        match = _PHP_SHELL.search(updated, search_from)
        if not match:
            break
        open_index = updated.index("(", match.end() - 1)
        close_index = match_bracket(updated, open_index)
        if close_index == -1:
            search_from = match.end()
            continue

        tokens = split_top_level(updated[open_index + 1 : close_index], ".")
        rebuilt: List[str] = []
        changed = False

        for token in tokens:
            stripped = token.strip()
            if (
                _PHP_VAR.search(stripped)
                and not is_string_literal(stripped)
                and not stripped.startswith("escapeshellarg")
            ):
                rebuilt.append(f"escapeshellarg({stripped})")
                changed = True
            else:
                rebuilt.append(stripped)

        if not changed:
            search_from = match.end()
            continue

        arguments = " . ".join(rebuilt)
        updated = updated[: open_index + 1] + arguments + updated[close_index:]
        search_from = open_index + 1 + len(arguments)
        wrapped += 1

    if wrapped:
        return updated, [
            f"Wrapped interpolated arguments of {wrapped} shell call(s) in escapeshellarg()"
        ]
    return code, []


def transform_php(code: str) -> Tuple[str, Notes]:
    notes: Notes = []
    for step in (
        _php_pdo_connection,
        _php_parameterise_queries,
        _php_result_api,
        _php_password_hashing,
        _php_escape_shell,
    ):
        code, step_notes = step(code)
        notes.extend(step_notes)
    return code, notes


# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────

_TRANSFORMERS = {
    "python": transform_python,
    "java": transform_java,
    "javascript": transform_js,
    "typescript": transform_js,
    "go": transform_go,
    "php": transform_php,
}


def apply_transformations(code: str, language: str) -> Tuple[str, Notes]:
    """
    Run the mechanical transformer for ``language``.

    Returns the rewritten source and the list of changes actually made. An empty
    note list means nothing was safe to change — the caller should report the
    original findings as unresolved rather than claim a fix.
    """
    transformer = _TRANSFORMERS.get(language)
    if transformer is None:
        return code, []
    try:
        return transformer(code)
    except Exception as exc:  # a failed transform must not lose the input
        return code, [f"Transformer aborted without modifying the source: {exc}"]
