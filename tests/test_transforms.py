"""
Mechanical transformer tests.

The two invariants that matter most:

* a transform must never emit source that is worse-formed than its input, and
* whatever it claims to fix must actually disappear from a re-scan.
"""

from __future__ import annotations

import pytest

from backend import rules, transforms


def scan_ids(code: str, language: str) -> set[str]:
    return {f["id"] for f in rules.scan(code, language)}


# ── Bracket helpers ──────────────────────────────────────────────────────────

def test_match_bracket_finds_the_partner():
    text = "f(a, g(b), c)"
    assert transforms.match_bracket(text, 1) == len(text) - 1


def test_match_bracket_ignores_brackets_in_strings():
    text = 'f("a)b", c)'
    assert text[transforms.match_bracket(text, 1)] == ")"
    assert transforms.match_bracket(text, 1) == len(text) - 1


def test_match_bracket_ignores_brackets_in_comments():
    text = "f(a, // )\n b)"
    assert transforms.match_bracket(text, 1) == len(text) - 1


def test_match_bracket_returns_minus_one_when_unbalanced():
    assert transforms.match_bracket("f(a, b", 1) == -1


def test_split_top_level_respects_nesting():
    assert transforms.split_top_level("a, f(b, c), d", ",") == ["a", " f(b, c)", " d"]


def test_split_top_level_respects_strings():
    assert transforms.split_top_level('a, "b, c", d', ",") == ["a", ' "b, c"', " d"]


# ── Python ───────────────────────────────────────────────────────────────────

def test_sql_is_parameterised_and_arguments_move_to_execute():
    source = (
        "import sqlite3\n"
        "def find(cur, name, pw):\n"
        '    q = "SELECT id FROM users WHERE name = \'%s\' AND pw = \'%s\'" % (name, pw)\n'
        "    cur.execute(q)\n"
    )
    output, notes = transforms.apply_transformations(source, "python")

    assert "PY-SEC-001" not in scan_ids(output, "python")
    assert "?" in output and "%s" not in output
    assert "cur.execute(q, (name, pw))" in output
    assert notes
    compile(output, "<test>", "exec")


@pytest.mark.parametrize(
    "operand,expected_binding",
    [
        ("customer", "(customer,)"),           # bare name, no parentheses
        ("(customer,)", "(customer,)"),        # single-element tuple
        ("order.customer_id", "(order.customer_id,)"),
        ("row['cid']", "(row['cid'],)"),
    ],
)
def test_sql_parameterisation_handles_operands_without_parentheses(operand, expected_binding):
    """`"… %s" % name` is at least as common as the tuple form and must work."""
    source = (
        "def find(cur, customer, order, row):\n"
        f"    q = \"SELECT id FROM orders WHERE customer = '%s'\" % {operand}\n"
        "    cur.execute(q)\n"
    )
    output, _ = transforms.apply_transformations(source, "python")
    assert "PY-SEC-001" not in scan_ids(output, "python")
    assert f"cur.execute(q, {expected_binding})" in output
    compile(output, "<test>", "exec")


def test_sql_parameterisation_ignores_a_trailing_comment():
    source = (
        "def find(cur, c):\n"
        "    q = \"SELECT id FROM t WHERE c = '%s'\" % c  # lookup\n"
        "    cur.execute(q)\n"
    )
    output, _ = transforms.apply_transformations(source, "python")
    assert "cur.execute(q, (c,))" in output
    assert "# lookup" not in output.split("execute")[0].split("\n")[-1]
    compile(output, "<test>", "exec")


def test_single_sql_parameter_gets_a_tuple_comma():
    source = (
        "def find(cur, name):\n"
        '    q = "SELECT id FROM users WHERE name = \'%s\'" % (name,)\n'
        "    cur.execute(q)\n"
    )
    output, _ = transforms.apply_transformations(source, "python")
    assert "cur.execute(q, (name,))" in output
    compile(output, "<test>", "exec")


def test_sql_transform_does_not_swallow_the_rest_of_the_file():
    """Regression: a greedy DOTALL pattern used to consume everything after."""
    source = (
        "def find(cur, name):\n"
        '    q = "SELECT id FROM users WHERE name = \'%s\'" % (name,)\n'
        "    cur.execute(q)\n"
        "    return cur.fetchone()\n"
        "\n"
        "SENTINEL = 'still here'\n"
    )
    output, _ = transforms.apply_transformations(source, "python")
    assert "SENTINEL = 'still here'" in output
    assert "return cur.fetchone()" in output
    compile(output, "<test>", "exec")


def test_md5_becomes_sha256():
    source = "import md5\nd = md5.new(pw).hexdigest()\n"
    output, _ = transforms.apply_transformations(source, "python")
    assert "PY-SEC-002" not in scan_ids(output, "python")
    assert "hashlib.sha256" in output
    assert "import hashlib" in output


def test_urllib2_becomes_requests_with_a_timeout():
    source = "import urllib2\nr = urllib2.urlopen(url)\nbody = r.read()\n"
    output, _ = transforms.apply_transformations(source, "python")
    assert "PY-DEP-001" not in scan_ids(output, "python")
    assert "requests.get(" in output
    assert "timeout=" in output
    assert ".text" in output  # requests has no .read()


def test_bare_except_is_narrowed():
    source = "try:\n    work()\nexcept:\n    handle()\n"
    output, _ = transforms.apply_transformations(source, "python")
    assert "PY-QUAL-002" not in scan_ids(output, "python")
    compile(output, "<test>", "exec")


def test_mutable_default_gets_a_none_guard():
    source = "def f(cache={}):\n    cache['a'] = 1\n    return cache\n"
    output, _ = transforms.apply_transformations(source, "python")
    assert "PY-QUAL-001" not in scan_ids(output, "python")
    assert "cache=None" in output
    assert "if cache is None:" in output
    compile(output, "<test>", "exec")


def test_mutable_default_guard_lands_after_a_docstring():
    source = 'def f(cache={}):\n    """Doc."""\n    return cache\n'
    output, _ = transforms.apply_transformations(source, "python")
    lines = output.splitlines()
    assert lines[1].strip() == '"""Doc."""'
    assert "if cache is None:" in lines[2]
    compile(output, "<test>", "exec")


def test_missing_http_timeout_is_added():
    source = "import requests\nr = requests.get('https://example.com')\n"
    output, _ = transforms.apply_transformations(source, "python")
    assert "timeout=10" in output
    assert "PY-QUAL-004" not in scan_ids(output, "python")


def test_existing_timeout_is_left_alone():
    source = "import requests\nr = requests.get('https://example.com', timeout=3)\n"
    output, _ = transforms.apply_transformations(source, "python")
    assert output.count("timeout") == 1


def test_python2_print_is_converted():
    source = 'print "hello"\n'
    output, _ = transforms.apply_transformations(source, "python")
    assert output.strip() == 'print("hello")'
    compile(output, "<test>", "exec")


# ── Java ─────────────────────────────────────────────────────────────────────

def test_simpledateformat_field_becomes_a_shared_formatter():
    source = (
        "import java.text.SimpleDateFormat;\n"
        "import java.util.Date;\n"
        "class A {\n"
        '    private SimpleDateFormat fmt = new SimpleDateFormat("yyyy");\n'
        "    String now() { return fmt.format(new Date()); }\n"
        "}\n"
    )
    output, notes = transforms.apply_transformations(source, "java")
    assert "JAVA-SEC-002" not in scan_ids(output, "java")
    assert "static final DateTimeFormatter" in output
    assert "Instant.now()" in output
    assert notes


def test_concatenated_sql_becomes_a_prepared_statement():
    source = (
        "class A {\n"
        "  void f(Connection conn, String id, String when) throws Exception {\n"
        "    try {\n"
        "      Statement stmt = conn.createStatement();\n"
        '      stmt.executeUpdate("UPDATE t SET at = \'" + when + "\' WHERE id = " + id);\n'
        "    } catch (Exception e) { e.printStackTrace(); }\n"
        "  }\n"
        "}\n"
    )
    output, _ = transforms.apply_transformations(source, "java")
    assert "JAVA-SEC-001" not in scan_ids(output, "java")
    assert "prepareStatement" in output
    assert "ps.setObject(1, when);" in output
    assert "ps.setObject(2, id);" in output
    # The quotes that wrapped the placeholder belong to the literal, not the value.
    assert "= ? WHERE id = ?" in output


# ── JavaScript ───────────────────────────────────────────────────────────────

def test_createcipher_becomes_authenticated_encryption():
    source = (
        "const crypto = require('crypto');\n"
        "const cipher = crypto.createCipher('aes-128-cbc', 'secret');\n"
        "let out = cipher.update('x', 'utf8', 'hex');\n"
        "out += cipher.final('hex');\n"
    )
    output, _ = transforms.apply_transformations(source, "javascript")
    assert "JS-SEC-001" not in scan_ids(output, "javascript")
    assert "createCipheriv('aes-256-gcm'" in output
    assert "randomBytes" in output
    assert "scryptSync" in output
    assert "getAuthTag" in output


def test_var_becomes_let():
    source = "var a = 1;\n"
    output, _ = transforms.apply_transformations(source, "javascript")
    assert output.strip() == "let a = 1;"


def test_template_literal_sql_is_parameterised():
    source = "db.query(`SELECT id FROM users WHERE id = ${id}`);\n"
    output, notes = transforms.apply_transformations(source, "javascript")
    assert "JS-SEC-003" not in scan_ids(output, "javascript")
    assert "'SELECT id FROM users WHERE id = $1', [id]" in output
    assert notes


def test_template_literal_sql_quotes_around_placeholders_are_dropped():
    source = "db.query(`SELECT id FROM users WHERE name = '${name}'`);\n"
    output, _ = transforms.apply_transformations(source, "javascript")
    assert "name = $1" in output
    assert "'$1'" not in output


def test_multiple_interpolations_become_ordered_placeholders():
    source = "db.query(`SELECT id FROM t WHERE a = ${x} AND b = ${y}`);\n"
    output, _ = transforms.apply_transformations(source, "javascript")
    assert "a = $1 AND b = $2" in output
    assert "[x, y]" in output


def test_a_nested_query_call_is_not_hidden_by_its_caller():
    """
    Regression: skipping a non-matching call used to jump past its closing
    paren, so `router.get(..., () => { db.query(`…`) })` was never examined.
    """
    source = (
        "router.get('/users/:id', (req, res) => {\n"
        "  db.query(`SELECT id FROM users WHERE id = ${req.params.id}`);\n"
        "});\n"
    )
    output, _ = transforms.apply_transformations(source, "javascript")
    assert "JS-SEC-003" not in scan_ids(output, "javascript")
    assert "$1" in output


def test_static_query_is_left_alone():
    source = "db.query('SELECT 1');\n"
    output, notes = transforms.apply_transformations(source, "javascript")
    assert output == source
    assert notes == []


# ── Global invariants ────────────────────────────────────────────────────────

def test_transform_never_breaks_python_syntax(example):
    if example["language"] != "python":
        pytest.skip("Python-only invariant")
    output, _ = transforms.apply_transformations(example["original_code"], example["language"])
    compile(output, "<transformed>", "exec")


def test_transform_never_introduces_a_new_finding(example):
    before = scan_ids(example["original_code"], example["language"])
    output, _ = transforms.apply_transformations(example["original_code"], example["language"])
    after = scan_ids(output, example["language"])
    assert not (after - before), f"introduced {sorted(after - before)}"


def test_transform_resolves_something_on_every_example(example):
    before = scan_ids(example["original_code"], example["language"])
    output, notes = transforms.apply_transformations(example["original_code"], example["language"])
    after = scan_ids(output, example["language"])
    assert before - after, "no finding was resolved"
    assert notes, "changes were made but not reported"


def test_transform_is_stable_on_its_own_output(example):
    """A second pass must not undo work or corrupt the source."""
    once, _ = transforms.apply_transformations(example["original_code"], example["language"])
    twice, _ = transforms.apply_transformations(once, example["language"])
    assert not (scan_ids(twice, example["language"]) - scan_ids(once, example["language"]))
    if example["language"] == "python":
        compile(twice, "<twice>", "exec")


def test_unknown_language_is_returned_untouched():
    output, notes = transforms.apply_transformations("SELECT 1;", "sql")
    assert output == "SELECT 1;"
    assert notes == []


def test_transformer_failure_returns_the_input(monkeypatch):
    def boom(_code):
        raise RuntimeError("synthetic failure")

    monkeypatch.setitem(transforms._TRANSFORMERS, "python", boom)
    output, notes = transforms.apply_transformations("x = 1\n", "python")
    assert output == "x = 1\n"
    assert any("aborted" in note for note in notes)
