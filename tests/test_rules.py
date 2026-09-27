"""
Rule engine tests.

Includes explicit regression tests for the false positives that used to exist:
``except Exception:`` being flagged as a bare except, any list assignment being
flagged as a mutable default argument, and module names matching inside comments.
"""

from __future__ import annotations

import pytest

from backend import rules


# ── Registry ─────────────────────────────────────────────────────────────────

def test_registry_is_not_empty():
    assert rules.rule_count() > 0
    for language in rules.SUPPORTED_LANGUAGES:
        assert rules.rules_for(language), f"{language} has no rules"


def test_rule_ids_are_unique():
    ids = [rule.id for rule in rules.ALL_RULES]
    assert len(ids) == len(set(ids))


def test_every_rule_is_well_formed():
    for rule in rules.ALL_RULES:
        assert rule.severity in rules.SEVERITY_RANK, rule.id
        assert rule.category in {
            rules.CATEGORY_VULNERABILITY,
            rules.CATEGORY_DEPRECATION,
            rules.CATEGORY_QUALITY,
        }, rule.id
        assert rule.title and rule.description and rule.remediation, rule.id
        assert rule.debt_points > 0, rule.id
        assert rule.languages, rule.id
        # Security findings should carry a CWE; quality findings need not.
        if rule.category == rules.CATEGORY_VULNERABILITY:
            assert rule.cwe, f"{rule.id} is a vulnerability without a CWE"


def test_typescript_inherits_javascript_rules():
    js_ids = {rule.id for rule in rules.rules_for("javascript")}
    ts_ids = {rule.id for rule in rules.rules_for("typescript")}
    assert js_ids < ts_ids


# ── Examples ─────────────────────────────────────────────────────────────────

def test_example_triggers_exactly_its_expected_rules(example):
    found = {f["id"] for f in rules.scan(example["original_code"], example["language"])}
    expected = set(example["expected_rule_ids"])
    assert found == expected, (
        f"missing={sorted(expected - found)} unexpected={sorted(found - expected)}"
    )


def test_findings_carry_usable_locations(example):
    source_line_count = len(example["original_code"].splitlines())
    for finding in rules.scan(example["original_code"], example["language"]):
        assert finding["lines"], f"{finding['id']} reported no line numbers"
        assert finding["occurrences"] == len(finding["lines"])
        for line in finding["lines"]:
            assert 1 <= line <= source_line_count, f"{finding['id']} line {line} out of range"
        for snippet in finding["snippets"]:
            assert snippet["line"] in finding["lines"]


def test_findings_are_sorted_by_severity(example):
    found = rules.scan(example["original_code"], example["language"])
    ranks = [rules.SEVERITY_RANK[f["severity"]] for f in found]
    assert ranks == sorted(ranks)


# ── Line accuracy ────────────────────────────────────────────────────────────

def test_line_numbers_point_at_the_offending_line():
    source = "\n".join(
        [
            "import hashlib",          # 1
            "",                        # 2
            "def check(secret):",      # 3
            "    return hashlib.md5(secret).hexdigest()",  # 4
        ]
    )
    findings = {f["id"]: f for f in rules.scan(source, "python")}
    assert findings["PY-SEC-002"]["lines"] == [4]


def test_multiple_occurrences_are_all_reported():
    source = "import hashlib\na = hashlib.md5(b'1')\nb = hashlib.sha1(b'2')\n"
    finding = next(f for f in rules.scan(source, "python") if f["id"] == "PY-SEC-002")
    assert finding["lines"] == [2, 3]
    assert finding["occurrences"] == 2


# ── Comment handling ─────────────────────────────────────────────────────────

def test_blank_comments_preserves_offsets():
    source = "import os  # urllib2 was here\nvalue = 1\n"
    blanked = rules.blank_comments(source, "python")
    assert len(blanked) == len(source)
    assert blanked.count("\n") == source.count("\n")


def test_blank_comments_keeps_string_literals():
    source = 'query = "SELECT * FROM users"  # a comment\n'
    blanked = rules.blank_comments(source, "python")
    assert "SELECT * FROM users" in blanked
    assert "a comment" not in blanked


@pytest.mark.parametrize(
    "language,source",
    [
        ("java", "// SimpleDateFormat used to be here\nclass A {}\n"),
        ("javascript", "/* createCipher( was removed */\nconst a = 1;\n"),
        ("go", "// crypto/md5 no longer imported\npackage main\n"),
    ],
)
def test_commented_out_code_is_not_flagged(language, source):
    assert rules.scan(source, language) == []


def test_module_named_only_in_a_comment_is_not_flagged():
    """Regression: `urllib2` mentioned in prose used to count as a usage."""
    source = "import requests\n# DEPRECATED: urllib2 removed in Python 3\nr = requests.get('http://x', timeout=5)\n"
    assert "PY-DEP-001" not in {f["id"] for f in rules.scan(source, "python")}


# ── False-positive regressions ───────────────────────────────────────────────

def test_except_exception_is_not_a_bare_except():
    """Regression: `except Exception:` is legitimate and must not be flagged."""
    source = "try:\n    pass\nexcept Exception:\n    raise\n"
    assert "PY-QUAL-002" not in {f["id"] for f in rules.scan(source, "python")}


def test_bare_except_is_still_flagged():
    source = "try:\n    pass\nexcept:\n    pass\n"
    found = {f["id"] for f in rules.scan(source, "python")}
    assert "PY-QUAL-002" in found


def test_plain_list_assignment_is_not_a_mutable_default():
    """Regression: the old regex flagged every `x = [...]` line."""
    source = "def f(a, b):\n    items = [1, 2, 3]\n    mapping = {'k': 'v'}\n    return items, mapping\n"
    assert "PY-QUAL-001" not in {f["id"] for f in rules.scan(source, "python")}


def test_actual_mutable_default_is_flagged():
    source = "def f(cache={}):\n    return cache\n"
    found = {f["id"] for f in rules.scan(source, "python")}
    assert "PY-QUAL-001" in found


def test_keyword_only_mutable_default_is_flagged():
    source = "def f(*, cache=[]):\n    return cache\n"
    assert "PY-QUAL-001" in {f["id"] for f in rules.scan(source, "python")}


def test_single_error_first_callback_is_not_callback_hell():
    """One error-first callback is idiomatic Node; two nested ones are not."""
    source = "fs.readFile('a', function (err, data) {\n  if (err) { return; }\n  use(data);\n});\n"
    assert "JS-DEP-001" not in {f["id"] for f in rules.scan(source, "javascript")}


def test_connection_in_try_with_resources_is_not_a_leak():
    """Regression: an unrelated `try (` elsewhere used to mask a real leak."""
    source = (
        "class A {\n"
        "  void run() {\n"
        "    try (Connection c = ds.getConnection()) {\n"
        "      c.commit();\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    assert "JAVA-QUAL-001" not in {f["id"] for f in rules.scan(source, "java")}


def test_bare_connection_is_still_a_leak():
    source = "class A {\n  void run() {\n    Connection c = ds.getConnection();\n  }\n}\n"
    assert "JAVA-QUAL-001" in {f["id"] for f in rules.scan(source, "java")}


def test_awaited_promise_is_not_an_unhandled_rejection():
    source = "async function f() {\n  const r = await p.then(x => x);\n}\n"
    assert "JS-QUAL-001" not in {f["id"] for f in rules.scan(source, "javascript")}


def test_placeholder_secret_is_not_a_hardcoded_credential():
    source = 'api_key = "your_key_here"\n'
    assert "PY-SEC-004" not in {f["id"] for f in rules.scan(source, "python")}


def test_real_hardcoded_secret_is_flagged():
    source = 'api_key = "sk-live-9f2a7c4e11b8"\n'
    assert "PY-SEC-004" in {f["id"] for f in rules.scan(source, "python")}


@pytest.mark.parametrize(
    "name",
    ["DB_PASSWORD", "STRIPE_API_KEY", "JWT_SECRET", "AUTH_TOKEN", "admin_passwd", "SERVICE_SECRET"],
)
def test_prefixed_secret_names_are_flagged(name):
    """
    Regression: a plain \\b anchor missed every realistically named secret.

    `\\b` does not match between `DB_` and `PASSWORD` because the underscore is
    itself a word character, so the rule only ever fired on a bare `password =`.
    """
    source = f'{name} = "aVeryRealLookingValue123"\n'
    assert "PY-SEC-004" in {f["id"] for f in rules.scan(source, "python")}


# ── Python 2 handling ────────────────────────────────────────────────────────

def test_python2_source_is_lifted_so_ast_rules_still_run():
    """Without the lift, unparseable Python 2 would report zero AST findings."""
    source = 'print "hello"\ntry:\n    pass\nexcept:\n    pass\n'
    context = rules.build_context(source, "python")
    assert context.parse_error is not None
    assert context.normalised_for_parse is True
    assert context.tree is not None

    found = {f["id"] for f in rules.scan(source, "python", context)}
    assert "PY-DEP-002" in found  # print statement
    assert "PY-QUAL-002" in found  # bare except, only visible via the AST


def test_python2_lift_preserves_line_numbers():
    source = "x = 1\n\nprint 'two'\n"
    lifted, changed = rules.normalise_python2(source)
    assert changed
    assert len(lifted.splitlines()) == len(source.splitlines())
    finding = next(f for f in rules.scan(source, "python") if f["id"] == "PY-DEP-002")
    assert finding["lines"] == [3]


def test_unparseable_source_does_not_crash_the_scan():
    findings = rules.scan("def broken(:\n", "python")
    assert isinstance(findings, list)


# ── SQL injection detection ──────────────────────────────────────────────────

@pytest.mark.parametrize(
    "source",
    [
        'cursor.execute("SELECT * FROM t WHERE id = %s" % uid)\n',
        'cursor.execute(f"SELECT * FROM t WHERE id = {uid}")\n',
        'cursor.execute("SELECT * FROM t WHERE id = {}".format(uid))\n',
        'cursor.execute("SELECT * FROM t WHERE id = " + uid)\n',
        'q = "SELECT * FROM t WHERE id = %s" % uid\ncursor.execute(q)\n',
    ],
)
def test_sql_injection_shapes_are_detected(source):
    assert "PY-SEC-001" in {f["id"] for f in rules.scan(source, "python")}


@pytest.mark.parametrize(
    "source",
    [
        'cursor.execute("SELECT * FROM t WHERE id = ?", (uid,))\n',
        'cursor.execute("SELECT * FROM t")\n',
        'label = "SELECT a plan" % kind\n',  # interpolated, but never executed
    ],
)
def test_parameterised_or_static_sql_is_not_flagged(source):
    assert "PY-SEC-001" not in {f["id"] for f in rules.scan(source, "python")}


# ── Split helper ─────────────────────────────────────────────────────────────

def test_split_findings_partitions_every_finding(example):
    found = rules.scan(example["original_code"], example["language"])
    buckets = rules.split_findings(found)
    assert len(buckets["vulnerabilities"]) + len(buckets["deprecations"]) == len(found)
    assert all(f["category"] == "vulnerability" for f in buckets["vulnerabilities"])
    assert all(f["category"] != "vulnerability" for f in buckets["deprecations"])
