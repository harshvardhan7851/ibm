"""
Source-text helpers shared by the scanner and the transformer.

These live in their own module because both :mod:`backend.rules` and
:mod:`backend.transforms` need them, and ``transforms`` already imports
``rules``.

They are deliberately lexical rather than syntactic: enough awareness of
strings and comments to avoid the obvious mistakes, without pulling a parser
per language into the project.
"""

from __future__ import annotations

from typing import List

_OPEN_TO_CLOSE = {"(": ")", "{": "}", "[": "]"}

#: Languages whose backtick is a string delimiter rather than an operator.
_BACKTICK_LANGUAGES = {"javascript", "typescript"}


def match_bracket(text: str, open_index: int) -> int:
    """
    Index of the bracket closing the one at ``open_index``, or ``-1``.

    Brackets inside string literals, template literals, ``//``/``#`` line
    comments and ``/* */`` block comments are skipped.
    """
    opener = text[open_index]
    closer = _OPEN_TO_CLOSE.get(opener)
    if closer is None:
        return -1

    depth = 0
    i = open_index
    length = len(text)

    while i < length:
        char = text[i]

        if char == "/" and i + 1 < length:
            if text[i + 1] == "/":
                newline = text.find("\n", i)
                i = length if newline == -1 else newline
                continue
            if text[i + 1] == "*":
                end = text.find("*/", i + 2)
                i = length if end == -1 else end + 2
                continue
        if char == "#":
            newline = text.find("\n", i)
            i = length if newline == -1 else newline
            continue

        if char in "\"'`":
            quote = char
            i += 1
            while i < length:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            continue

        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return i
        i += 1

    return -1


def split_top_level(text: str, separator: str) -> List[str]:
    """Split ``text`` on ``separator``, ignoring nested or quoted occurrences."""
    parts: List[str] = []
    current: List[str] = []
    depth = 0
    i = 0
    length = len(text)

    while i < length:
        char = text[i]

        if char in "\"'`":
            quote = char
            current.append(char)
            i += 1
            while i < length:
                current.append(text[i])
                if text[i] == "\\":
                    i += 1
                    if i < length:
                        current.append(text[i])
                    i += 1
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            continue

        if char in "({[":
            depth += 1
        elif char in ")}]":
            depth -= 1

        if char == separator and depth == 0:
            parts.append("".join(current))
            current = []
            i += 1
            continue

        current.append(char)
        i += 1

    parts.append("".join(current))
    return parts


def call_arguments(text: str, call_start: int) -> str:
    """
    Raw argument text of the call whose name starts at ``call_start``.

    Returns an empty string when the call is not bracketed or is unbalanced.
    """
    open_index = text.find("(", call_start)
    if open_index == -1:
        return ""
    close_index = match_bracket(text, open_index)
    if close_index == -1:
        return ""
    return text[open_index + 1 : close_index]


def indent_of(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def is_string_literal(token: str) -> bool:
    """True when ``token`` is a single complete quoted literal."""
    stripped = token.strip()
    if len(stripped) < 2:
        return False
    return stripped[0] == stripped[-1] and stripped[0] in "\"'"


def literal_body(token: str) -> str:
    """Contents of a quoted literal, without its delimiters."""
    stripped = token.strip()
    return stripped[1:-1] if is_string_literal(stripped) else stripped
