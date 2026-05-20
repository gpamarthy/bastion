"""Detection of injected instructions and obfuscation in untrusted text.

These detectors back the tool-poisoning, hidden-instruction, and result-
injection rules. They are intentionally regex/lookup based: cheap enough to run
on the hot path and fully offline.
"""

from __future__ import annotations

import re
import unicodedata

# Imperative / instruction-injection markers. Kept specific to hold the false-
# positive rate down on honest tool descriptions, which legitimately contain
# imperative language ("Use this to ...").
_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<\s*/?\s*(?:important|system|secret|admin|instructions?)\s*>", re.I),
    re.compile(r"\bignore\s+(?:the\s+|all\s+|any\s+)?(?:previous|prior|above|preceding)\b", re.I),
    re.compile(
        r"\bdisregard\s+(?:the\s+|all\s+|any\s+|your\s+)?(?:previous|prior|above|instructions?)\b",
        re.I,
    ),
    re.compile(r"\bdo\s+not\s+(?:tell|mention|inform|reveal|disclose|notify)\b", re.I),
    re.compile(r"\bdon'?t\s+(?:tell|mention|inform|reveal|disclose)\b", re.I),
    re.compile(r"\byou\s+must\s+(?:always|never)\b", re.I),
    re.compile(r"\b(?:your\s+real|the\s+actual)\s+(?:task|instructions?|goal)\b", re.I),
    re.compile(r"\bsystem\s+prompt\b", re.I),
    re.compile(
        r"\b(?:before|after)\s+(?:you\s+)?(?:use|call|invoke|run)(?:ing)?\s+this\s+tool\b", re.I
    ),
    re.compile(
        r"\binstead\s*,?\s+(?:you\s+(?:should|must)|please|return|send|read|fetch|exfiltrate)\b",
        re.I,
    ),
    re.compile(
        r"\b(?:send|forward|exfiltrate|leak|post)\s+(?:the\s+)?(?:contents?|data|files?|secrets?|credentials?)\s+to\b",
        re.I,
    ),
)

# Invisible / formatting code points that have no business in a tool schema.
# Declared as integers so the source file itself stays plain ASCII.
_INVISIBLE_CODEPOINTS: tuple[tuple[int, str], ...] = (
    (0x200B, "ZERO WIDTH SPACE"),
    (0x200C, "ZERO WIDTH NON-JOINER"),
    (0x200D, "ZERO WIDTH JOINER"),
    (0x2060, "WORD JOINER"),
    (0xFEFF, "ZERO WIDTH NO-BREAK SPACE (BOM)"),
    (0x200E, "LEFT-TO-RIGHT MARK"),
    (0x200F, "RIGHT-TO-LEFT MARK"),
    (0x202A, "LEFT-TO-RIGHT EMBEDDING"),
    (0x202B, "RIGHT-TO-LEFT EMBEDDING"),
    (0x202C, "POP DIRECTIONAL FORMATTING"),
    (0x202D, "LEFT-TO-RIGHT OVERRIDE"),
    (0x202E, "RIGHT-TO-LEFT OVERRIDE"),
    (0x2066, "LEFT-TO-RIGHT ISOLATE"),
    (0x2067, "RIGHT-TO-LEFT ISOLATE"),
    (0x2068, "FIRST STRONG ISOLATE"),
    (0x2069, "POP DIRECTIONAL ISOLATE"),
)
_NAMED_INVISIBLE: dict[str, str] = {chr(cp): name for cp, name in _INVISIBLE_CODEPOINTS}

_ALLOWED_CONTROL = {"\t", "\n", "\r"}


def find_injection_markers(text: str) -> list[str]:
    """Return the distinct injection-marker substrings found in ``text``."""
    found: list[str] = []
    for pattern in _INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            snippet = match.group(0).strip()
            if snippet not in found:
                found.append(snippet)
    return found


def find_invisible_chars(text: str) -> list[str]:
    """Return the names of invisible / control code points found in ``text``."""
    found: list[str] = []
    for ch in text:
        if ch in _NAMED_INVISIBLE:
            name = _NAMED_INVISIBLE[ch]
        elif ch not in _ALLOWED_CONTROL and unicodedata.category(ch) in ("Cc", "Cf"):
            name = f"U+{ord(ch):04X} ({unicodedata.category(ch)})"
        else:
            continue
        if name not in found:
            found.append(name)
    return found


__all__ = ["find_injection_markers", "find_invisible_chars"]
