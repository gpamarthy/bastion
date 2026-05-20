"""Lightweight PII detection.

Available to the argument-exfiltration rule as an opt-in detector. It is *not*
on by default: many honest tools legitimately take an email or an address as
an argument, so blocking on PII would be noisy. Operators enable it explicitly.
"""

from __future__ import annotations

import re

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn_ok(digits: str) -> bool:
    """Return True if ``digits`` passes the Luhn checksum."""
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def find_pii(text: str) -> list[tuple[str, str]]:
    """Return ``(kind, value-or-redaction)`` pairs for PII found in ``text``."""
    found: list[tuple[str, str]] = []
    for match in _EMAIL.finditer(text):
        found.append(("email", match.group(0)))
    for match in _IPV4.finditer(text):
        found.append(("ipv4", match.group(0)))
    for match in _SSN.finditer(text):
        found.append(("ssn", f"***-**-{match.group(0)[-4:]}"))
    for match in _CARD.finditer(text):
        digits = re.sub(r"[ -]", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            found.append(("credit_card", f"****{digits[-4:]}"))
    return found


__all__ = ["find_pii"]
