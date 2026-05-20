"""Detection of credentials and sensitive filesystem paths.

Backs the argument-exfiltration rule. Matches are returned redacted so a
finding can be logged or audited without copying the secret itself.
"""

from __future__ import annotations

import re

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
)

_SENSITIVE_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:^|/|~)\.ssh/", re.I),
    re.compile(r"\bid_(?:rsa|ed25519|ecdsa|dsa)\b", re.I),
    re.compile(r"\.aws/credentials", re.I),
    re.compile(r"(?:^|/)\.env(?:\.|\b)", re.I),
    re.compile(r"/etc/(?:shadow|passwd|sudoers)", re.I),
    re.compile(r"\.kube/config", re.I),
    re.compile(r"\b\.(?:npmrc|pypirc|netrc|dockercfg)\b", re.I),
)


def redact(value: str) -> str:
    """Return a non-reversible preview of a sensitive value."""
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-2:]}"


def find_secrets(text: str) -> list[tuple[str, str]]:
    """Return ``(kind, redacted)`` pairs for every credential found in ``text``."""
    found: list[tuple[str, str]] = []
    for kind, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            found.append((kind, redact(match.group(0))))
    return found


def find_sensitive_paths(text: str) -> list[str]:
    """Return the distinct sensitive filesystem paths referenced in ``text``."""
    found: list[str] = []
    for pattern in _SENSITIVE_PATH_PATTERNS:
        match = pattern.search(text)
        if match and match.group(0) not in found:
            found.append(match.group(0))
    return found


__all__ = ["find_secrets", "find_sensitive_paths", "redact"]
