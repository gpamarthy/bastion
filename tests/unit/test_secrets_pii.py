"""Tests for the secret, sensitive-path, and PII detectors."""

from __future__ import annotations

from bastion.detectors.pii import find_pii
from bastion.detectors.secrets import find_secrets, find_sensitive_paths, redact


def test_find_secrets_detects_aws_key() -> None:
    found = find_secrets("credentials: AKIAIOSFODNN7EXAMPLE here")
    assert any(kind == "aws_access_key_id" for kind, _ in found)


def test_find_secrets_detects_private_key_header() -> None:
    found = find_secrets("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert any(kind == "private_key" for kind, _ in found)


def test_find_secrets_redacts_the_value() -> None:
    found = find_secrets("AKIAIOSFODNN7EXAMPLE")
    assert found
    _, value = found[0]
    assert "IOSFODNN" not in value


def test_find_secrets_clean_text() -> None:
    assert find_secrets("just an ordinary sentence with no secrets") == []


def test_find_sensitive_paths() -> None:
    assert find_sensitive_paths("/home/user/.ssh/id_rsa")
    assert find_sensitive_paths("~/.aws/credentials")
    assert find_sensitive_paths("read the project README") == []


def test_find_pii_email_and_ssn() -> None:
    found = dict(find_pii("contact bob@example.com or SSN 123-45-6789"))
    assert "email" in found
    assert "ssn" in found


def test_find_pii_credit_card_requires_luhn() -> None:
    valid = find_pii("card 4111111111111111")  # passes Luhn
    invalid = find_pii("card 1234567812345678")  # fails Luhn
    assert any(k == "credit_card" for k, _ in valid)
    assert not any(k == "credit_card" for k, _ in invalid)


def test_redact_short_value() -> None:
    assert redact("abc") == "***"
