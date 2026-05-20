"""Process-wide settings, resolved from the environment.

Kept deliberately tiny - bastion takes almost all configuration from the
policy YAML, not from env vars. Only cross-cutting runtime knobs live here.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

_ENV_PREFIX = "BASTION_"


@dataclass(frozen=True, slots=True)
class Settings:
    """Resolved runtime settings."""

    log_level: str = "INFO"
    log_format: str = "console"

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            log_level=os.environ.get(f"{_ENV_PREFIX}LOG_LEVEL", "INFO"),
            log_format=os.environ.get(f"{_ENV_PREFIX}LOG_FORMAT", "console"),
        )


__all__ = ["Settings"]
