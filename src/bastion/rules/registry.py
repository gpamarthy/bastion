"""Plug-in registry for :class:`Rule` subclasses.

Rules register themselves via ``@register("id")`` at import time. The engine
resolves rule ids named in a policy YAML against this registry.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from bastion.core.errors import PolicyConfigError

if TYPE_CHECKING:
    from bastion.rules.base import Rule

_REGISTRY: dict[str, type[Rule]] = {}


def register(name: str) -> Callable[[type[Rule]], type[Rule]]:
    """Register a Rule subclass under ``name``.

    Re-registering the identical class (or a reloaded copy from the same
    module:qualname) is idempotent; a genuinely different class claiming a
    taken name raises.
    """

    def decorator(cls: type[Rule]) -> type[Rule]:
        cls.rule_id = name
        existing = _REGISTRY.get(name)
        if existing is not None and existing is not cls:
            same_origin = getattr(existing, "__module__", None) == getattr(
                cls, "__module__", None
            ) and getattr(existing, "__qualname__", None) == getattr(cls, "__qualname__", None)
            if not same_origin:
                raise PolicyConfigError(
                    f"rule id collision: {name} "
                    f"(existing={existing.__module__}.{existing.__qualname__}, "
                    f"new={cls.__module__}.{cls.__qualname__})",
                )
        _REGISTRY[name] = cls
        return cls

    return decorator


def get(name: str) -> type[Rule]:
    """Resolve a rule id to its registered class."""
    if name not in _REGISTRY:
        raise PolicyConfigError(f"unknown rule id: {name}")
    return _REGISTRY[name]


def all_rules() -> dict[str, type[Rule]]:
    """Return a snapshot of the registry."""
    return dict(_REGISTRY)


def reset() -> None:
    """Clear the registry. Test helper only."""
    _REGISTRY.clear()


__all__ = ["all_rules", "get", "register", "reset"]
