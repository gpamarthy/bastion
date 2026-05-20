"""Hot-reload support for the policy engine.

The dashboard's ``/admin/reload`` endpoint and a SIGHUP handler rebuild the
engine from disk without dropping the catalog (pins survive a reload).
"""

from __future__ import annotations

from pathlib import Path

from bastion.catalog.registry import ToolCatalog
from bastion.core import logger
from bastion.rules.engine import PolicyEngine
from bastion.rules.schema import load_policy

log = logger.get_logger(__name__)


def reload_engine(path: Path | str, *, catalog: ToolCatalog | None = None) -> PolicyEngine:
    """Rebuild a :class:`PolicyEngine` from ``path``, reusing ``catalog`` if given."""
    policy = load_policy(Path(path))
    engine = PolicyEngine(policy, catalog=catalog)
    log.info("policy reloaded", policy=policy.name, rules=len(engine.rules))
    return engine


__all__ = ["reload_engine"]
