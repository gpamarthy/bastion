"""The bastion MCP threat taxonomy.

Every rule maps to exactly one :class:`ThreatClass`. ``docs/mappings.md``
cross-references each class to OWASP LLM Top 10, OWASP Top 10 for Agentic
Applications, and MITRE ATLAS.
"""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Finding severity, ordered low to critical."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatClass(str, Enum):
    """MCP-specific attack classes bastion detects or enforces against."""

    TOOL_POISONING = "MCP01"
    RUG_PULL = "MCP02"
    TOOL_SHADOWING = "MCP03"
    HIDDEN_INSTRUCTIONS = "MCP04"
    ARG_EXFILTRATION = "MCP05"
    SCHEMA_VIOLATION = "MCP06"
    RESULT_INJECTION = "MCP07"
    CAPABILITY_ESCALATION = "MCP08"
    RESOURCE_ABUSE = "MCP09"
    RATE_ABUSE = "MCP10"


# Human-readable titles, keyed by the taxonomy code, for reports and the CLI.
THREAT_TITLES: dict[ThreatClass, str] = {
    ThreatClass.TOOL_POISONING: "Tool poisoning",
    ThreatClass.RUG_PULL: "Rug pull (tool definition drift)",
    ThreatClass.TOOL_SHADOWING: "Tool shadowing",
    ThreatClass.HIDDEN_INSTRUCTIONS: "Hidden instructions in tool schema",
    ThreatClass.ARG_EXFILTRATION: "Argument exfiltration",
    ThreatClass.SCHEMA_VIOLATION: "Argument schema violation",
    ThreatClass.RESULT_INJECTION: "Prompt injection via tool result",
    ThreatClass.CAPABILITY_ESCALATION: "Capability escalation",
    ThreatClass.RESOURCE_ABUSE: "Resource abuse",
    ThreatClass.RATE_ABUSE: "Rate / consumption abuse",
}


__all__ = ["THREAT_TITLES", "Severity", "ThreatClass"]
