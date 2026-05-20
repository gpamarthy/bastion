"""MCP transport layer: JSON-RPC framing and the stdio / HTTP transports.

All protocol-specific knowledge lives here so the proxy core stays
transport-agnostic above :class:`bastion.transport.base.Transport`.
"""
