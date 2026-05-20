# Security Policy

## Reporting a vulnerability

bastion is a security tool; vulnerabilities in it are taken seriously. Report
issues privately to the maintainer rather than opening a public issue. Include
a description, affected version, and a reproduction if possible.

## Threat posture

bastion treats both the MCP client and every MCP server passing through it as
hostile. It is designed to operate fully offline: it makes no outbound network
calls and emits no telemetry. Tool definitions and tool-call arguments never
leave the host.

stdout in stdio mode is reserved exclusively for the MCP JSON-RPC stream - all
logging and diagnostics go to stderr - so bastion never corrupts the protocol
channel it mediates.
