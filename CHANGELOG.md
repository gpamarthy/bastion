# Changelog

All notable changes to bastion are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added - M5: dashboard + reporting + docs

- Audit reporters: JSON, self-contained HTML, and SARIF 2.1.0 (for ingest by
  code-scanning dashboards). `bastion report` renders any of them.
- Read-only audit dashboard (`bastion dashboard`) with a live HTML view and
  JSON APIs, optional token auth.
- Session capture and replay: `bastion stdio --capture` records every frame;
  `bastion replay` re-runs a capture through a (possibly different) policy.
- Reproducible detection benchmark (`make benchmark`) reporting precision,
  recall, F1, and false-positive rate over the labelled corpus.
- Documentation: architecture, threat model, framework mappings
  (OWASP / MITRE ATLAS), and an operator runbook.
- Test suite of 165 tests (unit, transport, rules, integration, CLI, and the
  adversarial corpus) at ~90% branch coverage, with an 85% CI floor.

### Added - M4: approval flow + HTTP transport

- Approval flow: an `ApprovalStore` of remembered allow/deny decisions and an
  `ApprovalBroker` for live decisions with timeout-to-default. The interceptor
  resolves an approval verdict against the store, then the broker, then a
  configurable fallback (`block`/`allow`).
- `bastion approvals` CLI group: `list`, `allow`, `deny`, `revoke`.
- Streamable-HTTP gateway: `bastion serve --upstream URL` runs a FastAPI
  `POST /mcp` endpoint that intercepts the JSON request/response path with the
  same policy engine; SSE responses stream through. Requires the `http` extra.
- Policy schema gained an `approval` block (store path, timeout, fallback).

### Added - M3: argument inspection + audit

- Six new rules: `arg_exfiltration` (MCP05), `arg_schema` (MCP06),
  `result_injection` (MCP07), `resource_guard` (MCP09), `shadowing` (MCP03),
  and `rate_limit` (MCP10).
- Secret, sensitive-path, and PII detectors; an inline JSON-Schema subset
  validator (no schema-validation dependency).
- Evidence-grade audit trail: `AuditEvent` model with `full`/`redacted`/
  `hashed` argument recording, and SQLite and JSONL sinks. The
  `PolicyInterceptor` records every tool call, every tool result, and every
  flagged tool definition.
- All bundled policies updated to enable the M3 rules.

### Added - M2: catalog + rule engine + first rules

- Tool catalog: canonical SHA-256 fingerprinting, structural definition
  diffing, and a pin store (in-memory or JSON-file backed) for rug-pull
  baselines.
- Policy engine: YAML policy schema, plug-in rule registry, per-rule timeout
  and total-budget enforcement, and a `PolicyEngine` that evaluates tool
  definitions, calls, and results.
- Four rules: `tool_poisoning` (MCP01), `rug_pull` (MCP02),
  `hidden_instructions` (MCP04), and `capability_grant` (MCP08).
- Content detectors: injection-marker, invisible/bidi-character, and
  entropy/string-walk helpers.
- `PolicyInterceptor` wiring the engine into the gateway: poisoned tools are
  redacted from `tools/list`, denied calls are blocked. Approval verdicts are
  logged and allowed through pending the M4 approval broker.
- Three bundled policies (`default`, `strict`, `minimal`) and CLI commands
  `lint`, `rules`, and `scan`; `stdio` gained `--policy`.
- A deliberately malicious example MCP server and a labelled adversarial
  corpus with a parametrised runner.

### Added - M1: transport + passthrough gateway

- JSON-RPC 2.0 framing for the MCP stdio transport (`encode`, `decode_line`,
  streaming `FrameReader`) with partial-read reassembly and a 16 MiB frame
  ceiling.
- `Transport` abstraction with a stdio implementation: client-side binding to
  the process's own stdin/stdout and a `SubprocessServer` that spawns and
  supervises the real MCP server.
- `MCPSession` connection state - `initialize` handshake capture and
  request-id → method correlation.
- `MessagePump` - two-direction async forwarding with an `Interceptor` seam;
  blocked requests answered with a spec-valid JSON-RPC error.
- `MCPGateway` wiring transports, session, and pump into one connection.
- `bastion stdio` CLI command.
- Fake MCP server fixture plus unit, transport, and integration test suites.
