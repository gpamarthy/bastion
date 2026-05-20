# bastion

**A runtime security gateway for MCP (Model Context Protocol) tool-call traffic.**

bastion is a transparent JSON-RPC man-in-the-middle that sits between an MCP
client (Claude Code, Cursor, an agent runtime) and the MCP servers it uses. It
inspects every tool definition, every tool call, and every tool result on the
wire, enforces a policy-as-code ruleset, blocks malicious traffic before the
model ever sees it, and writes an evidence-grade audit trail.

It treats both the MCP client and every MCP server as hostile; bastion is the
only trusted component.

## Why bastion exists

The AI-agent security market splits in two, and misses the middle:

- **Content-layer detectors** (Lakera Guard, LLM Guard) score prompts and
  completions. They never see the JSON-RPC tool-call layer where MCP attacks
  actually live.
- **Routing / governance gateways** (Kong AI Gateway, MintMCP) handle auth and
  observability, but do little adversarial detection.

bastion is the intersection nobody ships: **inline JSON-RPC enforcement** +
**tool-definition integrity over time** + **portable policy-as-code** +
**fully offline operation** + **evidence-grade audit**, with a reproducible
attack corpus and OWASP / MITRE ATLAS mappings.

### bastion is not warden

A sibling project, [`warden`](https://github.com/gpamarthy/warden), polices
LLM **completion** traffic (HTTP, OpenAI/Anthropic schemas). bastion polices
agent **tool-call** traffic at the MCP transport layer (JSON-RPC 2.0 over stdio
and Streamable HTTP). Different wire, different threat model, different policy
primitive: capability grants per tool, not content checks.

## Threat coverage

bastion targets ten MCP-specific attack classes. Full detail in
[`docs/threat-model.md`](docs/threat-model.md); framework cross-references in
[`docs/mappings.md`](docs/mappings.md).

| Code  | Attack                       | Rule                  | Enforcement       |
|-------|------------------------------|-----------------------|-------------------|
| MCP01 | Tool poisoning               | `tool_poisoning`      | redact from list  |
| MCP02 | Rug pull (definition drift)  | `rug_pull`            | redact from list  |
| MCP03 | Tool shadowing               | `shadowing`           | flag for approval |
| MCP04 | Hidden instructions          | `hidden_instructions` | redact from list  |
| MCP05 | Argument exfiltration        | `arg_exfiltration`    | block the call    |
| MCP06 | Schema violation             | `arg_schema`          | block the call    |
| MCP07 | Result injection             | `result_injection`    | block the result  |
| MCP08 | Capability escalation        | `capability_grant`    | allow/deny/approve|
| MCP09 | Resource abuse               | `resource_guard`      | block the call    |
| MCP10 | Rate / consumption abuse     | `rate_limit`          | block the call    |

## Quickstart

```bash
make install        # create .venv and install with dev extras
make test           # run the suite
make benchmark      # precision / recall / F1 over the attack corpus
```

Audit a server's tool catalog without proxying it (a usable CI gate):

```bash
bastion scan --policy default -- python examples/poisoned-server/server.py
```

Wire bastion into an MCP client by pointing a server entry at it. In a Claude
Code `.mcp.json`:

```jsonc
{
  "mcpServers": {
    "filesystem": {
      "command": "bastion",
      "args": ["stdio", "--policy", "default", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "/work"]
    }
  }
}
```

bastion spawns the real server as a child process and mediates every message.

## CLI

| Command              | Purpose                                                  |
|----------------------|----------------------------------------------------------|
| `bastion stdio`      | stdio interception gateway in front of an MCP server     |
| `bastion serve`      | Streamable-HTTP interception gateway (`http` extra)      |
| `bastion scan`       | one-shot audit of a server's tool catalog                |
| `bastion lint`       | validate a policy file                                   |
| `bastion rules`      | list registered rules                                    |
| `bastion approvals`  | manage remembered allow/deny decisions                   |
| `bastion report`     | render the audit trail as JSON / HTML / SARIF            |
| `bastion dashboard`  | serve the read-only audit dashboard (`http` extra)       |
| `bastion replay`     | replay a recorded session capture through a policy       |

Three bundled policies ship: `minimal` (detection only), `default` (gated,
unmatched tools held for approval), and `strict` (deny by default).

## Architecture

```
  MCP client                 bastion gateway              MCP server
  (Claude Code)                                          (child process)
       |                                                       |
       |   stdin/stdout    +-----------------------+   pipes    |
       +<----------------->|  transport  (framing) |<---------->+
                           |  session    (id map)  |
                           |  pump  (2 directions) |
                           |  interceptor + engine |
                           |  catalog  +  audit    |
                           +-----------------------+
```

Two independent async tasks move frames, one per direction, so neither
direction can block the other. Every frame is offered to the policy engine
before forwarding; a blocked request is answered with a spec-valid JSON-RPC
error carrying the original id, so a block never hangs the agent. See
[`docs/architecture.md`](docs/architecture.md).

## Design posture

- **Offline by default.** No outbound network calls, no telemetry. No tool
  definition ever leaves the host.
- **Small dependency surface.** It is a security tool; every dependency is a
  liability. The core needs only pydantic, pyyaml, structlog, click, aiosqlite.
- **Fail-closed under load.** When the policy budget is exceeded, bastion
  blocks rather than waving traffic through.
- **Evidence-grade audit.** Every call, result, and flagged definition is
  recorded with its taxonomy mapping, exportable as SARIF.

## Status

Milestones M1 through M5 are complete: stdio and HTTP transports, the ten-rule
policy engine, the catalog and rug-pull pinning, argument inspection, the audit
trail, the approval flow, session replay, reporting, and the dashboard. See
[`CHANGELOG.md`](CHANGELOG.md).

The suite is 165 tests (unit, transport, rules, integration, CLI, and a
labelled adversarial corpus) at ~90% branch coverage, gated at 85% in CI;
`ruff` and `mypy --strict` are clean.

Known limitations are documented in [`docs/threat-model.md`](docs/threat-model.md):
the HTTP gateway streams SSE responses through without per-event inspection,
and rug-pull pinning is trust-on-first-use.

## License

MIT, see [LICENSE](LICENSE).
