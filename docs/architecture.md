# Architecture

bastion is a JSON-RPC 2.0 man-in-the-middle between an MCP client and the MCP
servers it uses. It presents as the server to the real client and as the
client to the real server, so every tool definition, tool call, and tool
result crosses it.

## Trust boundary

bastion is the only trusted component. Both the MCP client and every MCP
server are treated as hostile: a server can ship poisoned tool definitions or
inject instructions into results, and a client (driven by a compromised agent)
can attempt to exfiltrate data through tool-call arguments.

## Components

```
  MCP client                 bastion gateway              MCP server
       |                                                       |
       |   transport: JSON-RPC framing (stdio / HTTP)           |
       +<----------------->  proxy: session + pump  <---------->+
                             interceptor: PolicyInterceptor
                                |        |        |
                             engine   catalog   audit sink
```

- **transport** (`transport/`) confines all protocol knowledge. `stdio.py`
  spawns and supervises a child MCP server; `http.py` is a FastAPI gateway.
  `framing.py` handles newline-delimited JSON-RPC.
- **proxy** (`proxy/`) is the stdio core: `MCPSession` tracks the handshake
  and request-id correlation; `MessagePump` runs two independent async
  forwarding loops (one per direction) so neither can block the other;
  `MCPGateway` wires it together.
- **interceptor** (`rules/interceptor.py`) classifies each frame and runs the
  policy engine at three points: `tools/list` results, `tools/call` requests,
  and `tools/call` results.
- **engine** (`rules/`) loads a YAML policy, instantiates rules, and evaluates
  them under a per-rule timeout and a total budget.
- **catalog** (`catalog/`) fingerprints tool definitions and pins baselines
  for rug-pull detection.
- **audit** (`audit/`) records every call, result, and flagged definition to
  a SQLite or JSONL sink.

## Enforcement model

- A blocked **request** is answered with a spec-valid JSON-RPC error carrying
  the original id, so a block never hangs the agent.
- A blocked tool **definition** is redacted from the `tools/list` result; the
  poisoned tool never reaches the client.
- A blocked **result** is replaced with an error response.
- An `require_approval` verdict is resolved against the approval store
  (remembered decisions), then the broker (live decisions), then a configurable
  fallback.

## Latency

bastion is in the hot path of every tool call. Each rule runs under a per-rule
timeout; the engine tracks a total budget and, on breach, fails closed (blocks)
or open per `on_budget_exceeded`. Default rules are regex/hash based and carry
no ML dependency.
