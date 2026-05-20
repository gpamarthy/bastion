# Operator runbook

## Deploying bastion

### stdio mode

Point an MCP client's server entry at bastion instead of the real server:

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

### HTTP mode

```bash
bastion serve --upstream https://mcp.internal.example.com/mcp --policy strict
```

Clients then point at `http://127.0.0.1:8900/mcp`.

## Choosing a policy

- `minimal`  - detection only; blocks poisoned definitions, no capability gating.
- `default`  - definition rules block; calls gated, unmatched tools held for approval.
- `strict`   - deny by default; only explicitly granted tools may be called.

Validate a policy before deploying: `bastion lint <policy>`.
Audit a server's catalog without proxying it: `bastion scan -- <server-cmd>`.

## Approvals

Pre-approve or deny tools out of band:

```bash
bastion approvals allow  --server filesystem --tool read_file
bastion approvals deny   --server filesystem --tool delete_file
bastion approvals list
```

The running gateway consults the approval store before holding a call.

## Reading the audit trail

```bash
bastion report --format html -o audit.html      # human review
bastion report --format sarif -o audit.sarif    # code-scanning ingest
bastion dashboard --db bastion-audit.db          # live view on :8901
```

## Responding to a finding

1. A `block` row with taxonomy `MCP01`/`MCP04` means a poisoned tool was
   redacted. Inspect the server; do not re-enable it until the definition is
   clean.
2. An `MCP02` block means a tool definition drifted. Confirm the change was
   intentional; if so, clear the pin store entry to re-pin the new baseline.
3. An `MCP05` block means a tool call carried a secret or sensitive path.
   Treat as a potential exfiltration attempt and review the session.
4. Repeated `MCP10` blocks indicate a runaway agent; check the session id.
