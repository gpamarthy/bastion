# Threat model

bastion defends an MCP-based agent deployment. The trust boundary places
bastion as the only trusted component; the MCP client and every MCP server are
adversaries. It targets ten MCP-specific attack classes.

| Code  | Attack                       | bastion mechanism                                                |
|-------|------------------------------|------------------------------------------------------------------|
| MCP01 | Tool poisoning               | `tool_poisoning`: injection-marker scan of every tool description |
| MCP02 | Rug pull (definition drift)  | `rug_pull`: fingerprint pinned on first use, drift blocked        |
| MCP03 | Tool shadowing               | `shadowing`: cross-server tool-name collision flagged             |
| MCP04 | Hidden instructions          | `hidden_instructions`: invisible chars + nested-schema deep walk  |
| MCP05 | Argument exfiltration        | `arg_exfiltration`: secret / sensitive-path / PII scan of args    |
| MCP06 | Schema violation             | `arg_schema`: arguments validated against the declared schema     |
| MCP07 | Result injection             | `result_injection`: injection scan of `tools/call` results        |
| MCP08 | Capability escalation        | `capability_grant`: per-tool allow / deny / require-approval      |
| MCP09 | Resource abuse               | `resource_guard`: filesystem and network egress allow-lists       |
| MCP10 | Rate / consumption abuse     | `rate_limit`: per-tool and per-session call ceilings              |

## Attack detail

**Tool poisoning (MCP01).** A malicious server hides instructions in a tool's
human-readable description. When the agent reads the catalog, the instructions
become part of its context. bastion scans every description for injection
markers and redacts a poisoned tool from `tools/list`.

**Rug pull (MCP02).** A server ships a benign tool, waits for approval, then
swaps in a malicious definition. bastion pins the fingerprint of each tool on
first sight and blocks any later definition that drifts. Pinning a poisoned
first-seen definition is not a gap: the poisoning and hidden-instruction rules
inspect every definition on every list.

**Tool shadowing (MCP03).** A server registers a tool whose name collides with
a trusted tool from another server. bastion flags a definition whose name is
already pinned under a different server.

**Hidden instructions (MCP04).** Payloads are obfuscated with zero-width or
bidirectional characters, or buried in nested `inputSchema` fields a human
reviewer never reads. bastion deep-walks the whole definition.

**Argument exfiltration (MCP05).** A confused-deputy or compromised agent
smuggles secrets out through tool-call arguments. bastion scans every string
argument for credentials and sensitive filesystem paths.

**Schema violation (MCP06).** Arguments that violate the tool's own declared
`inputSchema` indicate a buggy client or a type-confusion attack.

**Result injection (MCP07).** A tool result is untrusted data read straight
into the agent's context; bastion applies the injection detectors to it.

**Capability escalation (MCP08).** The capability table gates each call;
unmatched tools fall back to `default_decision`.

**Resource abuse (MCP09).** Filesystem-path and network-host allow-lists bound
where a tool call may reach.

**Rate abuse (MCP10).** Per-tool and per-session ceilings bound a runaway or
abusive agent.

## Known limitations

- The HTTP gateway streams `text/event-stream` responses through without
  per-event inspection.
- PII detection is opt-in; it is off by default to keep the false-positive
  rate low on tools that legitimately take an email or address.
- Rug-pull pinning is trust-on-first-use. An out-of-band approved-pin workflow
  hardens it.
