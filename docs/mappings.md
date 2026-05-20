# Framework mappings

Every bastion threat class is cross-referenced to recognised AI-security
frameworks so findings slot into existing risk and compliance processes.

| bastion | Title                   | OWASP LLM Top 10        | OWASP Agentic Top 10            | MITRE ATLAS                          |
|---------|-------------------------|-------------------------|---------------------------------|--------------------------------------|
| MCP01   | Tool poisoning          | LLM01 Prompt Injection  | Tool Misuse / Goal Manipulation | Publish Poisoned AI Agent Tool       |
| MCP02   | Rug pull                | LLM03 Supply Chain      | Tool Misuse                     | AI Supply Chain Compromise           |
| MCP03   | Tool shadowing          | LLM01 Prompt Injection  | Identity & Privilege Abuse      | Publish Poisoned AI Agent Tool       |
| MCP04   | Hidden instructions     | LLM01 Prompt Injection  | Goal Manipulation               | LLM Prompt Injection                 |
| MCP05   | Argument exfiltration   | LLM02 Sensitive Disclosure | Tool Misuse                  | Exfiltration via AI Inference        |
| MCP06   | Schema violation        | LLM05 Improper Output   | Tool Misuse                     | -                                    |
| MCP07   | Result injection        | LLM01 Prompt Injection  | Goal Manipulation               | LLM Prompt Injection (Indirect)      |
| MCP08   | Capability escalation   | LLM06 Excessive Agency  | Identity & Privilege Abuse      | -                                    |
| MCP09   | Resource abuse          | LLM06 Excessive Agency  | Tool Misuse                     | -                                    |
| MCP10   | Rate / consumption abuse| LLM10 Unbounded Consumption | Resource Overload          | Denial of AI Service                 |

References:

- OWASP Top 10 for LLM Applications (2025).
- OWASP Top 10 for Agentic Applications / Agentic Security Initiative (2026).
- MITRE ATLAS (Adversarial Threat Landscape for AI Systems).

Each rule also declares its `ThreatClass` in code (`core/taxonomy.py`), so the
audit trail and SARIF report carry the mapping with every finding.
