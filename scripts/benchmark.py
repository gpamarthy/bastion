#!/usr/bin/env python3
"""bastion detection benchmark.

Runs every labelled case in ``tests/adversarial/`` through the rule engine and
reports precision, recall, F1, and the false-positive rate. Numbers are only
as good as the corpus - this is a reproducible harness, not a vendor claim.

Usage: python scripts/benchmark.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import yaml

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

from bastion.core.models import ToolCall, ToolDefinition, ToolResult  # noqa: E402
from bastion.proxy.session import MCPSession  # noqa: E402
from bastion.rules.engine import PolicyEngine  # noqa: E402
from bastion.rules.schema import PolicyConfig, RuleEntry  # noqa: E402
from bastion.rules.types import RuleContext  # noqa: E402

_CORPUS = _ROOT / "tests" / "adversarial"
_POLICY = PolicyConfig(
    name="benchmark",
    rules=[
        RuleEntry(id="tool_poisoning"),
        RuleEntry(id="hidden_instructions"),
        RuleEntry(id="arg_exfiltration"),
        RuleEntry(id="result_injection"),
    ],
)


async def _evaluate(case: dict[str, Any], engine: PolicyEngine, ctx: RuleContext) -> bool:
    kind = case.get("kind", "definition")
    if kind == "call":
        spec = case["call"]
        call = ToolCall(spec["name"], spec.get("arguments", {}), 1, spec)
        verdict = await engine.evaluate_tool_call(call, ctx)
    elif kind == "result":
        spec = case["result"]
        result = ToolResult(spec.get("content", []), False, spec)
        verdict = await engine.evaluate_tool_result(result, None, ctx)
    else:
        verdict = await engine.evaluate_tool_def(ToolDefinition.from_raw(case["tool"]), ctx)
    return verdict.blocked


async def main() -> int:
    cases = sorted(_CORPUS.rglob("*.yaml"))
    tp = fp = tn = fn = 0
    failures: list[str] = []

    for path in cases:
        case = yaml.safe_load(path.read_text(encoding="utf-8"))
        engine = PolicyEngine(_POLICY)
        ctx = RuleContext(MCPSession(server_label="bench"), engine.catalog, "bench")
        blocked = await _evaluate(case, engine, ctx)
        is_attack = case["expect"] == "block"
        name = f"{path.parent.name}/{path.stem}"
        if is_attack and blocked:
            tp += 1
        elif is_attack and not blocked:
            fn += 1
            failures.append(f"  MISS  {name} (attack not blocked)")
        elif not is_attack and blocked:
            fp += 1
            failures.append(f"  FP    {name} (benign blocked)")
        else:
            tn += 1

    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0

    print(f"bastion detection benchmark  ({len(cases)} cases)")
    print(f"  attacks: {tp + fn}   benign: {fp + tn}")
    print(f"  TP={tp}  FN={fn}  FP={fp}  TN={tn}")
    print(f"  precision = {precision:.3f}")
    print(f"  recall    = {recall:.3f}")
    print(f"  f1        = {f1:.3f}")
    print(f"  fpr       = {fpr:.3f}")
    for line in failures:
        print(line)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
