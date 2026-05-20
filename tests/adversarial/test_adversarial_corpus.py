"""Adversarial corpus runner.

Every YAML file under ``tests/adversarial/<category>/`` is one labelled case.
A case has a ``kind`` (``definition``, ``call``, or ``result``, default
``definition``) and the verdict bastion must reach. Attack cases must be
blocked; benign cases must pass (a benign case that blocks is a false
positive, tracked here as a hard failure).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from bastion.core.models import ToolCall, ToolDefinition, ToolResult
from bastion.proxy.session import MCPSession
from bastion.rules.engine import PolicyEngine
from bastion.rules.schema import PolicyConfig, RuleEntry
from bastion.rules.types import RuleContext, Verdict

pytestmark = pytest.mark.adversarial

_CORPUS_DIR = Path(__file__).parent
_CASES = sorted(p for p in _CORPUS_DIR.rglob("*.yaml"))

# Stateless detection rules; rug-pull / capability / rate-limit are stateful or
# policy-driven and are tested separately.
_POLICY = PolicyConfig(
    name="corpus",
    rules=[
        RuleEntry(id="tool_poisoning"),
        RuleEntry(id="hidden_instructions"),
        RuleEntry(id="arg_exfiltration"),
        RuleEntry(id="result_injection"),
    ],
)


def _case_id(path: Path) -> str:
    return f"{path.parent.name}/{path.stem}"


async def _evaluate(case: dict[str, Any], engine: PolicyEngine, ctx: RuleContext) -> Verdict:
    kind = case.get("kind", "definition")
    if kind == "call":
        spec = case["call"]
        call = ToolCall(
            tool_name=spec["name"],
            arguments=spec.get("arguments", {}),
            request_id=1,
            raw=spec,
        )
        return await engine.evaluate_tool_call(call, ctx)
    if kind == "result":
        spec = case["result"]
        result = ToolResult(content=spec.get("content", []), is_error=False, raw=spec)
        return await engine.evaluate_tool_result(result, None, ctx)
    return await engine.evaluate_tool_def(ToolDefinition.from_raw(case["tool"]), ctx)


@pytest.mark.parametrize("case_path", _CASES, ids=[_case_id(p) for p in _CASES])
async def test_corpus_case(case_path: Path) -> None:
    case = yaml.safe_load(case_path.read_text(encoding="utf-8"))
    engine = PolicyEngine(_POLICY)
    ctx = RuleContext(
        session=MCPSession(server_label="corpus"),
        catalog=engine.catalog,
        server_label="corpus",
    )
    verdict = await _evaluate(case, engine, ctx)

    if case["expect"] == "block":
        assert verdict.blocked, f"{_case_id(case_path)}: expected block, case passed"
    else:
        assert not verdict.blocked, (
            f"{_case_id(case_path)}: false positive, benign case blocked ({verdict.reason})"
        )


def test_corpus_is_not_empty() -> None:
    assert _CASES, "no adversarial corpus files found"
