"""End-to-end tests of approval resolution through the stdio gateway."""

from __future__ import annotations

import pytest
from conftest import HarnessFactory

from bastion.approval.store import ApprovalStore
from bastion.core.models import Decision, MessageKind
from bastion.rules.engine import PolicyEngine
from bastion.rules.interceptor import PolicyInterceptor
from bastion.rules.schema import CapabilityGrant, PolicyConfig, RuleEntry

pytestmark = pytest.mark.integration

# A policy that holds every call to `echo` for approval.
_APPROVAL_POLICY = PolicyConfig(
    name="approval-test",
    default_decision="allow",
    capabilities=[CapabilityGrant(tool="echo", decision="require_approval")],
    rules=[RuleEntry(id="capability_grant")],
)


def _interceptor(
    *, store: ApprovalStore | None = None, unresolved: Decision = Decision.BLOCK
) -> PolicyInterceptor:
    return PolicyInterceptor(
        PolicyEngine(_APPROVAL_POLICY),
        server_label="fake",
        approval_store=store,
        unresolved_decision=unresolved,
    )


async def _call_echo(harness_factory: HarnessFactory, interceptor: PolicyInterceptor):
    harness = await harness_factory(interceptor=interceptor)
    await harness.initialize()
    return await harness.request("tools/call", 2, {"name": "echo", "arguments": {"text": "hi"}})


async def test_unresolved_approval_blocks_by_default(
    harness_factory: HarnessFactory,
) -> None:
    response = await _call_echo(harness_factory, _interceptor())
    assert response.kind is MessageKind.ERROR


async def test_unresolved_approval_can_fall_back_to_allow(
    harness_factory: HarnessFactory,
) -> None:
    response = await _call_echo(harness_factory, _interceptor(unresolved=Decision.ALLOW))
    assert response.kind is MessageKind.RESPONSE


async def test_remembered_allow_lets_the_call_through(
    harness_factory: HarnessFactory,
) -> None:
    store = ApprovalStore()
    store.remember("fake", "echo", "allow")
    response = await _call_echo(harness_factory, _interceptor(store=store))
    assert response.kind is MessageKind.RESPONSE
    assert response.result["content"][0]["text"] == "hi"


async def test_remembered_deny_blocks_the_call(
    harness_factory: HarnessFactory,
) -> None:
    store = ApprovalStore()
    store.remember("fake", "echo", "deny")
    response = await _call_echo(harness_factory, _interceptor(store=store))
    assert response.kind is MessageKind.ERROR
