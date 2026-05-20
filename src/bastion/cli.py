"""bastion command-line interface.

Commands import their heavy dependencies lazily so ``bastion --help`` and
``bastion version`` stay fast.
"""

from __future__ import annotations

import asyncio
import sys

import click

from bastion import __version__


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="bastion")
def cli() -> None:
    """bastion - a runtime security gateway for MCP tool-call traffic."""


@cli.command()
def version() -> None:
    """Print the bastion version."""
    click.echo(__version__)


@cli.command(
    context_settings={"ignore_unknown_options": True},
    short_help="Run the stdio interception gateway in front of an MCP server.",
)
@click.option(
    "--policy",
    default=None,
    help="Policy to enforce: a bundled name (default/strict/minimal) or a path. "
    "Omit for transparent passthrough.",
)
@click.option(
    "--capture",
    default=None,
    help="Record every frame to a JSONL capture file for later replay.",
)
@click.option("--log-level", default="INFO", show_default=True)
@click.option(
    "--log-format",
    type=click.Choice(["console", "json"]),
    default="console",
    show_default=True,
)
@click.argument("server_command", nargs=-1, required=True, type=click.UNPROCESSED)
def stdio(
    policy: str | None,
    capture: str | None,
    log_level: str,
    log_format: str,
    server_command: tuple[str, ...],
) -> None:
    """Mediate an MCP server spoken over stdio.

    Wire bastion into an MCP client config by pointing a server entry at:

        bastion stdio --policy default -- <real-server-command...>
    """
    from bastion.core.logger import configure
    from bastion.proxy.gateway import MCPGateway
    from bastion.proxy.pump import Interceptor

    configure(level=log_level, fmt=log_format)  # type: ignore[arg-type]

    interceptor: Interceptor | None = None
    audit_sink = None
    if policy is not None:
        from bastion.approval.store import ApprovalStore
        from bastion.audit import build_sink
        from bastion.core.models import Decision
        from bastion.rules.engine import PolicyEngine, validate_policy
        from bastion.rules.interceptor import PolicyInterceptor
        from bastion.rules.schema import resolve_policy_path

        policy_path = resolve_policy_path(policy)
        ok, errors = validate_policy(policy_path)
        if not ok:
            for err in errors:
                click.echo(f"  {err}", err=True)
            click.echo(f"invalid policy: {policy_path}", err=True)
            sys.exit(2)
        engine = PolicyEngine.from_policy_file(policy_path)
        audit_sink = build_sink(engine.policy.audit)
        approval = engine.policy.approval
        store = ApprovalStore(approval.store) if approval.store else None
        unresolved = Decision.BLOCK if approval.on_unresolved == "block" else Decision.ALLOW
        interceptor = PolicyInterceptor(
            engine,
            server_label=server_command[0],
            audit_sink=audit_sink,
            record_arguments=engine.policy.audit.record_arguments,
            approval_store=store,
            unresolved_decision=unresolved,
        )

    if capture is not None:
        from bastion.audit.replay import RecordingInterceptor, SessionRecorder
        from bastion.proxy.pump import PassthroughInterceptor

        interceptor = RecordingInterceptor(
            interceptor or PassthroughInterceptor(), SessionRecorder(capture)
        )

    async def _run() -> int:
        try:
            gateway = await MCPGateway.for_stdio(list(server_command), interceptor=interceptor)
            return await gateway.run()
        finally:
            if audit_sink is not None:
                await audit_sink.close()

    try:
        exit_code = asyncio.run(_run())
    except KeyboardInterrupt:
        exit_code = 130
    sys.exit(exit_code)


@cli.command()
@click.argument("policy")
def lint(policy: str) -> None:
    """Validate a policy file (bundled name or path)."""
    from bastion.rules.engine import validate_policy
    from bastion.rules.schema import resolve_policy_path

    path = resolve_policy_path(policy)
    ok, errors = validate_policy(path)
    if ok:
        click.echo(f"ok: {path}")
        return
    for err in errors:
        click.echo(f"  {err}", err=True)
    click.echo(f"invalid: {path}", err=True)
    sys.exit(1)


@cli.command(name="rules")
def rules_cmd() -> None:
    """List every registered policy rule."""
    import bastion.rules.checks  # noqa: F401  (populates the registry)
    from bastion.rules import registry

    click.echo(f"{'RULE':22} {'CLASS':7} {'SEVERITY':9} QUALITY")
    for rule_id, cls in sorted(registry.all_rules().items()):
        click.echo(f"{rule_id:22} {cls.threat_class.value:7} {cls.severity.value:9} {cls.quality}")


@cli.command(
    context_settings={"ignore_unknown_options": True},
    short_help="Scan an MCP server's tool catalog against a policy.",
)
@click.option("--policy", default="default", show_default=True)
@click.argument("server_command", nargs=-1, required=True, type=click.UNPROCESSED)
def scan(policy: str, server_command: tuple[str, ...]) -> None:
    """Connect to an MCP server, pull its tool catalog, and audit it.

    Exits non-zero if any tool definition is blocked - usable as a CI gate.
    """
    from bastion.core.logger import configure

    configure(level="WARNING", fmt="console")
    findings = asyncio.run(_run_scan(policy, list(server_command)))
    blocked = [f for f in findings if f[1]]
    for name, reason in findings:
        if reason:
            click.echo(f"  BLOCK  {name}: {reason}")
        else:
            click.echo(f"  ok     {name}")
    click.echo(f"\n{len(findings)} tool(s) scanned, {len(blocked)} blocked [policy: {policy}]")
    if blocked:
        sys.exit(1)


async def _run_scan(policy: str, server_command: list[str]) -> list[tuple[str, str | None]]:
    from bastion.proxy.probe import probe_tools
    from bastion.proxy.session import MCPSession
    from bastion.rules.engine import PolicyEngine
    from bastion.rules.schema import resolve_policy_path
    from bastion.rules.types import RuleContext

    engine = PolicyEngine.from_policy_file(resolve_policy_path(policy))
    probe = await probe_tools(server_command)
    label = server_command[0]
    ctx = RuleContext(
        session=MCPSession(server_label=label),
        catalog=engine.catalog,
        server_label=label,
    )
    findings: list[tuple[str, str | None]] = []
    for tool in probe.tools:
        verdict = await engine.evaluate_tool_def(tool, ctx)
        findings.append((tool.name, verdict.reason if verdict.blocked else None))
    return findings


@cli.command(short_help="Run the HTTP interception gateway in front of an MCP server.")
@click.option("--upstream", required=True, help="Upstream MCP server URL.")
@click.option("--policy", default="default", show_default=True)
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8900, show_default=True, type=int)
@click.option("--log-level", default="INFO", show_default=True)
def serve(upstream: str, policy: str, host: str, port: int, log_level: str) -> None:
    """Mediate an MCP server reachable over Streamable HTTP."""
    from bastion.core.logger import configure

    configure(level=log_level, fmt="console")
    try:
        import uvicorn

        from bastion.transport.http import build_http_app
    except ImportError:
        click.echo("the 'http' extra is required: pip install 'bastion[http]'", err=True)
        sys.exit(2)

    from bastion.approval.broker import ApprovalBroker
    from bastion.approval.store import ApprovalStore
    from bastion.audit import build_sink
    from bastion.core.models import Decision
    from bastion.rules.engine import PolicyEngine, validate_policy
    from bastion.rules.interceptor import PolicyInterceptor
    from bastion.rules.schema import resolve_policy_path

    policy_path = resolve_policy_path(policy)
    ok, errors = validate_policy(policy_path)
    if not ok:
        for err in errors:
            click.echo(f"  {err}", err=True)
        click.echo(f"invalid policy: {policy_path}", err=True)
        sys.exit(2)

    engine = PolicyEngine.from_policy_file(policy_path)
    approval = engine.policy.approval
    unresolved = Decision.BLOCK if approval.on_unresolved == "block" else Decision.ALLOW
    interceptor = PolicyInterceptor(
        engine,
        server_label=upstream,
        audit_sink=build_sink(engine.policy.audit),
        record_arguments=engine.policy.audit.record_arguments,
        approval_store=ApprovalStore(approval.store) if approval.store else None,
        approval_broker=ApprovalBroker(
            timeout_seconds=approval.timeout_seconds, default_on_timeout=unresolved
        ),
        unresolved_decision=unresolved,
    )
    app = build_http_app(interceptor=interceptor, upstream_url=upstream, server_label=upstream)
    uvicorn.run(app, host=host, port=port, log_level=log_level.lower())


@cli.group("approvals")
def approvals_group() -> None:
    """Manage remembered approval decisions."""


_STORE_OPTION = click.option(
    "--store",
    "store_path",
    default="bastion-approvals.json",
    show_default=True,
    help="Path to the approval store.",
)


@approvals_group.command("list")
@_STORE_OPTION
def approvals_list(store_path: str) -> None:
    """List remembered approval decisions."""
    from bastion.approval.store import ApprovalStore

    records = ApprovalStore(store_path).all_records()
    if not records:
        click.echo("no remembered approvals")
        return
    for record in records:
        note = f"  ({record.note})" if record.note else ""
        click.echo(f"  {record.decision:5} {record.server} :: {record.tool}{note}")


@approvals_group.command("allow")
@_STORE_OPTION
@click.option("--server", required=True)
@click.option("--tool", required=True)
@click.option("--note", default="")
def approvals_allow(store_path: str, server: str, tool: str, note: str) -> None:
    """Remember an allow decision for a tool."""
    from bastion.approval.store import ApprovalStore

    ApprovalStore(store_path).remember(server, tool, "allow", note)
    click.echo(f"remembered: allow {server} :: {tool}")


@approvals_group.command("deny")
@_STORE_OPTION
@click.option("--server", required=True)
@click.option("--tool", required=True)
@click.option("--note", default="")
def approvals_deny(store_path: str, server: str, tool: str, note: str) -> None:
    """Remember a deny decision for a tool."""
    from bastion.approval.store import ApprovalStore

    ApprovalStore(store_path).remember(server, tool, "deny", note)
    click.echo(f"remembered: deny {server} :: {tool}")


@approvals_group.command("revoke")
@_STORE_OPTION
@click.option("--server", required=True)
@click.option("--tool", required=True)
def approvals_revoke(store_path: str, server: str, tool: str) -> None:
    """Forget a remembered decision for a tool."""
    from bastion.approval.store import ApprovalStore

    removed = ApprovalStore(store_path).revoke(server, tool)
    click.echo("revoked" if removed else "no such remembered decision")


@cli.command()
@click.option("--db", "db_path", default="bastion-audit.db", show_default=True)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "html", "sarif"]),
    default="json",
    show_default=True,
)
@click.option("--output", "-o", default=None, help="Write to a file instead of stdout.")
def report(db_path: str, fmt: str, output: str | None) -> None:
    """Render the audit trail as a JSON, HTML, or SARIF report."""
    from pathlib import Path

    from bastion.reporters import render_report

    text = render_report(db_path, fmt)
    if output:
        Path(output).write_text(text, encoding="utf-8")
        click.echo(f"wrote {fmt} report to {output}")
    else:
        click.echo(text)


@cli.command()
@click.option("--db", "db_path", default="bastion-audit.db", show_default=True)
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8901, show_default=True, type=int)
def dashboard(db_path: str, host: str, port: int) -> None:
    """Serve the read-only audit dashboard."""
    try:
        import uvicorn

        from bastion.dashboard.server import build_dashboard_app
    except ImportError:
        click.echo("the 'http' extra is required: pip install 'bastion[http]'", err=True)
        sys.exit(2)
    uvicorn.run(build_dashboard_app(db_path), host=host, port=port, log_level="warning")


@cli.command()
@click.argument("capture")
@click.option("--policy", default="default", show_default=True)
def replay(capture: str, policy: str) -> None:
    """Replay a recorded session capture through a policy.

    Re-runs captured traffic against a (possibly different) policy and reports
    what it would decide - a safe way to test a policy change.
    """
    from bastion.core.logger import configure

    configure(level="WARNING", fmt="console")
    redacted, blocked, total = asyncio.run(_run_replay(capture, policy))
    click.echo(f"replayed {total} frame(s) through policy '{policy}'")
    click.echo(f"  tools redacted: {redacted}")
    click.echo(f"  calls blocked:  {blocked}")
    if redacted or blocked:
        sys.exit(1)


async def _run_replay(capture: str, policy: str) -> tuple[int, int, int]:
    from bastion.audit.replay import load_capture, replay_capture
    from bastion.rules.engine import PolicyEngine
    from bastion.rules.interceptor import PolicyInterceptor
    from bastion.rules.schema import resolve_policy_path

    engine = PolicyEngine.from_policy_file(resolve_policy_path(policy))
    interceptor = PolicyInterceptor(engine, server_label="replay")
    frames = load_capture(capture)
    await replay_capture(frames, interceptor)
    return (
        interceptor.stats["tools_redacted"],
        interceptor.stats["calls_blocked"],
        len(frames),
    )


def main() -> None:
    """Console-script entry point."""
    cli()


if __name__ == "__main__":
    main()
