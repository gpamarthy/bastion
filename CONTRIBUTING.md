# Contributing

## Development setup

```bash
make install     # create .venv and install with dev + http extras
```

## Before opening a pull request

```bash
make lint        # ruff check + format check
make typecheck   # mypy --strict on src/
make test        # full pytest suite
make benchmark   # detection benchmark over the adversarial corpus
```

All four must pass. CI runs them on Python 3.10 through 3.13 and enforces an
85% branch-coverage floor.

## Adding a rule

1. Add a module under `src/bastion/rules/checks/` and decorate the class with
   `@register("your_rule_id")`.
2. Declare `threat_class` and `severity`; override one or more of
   `inspect_tool_def`, `inspect_tool_call`, `inspect_tool_result`.
3. Import it in `src/bastion/rules/checks/__init__.py`.
4. Add unit tests under `tests/rules/` and, where applicable, labelled cases
   under `tests/adversarial/`.

## Conventions

- stdout is the MCP channel in stdio mode: never `print` to stdout in `src/`.
- Keep the dependency surface small; it is a security tool.
- A blocked request must always be answered with a spec-valid JSON-RPC error.
