# Third-party licenses

bastion depends on the following third-party packages. Each is distributed
under its own license; consult the package for the full text.

## Runtime (core)

| Package    | License      |
|------------|--------------|
| pydantic   | MIT          |
| PyYAML     | MIT          |
| structlog  | MIT / Apache-2.0 |
| click      | BSD-3-Clause |
| aiosqlite  | MIT          |

## Runtime (`http` extra)

| Package    | License      |
|------------|--------------|
| fastapi    | MIT          |
| uvicorn    | BSD-3-Clause |
| httpx      | BSD-3-Clause |

## Development only

ruff, mypy, pytest, pytest-asyncio, pytest-cov, hypothesis, pre-commit,
types-PyYAML. These are not distributed with bastion and are used only to
build and test it.
