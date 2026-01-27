# CLAUDE.md — btx_lib_mail

## Project Overview

`btx_lib_mail` is a Python library providing SMTP email delivery with a
rich-click CLI. It supports multipart UTF-8 messages, attachments, STARTTLS,
authentication, and multi-host failover.

## Quick Commands

```bash
make test          # ruff lint + pyright + bandit + pytest (100% coverage target)
make clean         # remove build artifacts
```

## Project Layout

```
src/btx_lib_mail/
  __init__.py          # public re-exports
  __init__conf__.py    # static metadata (version, author, shell_command)
  __main__.py          # python -m entry point
  behaviors.py         # scaffold helpers (greeting, noop, intentional failure)
  cli.py               # rich-click CLI adapter (send, validate-email, validate-smtp-host, etc.)
  lib_mail.py          # core SMTP delivery logic, validators, configuration

tests/
  conftest.py          # shared fixtures (cli_runner, traceback isolation)
  test_behaviors.py    # behavior helper tests
  test_cli.py          # CLI command tests
  test_lib_mail.py     # core mail logic + validator tests
  test_metadata.py     # metadata constant tests
  test_module_entry.py # python -m entry tests
  test_scripts.py      # automation script tests
```

## Key Architecture

- **Config**: `ConfMail` (Pydantic model) holds SMTP settings; global `conf` instance
- **Delivery**: `send()` → `_prepare_*` helpers → `_deliver_to_any_host` → `_deliver_via_host`
- **Validation**: `validate_email_address()` and `validate_smtp_host()` are public
- **CLI**: `cli.py` uses rich-click groups; `lib_cli_exit_tools` handles exit codes

## Testing Conventions

- All tests use `RecordingSMTP` to stub `smtplib.SMTP`
- `_reset_conf_mail` autouse fixture restores global config between tests
- Markers: `os_agnostic`, `integration` (real SMTP via `TEST_SMTP_*` env vars)
- Doctests run via `--doctest-modules` in pytest config
- Coverage must be ≥85% (currently 100%)

## Style & Tooling

- Python ≥3.10; `from __future__ import annotations` in every module
- `ruff` for linting/formatting (line-length 160)
- `pyright` strict mode
- `bandit` security scanning
- `import-linter` enforces layer contracts (CLI depends on behaviors only)

## Public API

```python
from btx_lib_mail import (
    ConfMail, conf, send, logger,
    validate_email_address, validate_smtp_host,
)
```

## CLI Commands

```
btx-lib-mail send              # send an email
btx-lib-mail validate-email    # validate email address syntax
btx-lib-mail validate-smtp-host # validate SMTP host format (IPv6-aware)
btx-lib-mail info              # show package metadata
btx-lib-mail hello             # emit greeting
btx-lib-mail fail              # trigger intentional failure
```

## Version

Current: 1.2.0 (see `pyproject.toml` and `__init__conf__.py`)
