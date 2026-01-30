# CLAUDE.md — btx_lib_mail

## Project Overview

`btx_lib_mail` is a Python library providing SMTP email delivery with a
rich-click CLI. It supports multipart UTF-8 messages, attachments, STARTTLS,
authentication, multi-host failover, and comprehensive attachment security.

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
  lib_mail.py          # core SMTP delivery logic, validators, configuration, security

tests/
  conftest.py          # shared fixtures (cli_runner, traceback isolation)
  test_behaviors.py    # behavior helper tests
  test_cli.py          # CLI command tests
  test_lib_mail.py     # core mail logic + validator + security tests
  test_metadata.py     # metadata constant tests
  test_module_entry.py # python -m entry tests
  test_scripts.py      # automation script tests
```

## Key Architecture

- **Config**: `ConfMail` (Pydantic model) holds SMTP and security settings; global `conf` instance
- **Delivery**: `send()` → `_prepare_*` helpers → `_deliver_to_any_host` → `_deliver_via_host`
- **Validation**: `validate_email_address()` and `validate_smtp_host()` are public
- **Security**: `AttachmentSecurityOptions` + `_validate_attachment_security()` orchestrate checks
- **CLI**: `cli.py` uses rich-click groups; `lib_cli_exit_tools` handles exit codes

## Testing Conventions

- All tests use `RecordingSMTP` to stub `smtplib.SMTP`
- `_reset_conf_mail` autouse fixture restores global config between tests
- Markers: `os_agnostic`, `integration` (real SMTP via `TEST_SMTP_*` env vars)
- Doctests run via `--doctest-modules` in pytest config
- Coverage must be ≥85% (currently ~97%)

## Style & Tooling

- Python ≥3.10; `from __future__ import annotations` in every module
- `ruff` for linting/formatting (line-length 160)
- `pyright` strict mode
- `bandit` security scanning
- `import-linter` enforces layer contracts (CLI depends on behaviors only)

## Public API

```python
from btx_lib_mail import (
    # Core
    ConfMail, conf, send, logger,
    validate_email_address, validate_smtp_host,
    # Security
    AttachmentSecurityError,
    DANGEROUS_EXTENSIONS_POSIX,
    DANGEROUS_EXTENSIONS_WINDOWS,
    DANGEROUS_DIRECTORIES_POSIX,
    DANGEROUS_DIRECTORIES_WINDOWS,
    SENSITIVE_PATH_PATTERNS,
)
```

## CLI Commands

```
btx-lib-mail send               # send an email
btx-lib-mail validate-email     # validate email address syntax
btx-lib-mail validate-smtp-host # validate SMTP host format (IPv6-aware)
btx-lib-mail info               # show package metadata
btx-lib-mail hello              # emit greeting
btx-lib-mail fail               # trigger intentional failure
```

## Attachment Security

Attachments are validated against multiple security checks:

1. **Path Traversal** — Paths with `..` are rejected
2. **Symlinks** — Rejected by default (`attachment_allow_symlinks=False`)
3. **Sensitive Patterns** — `/.ssh/`, `/id_rsa`, `/.env`, etc. always blocked
4. **Directory Restrictions** — System directories blocked by default
5. **Extension Filtering** — Dangerous extensions (`.sh`, `.exe`, etc.) blocked
6. **Size Limits** — Default 25 MiB (`attachment_max_size_bytes`)

### Configuration Fields (ConfMail)

| Field                                    | Type                      | Default              |
|------------------------------------------|---------------------------|----------------------|
| `attachment_allowed_extensions`          | `frozenset[str] \| None`  | `None` (blacklist)   |
| `attachment_blocked_extensions`          | `frozenset[str]`          | OS-specific dangers  |
| `attachment_allowed_directories`         | `frozenset[Path] \| None` | `None` (blacklist)   |
| `attachment_blocked_directories`         | `frozenset[Path]`         | OS-specific sensitive|
| `attachment_max_size_bytes`              | `int \| None`             | `26_214_400` (25 MiB)|
| `attachment_allow_symlinks`              | `bool`                    | `False`              |
| `attachment_raise_on_security_violation` | `bool`                    | `True`               |

### Environment Variables

| Variable                              | Purpose                           |
|---------------------------------------|-----------------------------------|
| `BTX_MAIL_ATTACHMENT_ALLOWED_EXT`     | Allowed extensions (whitelist)    |
| `BTX_MAIL_ATTACHMENT_BLOCKED_EXT`     | Blocked extensions (override)     |
| `BTX_MAIL_ATTACHMENT_ALLOWED_DIRS`    | Allowed directories (whitelist)   |
| `BTX_MAIL_ATTACHMENT_BLOCKED_DIRS`    | Blocked directories (override)    |
| `BTX_MAIL_ATTACHMENT_MAX_SIZE`        | Max size in bytes                 |
| `BTX_MAIL_ATTACHMENT_ALLOW_SYMLINKS`  | Allow symlinks (boolean)          |
| `BTX_MAIL_ATTACHMENT_RAISE_ON_SECURITY` | Raise on violation (boolean)    |

### CLI Options (send command)

```
--attachment-allowed-ext .pdf,.txt    # whitelist mode
--attachment-blocked-ext .exe,.bat    # override blacklist
--attachment-allowed-dir /path        # whitelist mode (repeat for multiple)
--attachment-blocked-dir /path        # override blacklist (repeat for multiple)
--attachment-max-size 50000000        # 50 MiB
--attachment-allow-symlinks           # allow symlinks
--attachment-no-symlinks              # reject symlinks (default)
--attachment-strict                   # raise on violation (default)
--attachment-warn                     # log warning and skip
```

## Version

Current: 1.2.1 (see `pyproject.toml` and `__init__conf__.py`)
