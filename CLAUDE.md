# CLAUDE.md  -  btx_lib_mail

## Project Overview

`btx_lib_mail` is a Python library providing SMTP email delivery with a
rich-click CLI. It supports multipart UTF-8 messages, attachments, STARTTLS,
authentication, multi-host failover, and comprehensive attachment security.

## Quick Commands

```bash
make test          # ruff format + lint, pyright, bandit, import-linter, pip-audit, pytest (coverage gated)
make clean         # remove build artifacts
make help          # every target, read from the generated Makefile
```

## Project Layout

```
src/btx_lib_mail/
  __init__.py          # public re-exports (__all__)
  __init__conf__.py    # static metadata (version, author, shell_command) and print_info()
  __main__.py          # python -m entry point: runs cli.main()
  behaviors.py         # scaffold helpers (greeting, noop, intentional failure)
  cli/                 # rich-click CLI adapter (send, validate-email, validate-smtp-host, info, hello, fail)
    __init__.py        #   public surface: cli, main, CliContext, the commands, traceback helpers
    _settings_sources.py #   options > environment > env file: Sources, resolve_*, env/password files
    _output.py         #   CliContext, emit (human or JSON), error_payload, collect_skipped
    _traceback.py      #   traceback limits and the lib_cli_exit_tools state helpers
    _commands.py       #   the cli group and info, hello, validate-email, validate-smtp-host, fail
    _send_command.py   #   send: one ConfMail from options > environment > env file > conf
    _dispatch.py       #   main(): run_cli, the JSON failure handler, traceback restore
  lib_mail.py          # send() and the public re-exports of the private modules below
  _config.py           # ConfMail and the global conf
  _attachments.py      # attachment security: blocklists, path checks, open-once
  _validation.py       # email and host syntax, EHLO name, durations, recipient and host lists
  _compose.py          # message assembly: shared body encoded once, per-recipient header lines
  _transport.py        # Transport protocol, DeliveryOptions, SmtplibTransport (BDAT/DATA), deadline
  _common.py           # logger, printable(), is_valid_unicode()
  _descriptor_path.py  # descriptor_path(): the path the kernel holds for an open file (per OS)
  errors.py            # BtxMailError and its subclasses
  secret_safety.py     # SecretSafeModel, redact_validation_error: credential-safe pydantic errors
  typed_click.py       # typed Protocol facade over rich-click's partially-typed decorators

tests/
  conftest.py                  # shared fixtures (cli_runner, traceback isolation, data_server)
  smtp_test_server.py          # real in-process aiosmtpd server helpers (DATA and BDAT)
  test_attachment_integrity.py # open once, encode once, swaps, growth, closed handles, subject/timeout
  test_behaviors.py            # behavior helper tests
  test_cli.py                  # CLI group, traceback handling, simple commands
  test_cli_send.py             # send command: settings sources, --env-file, --password-file, --json, real server
  test_deadline.py             # delivery deadline against a dripping server
  test_errors.py               # BtxMailError hierarchy at every raise site
  test_lib_mail.py             # configuration, validators, attachment rules, orchestration
  test_limits.py               # per-call ceilings: address length, recipient and attachment counts
  log_capture.py               # everything_logged(), assert_never_logged(): a secret in text, bytes or AUTH PLAIN form
  test_log_capture.py          # the never-logged check finds every planted form
  transport_doubles.py         # RecordingTransport / RefusingTransport, typed against Transport
  test_metadata.py             # metadata constant tests
  test_module_entry.py         # python -m entry tests
  test_packaging.py            # builds the sdist and refuses anything outside its include list
  test_secret_safety.py        # SecretSafeModel / redact_validation_error tests
  test_streaming.py            # wire tests (real aiosmtpd): DATA/BDAT, dot-stuffing, STARTTLS+AUTH, EHLO name
  test_transfer_memory.py      # tracemalloc bound while streaming (sink server, DATA and BDAT)
```

## Key Architecture

- **Config**: `ConfMail` (Pydantic model, `_config.py`) holds SMTP and security settings; global `conf` instance;
  an unknown key is refused (`extra="forbid"`); every refusal is a `ConfigurationError`
- **Delivery**: `send()` -> `prepare_recipients` -> `prepare_attachments` (each path checked, then the file opened
  ONCE) -> `prepare_hosts` -> `check_subject` / `envelope_header_lines` (all refusals before the first delivery) ->
  `compose_body_once` (shared body + attachments encoded once per call) -> per recipient `message_for` (its header
  lines + the shared body, read in place) -> `_deliver_to_any_host` (rewinds, failover across hosts; an unreachable host is tried last for the rest of the call) -> injected
  `Transport` (`SmtplibTransport` streams DATA/BDAT, one connection per recipient)
- **EHLO name**: `ConfMail.smtp_local_hostname` / `send(local_hostname=)` / `--local-hostname` /
  `BTX_MAIL_SMTP_LOCAL_HOSTNAME`; unset, `_default_local_hostname()` computes smtplib's default once per process
- **Validation**: `validate_email_address()` and `validate_smtp_host()` are public;
  `validate_smtp_host()` refuses a host carrying `@` or `/`, or an interior whitespace or
  control character, without echoing the value, and a malformed port, bracket, host name
  (empty or over-long label, label hyphen, over 253 characters, non-IP bracket content)
  or a comma (two hosts in one string); `ConfMail.smtphosts` runs it on every non-blank entry
- **Security**: `AttachmentSecurityOptions` + `_validate_attachment_security()` (path rules) + `_open_attachment()`
  (same file, regular, size) in `_attachments.py`; extension sets are normalised wherever they are given
- **Errors**: every on-purpose exception is a `BtxMailError`; each concrete class also subclasses the builtin a caller
  would catch (`InvalidInputError` ValueError, `ConfigurationError` ValidationError, `AttachmentNotFoundError`
  FileNotFoundError, `DeliveryError` RuntimeError with `failed_recipients`/`hosts`)
- **CLI**: the `cli` package uses rich-click groups; `lib_cli_exit_tools` handles exit codes (`docs/cli.md`, "Exit codes").
  `send` builds one `ConfMail` (a copy of `conf`, each resolved option assigned with validation) from options >
  environment > the env file (`--env-file`, else `./.env`) and calls `send(config=)`. `ctx.obj` is a typed
  `CliContext` (output mode, traceback, and a `transport` seam for embedding/tests). `--json`/`--json-bare` on the
  group (read from the tokens before the subcommand); failures become JSON in `main()`'s exception handler.
  `python -m btx_lib_mail` runs `cli.main()` too
- **Deadline**: `ConfMail.smtp_delivery_deadline` / `send(delivery_deadline=)` / `--delivery-deadline`; a watchdog
  thread shuts the socket down when one SMTP session overruns (`_session_deadline`)

## Testing Conventions

- Tests inject a `Transport` double from `tests/transport_doubles.py` (`RecordingTransport`,
  `RefusingTransport`, checked against the protocol by pyright) through `send(transport=)`
  (CLI tests through `invoke(..., obj=CliContext(transport=...))`); wire tests use a real
  in-process `aiosmtpd` server (`tests/smtp_test_server.py`, `data_server` fixture in conftest),
  never a socket-level monkeypatch. The package's own code is not patched, except the
  `lib_mail.DEFAULT_TRANSPORT` seam and the fault injections in `test_secret_safety.py` that
  reach its fail-closed branches; the CLI plumbing is driven through `main()`
- `_reset_conf_mail` autouse fixture restores global config between tests
- Markers: `os_agnostic`, `os_windows`, `os_macos`, `os_posix`, `os_linux`, `local_only`
  (real SMTP via `TEST_SMTP_*` env vars)
- Doctests run via `--doctest-modules` in pytest config
- Coverage must be at least 85% (`fail_under = 85` in `pyproject.toml`); read the actual figure
  from `make test`'s coverage summary or `coverage.xml` rather than a number restated here

## Style & Tooling

- Python 3.10+; `from __future__ import annotations` in every module
- `ruff` for linting/formatting (line-length 160)
- `pyright` strict mode
- Docstrings: Google style (Args/Returns/Raises/Examples, Attributes for classes), enforced on `src/` by ruff's `D` rules
- `bandit` security scanning
- `import-linter` enforces one layers contract (a module imports only from layers below it; modules in one layer
  are independent): `cli` > `lib_mail` > `_compose` > `_config | _transport` > `_attachments | _validation` >
  `secret_safety | errors` > `_common | _descriptor_path` > `behaviors`

## Public API

```python
from btx_lib_mail import (
    # Core
    ConfMail, conf, send, logger,
    validate_email_address, validate_smtp_host,
    # Scaffold helpers (behaviors.py) and metadata (__init__conf__.py)
    CANONICAL_GREETING, emit_greeting, noop_main, raise_intentional_failure, print_info,
    # Delivery seam
    DeliveryOptions, Transport,
    # Errors (every one is a BtxMailError)
    BtxMailError, InvalidInputError, ConfigurationError,
    AttachmentNotFoundError, DeliveryError,
    # Security
    AttachmentSecurityError,
    AttachmentViolation,
    DANGEROUS_EXTENSIONS_POSIX,
    DANGEROUS_EXTENSIONS_WINDOWS,
    DANGEROUS_DIRECTORIES_POSIX,
    DANGEROUS_DIRECTORIES_WINDOWS,
    SENSITIVE_PATH_PATTERNS,
    # Secret safety
    SecretSafeModel,
    redact_validation_error,
    REDACTED_INPUT,
)
```

`SmtplibTransport` is importable from `btx_lib_mail.lib_mail`.

## CLI Commands

```
btx-lib-mail [--json|--json-bare] [--traceback] <command> ...
btx-lib-mail send               # send an email (settings: options > env > --env-file > conf)
btx-lib-mail validate-email     # validate email address syntax
btx-lib-mail validate-smtp-host # validate SMTP host format (IPv6-aware)
btx-lib-mail info               # show package metadata
btx-lib-mail hello              # emit greeting
btx-lib-mail fail               # trigger intentional failure
```

## Attachment Security

Attachments are validated against multiple security checks:

1. **Path Traversal**  -  a `..` path component is rejected
2. **Symlinks**  -  a symlink as the last component is rejected by default (`attachment_allow_symlinks=False`)
3. **Sensitive Patterns**  -  `/.ssh/`, `/id_rsa`, `/.env`, `/.netrc`, etc. always blocked; case ignored on macOS/Windows only
4. **Directory Restrictions**  -  System directories blocked by default
5. **Extension Filtering**  -  POSIX and Windows dangerous extensions (`.sh`, `.exe`, etc.) blocked on every platform
6. **Size Limits**  -  Default 25 MiB (`attachment_max_size_bytes`), also enforced while reading
7. **One open file**  -  each file opened once after its checks; a swapped path (or parent directory) is refused as `CHANGED`
8. **File name**  -  a control character (Unicode `Cc`), a bidirectional formatting character or invalid Unicode in the name, or NUL in the path, is refused as `FILENAME`

### Configuration Fields (ConfMail)

| Field                                    | Type                      | Default                 |
|------------------------------------------|---------------------------|-------------------------|
| `attachment_allowed_extensions`          | `frozenset[str] \| None`  | `None` (blacklist)      |
| `attachment_blocked_extensions`          | `frozenset[str]`          | POSIX + Windows dangers |
| `attachment_allowed_directories`         | `frozenset[Path] \| None` | `None` (blacklist)      |
| `attachment_blocked_directories`         | `frozenset[Path]`         | OS-specific sensitive   |
| `attachment_max_size_bytes`              | `int \| None`             | `26_214_400` (25 MiB)   |
| `attachment_max_count`                   | `int \| None`             | `100`                   |
| `attachment_allow_symlinks`              | `bool`                    | `False`                 |
| `attachment_raise_on_security_violation` | `bool`                    | `True`                  |
| `attachment_allow_empty_blocklists`      | `bool`                    | `False`                 |

### Environment Variables

| Variable                                | Purpose                         |
|-----------------------------------------|---------------------------------|
| `BTX_MAIL_ATTACHMENT_ALLOWED_EXT`       | Allowed extensions (whitelist)  |
| `BTX_MAIL_ATTACHMENT_BLOCKED_EXT`       | Blocked extensions (override)   |
| `BTX_MAIL_ATTACHMENT_ALLOWED_DIRS`      | Allowed directories (whitelist) |
| `BTX_MAIL_ATTACHMENT_BLOCKED_DIRS`      | Blocked directories (override)  |
| `BTX_MAIL_ATTACHMENT_MAX_SIZE`          | Max size in bytes               |
| `BTX_MAIL_ATTACHMENT_MAX_COUNT`         | Max attachments per call        |
| `BTX_MAIL_ATTACHMENT_ALLOW_SYMLINKS`    | Allow symlinks (boolean)        |
| `BTX_MAIL_ATTACHMENT_RAISE_ON_SECURITY` | Raise on violation (boolean)    |

### CLI Options (send command)

```
--attachment-allowed-ext .pdf,.txt    # whitelist mode
--attachment-blocked-ext .exe,.bat    # override blacklist
--attachment-allowed-dir /path        # whitelist mode (repeat for multiple)
--attachment-blocked-dir /path        # override blacklist (repeat for multiple)
--attachment-max-size 50000000        # 50 MiB
--attachment-max-count 10             # at most 10 attachments
--attachment-allow-symlinks           # allow symlinks
--attachment-no-symlinks              # reject symlinks (default)
--attachment-strict                   # raise on violation (default)
--attachment-warn                     # log warning and skip
```

## Version

The version lives in `pyproject.toml` and `__init__conf__.py`; read it there rather than a number restated here.

## Attachment Streaming

Attachments are streamed, not buffered whole. No off-the-shelf Python library
streams SMTP attachments or implements the client side of RFC 3030 BDAT/CHUNKING
(stdlib `smtplib` and `aiosmtpd` both buffer and lack BDAT), so it is hand-rolled
on stdlib:

- `compose_body_once` / `_compose_body` (`_compose.py`) serialise the recipient-independent body into a
  `SpooledTemporaryFile` (in memory below 1 MiB, on disk above it) using `EmailMessage` + `email.policy.SMTP`
  (CRLF), once per `send()`, streaming each attachment's base64 from its already-open file in `57 * 1024`-byte
  reads so a large attachment is never held whole; `message_for` joins a recipient's header lines with that spool,
  read in place, so scratch disk is the encoded body (about 1.37x the attachment) once.
- `SmtplibTransport` streams the message to the socket in `STREAM_CHUNK_SIZE` (64 KiB) chunks: RFC 3030 `BDAT`
  when the server advertises `CHUNKING`, otherwise the `DATA` phase with `_DotStuffer` incremental dot-stuffing.
  Peak transfer memory is about one chunk.
- Delivery goes through the `Transport` protocol (injected via `send(transport=)`);
  tests use a real `FakeTransport` (orchestration) and a real in-process `aiosmtpd`
  server (wire behaviour), never a socket-level monkeypatch.

Wire behaviour is proven end to end in `tests/test_streaming.py` (DATA + BDAT round-trips, dot-stuffing edge cases,
STARTTLS+AUTH), and the memory bounds in `tests/test_streaming.py` (composing) and `tests/test_transfer_memory.py`
(streaming).
