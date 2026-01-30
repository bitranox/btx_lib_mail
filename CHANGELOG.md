# Changelog

## [1.3.0] - 2026-01-30

### Added
- **Attachment security validation** with multiple protection layers:
  - Path traversal prevention (rejects `..` sequences)
  - Symlink handling (rejected by default, configurable via `attachment_allow_symlinks`)
  - Sensitive pattern detection (`/.ssh/`, `/id_rsa`, `/.env`, `/.aws/credentials`, etc.)
  - OS-specific dangerous extension blocking (`.sh`, `.py`, `.exe`, `.bat`, `.ps1`, etc.)
  - OS-specific system directory blocking (`/etc`, `/var`, `C:\Windows`, etc.)
  - Size limit enforcement (default 25 MiB)
- `AttachmentSecurityError` exception with `path`, `reason`, and `violation_type` attributes.
- Public constants for extending or replacing defaults:
  - `DANGEROUS_EXTENSIONS_POSIX` / `DANGEROUS_EXTENSIONS_WINDOWS`
  - `DANGEROUS_DIRECTORIES_POSIX` / `DANGEROUS_DIRECTORIES_WINDOWS`
  - `SENSITIVE_PATH_PATTERNS`
- `ConfMail` fields for attachment security configuration:
  - `attachment_allowed_extensions` / `attachment_blocked_extensions`
  - `attachment_allowed_directories` / `attachment_blocked_directories`
  - `attachment_max_size_bytes`, `attachment_allow_symlinks`
  - `attachment_raise_on_security_violation` (raise vs warn-and-skip)
- Per-call security overrides in `send()` function.
- CLI options for attachment security (`--attachment-allowed-ext`, `--attachment-blocked-ext`,
  `--attachment-allowed-dir`, `--attachment-blocked-dir`, `--attachment-max-size`,
  `--attachment-allow-symlinks`/`--attachment-no-symlinks`, `--attachment-strict`/`--attachment-warn`).
- Environment variables for attachment security (`BTX_MAIL_ATTACHMENT_*`).
- README documentation for attachment security with configuration examples and
  OS-specific default values.

## [1.2.1] - 2026-01-28
### Fixed
- Removed unnecessary `cast(Any, …)` from the `smtp_timeout` assignment test;
  pyright already accepts `float → float` without suppression.

### Changed
- Clarified the `cast(Any, …)` comment in `test_conf_mail_assignment_validates`
  to document it as a deliberate type-mismatch bypass for Pydantic's runtime
  field-validator coercion (`str → list[str]`), not a missing-stub workaround.

## [1.2.0] - 2026-01-27
### Added
- Public `validate_email_address()` for email syntax validation (API + CLI).
- Public `validate_smtp_host()` for SMTP host format validation with IPv6
  bracket support (API + CLI).
- CLI subcommands `validate-email` and `validate-smtp-host`.

### Changed
- SMTP host validation now supports IPv6 bracketed addresses (`[::1]:25`).

### Removed
- `_is_valid_email_address()` — replaced by `validate_email_address()`.
- `_split_host_and_port()` — replaced by `validate_smtp_host()` and `_parse_smtp_host()`.

## [1.1.0] - 2026-01-27
### Added
- `ConfMail` now validates `smtp_timeout` is positive via a Pydantic
  `field_validator`; zero or negative values raise `ValidationError`.
- Per-call `timeout` overrides passed to `send()` are also validated,
  raising `ValueError` for non-positive values.
- `_split_host_and_port()` rejects port numbers outside the 1-65535 range.
- `_prepare_hosts()` eagerly validates port syntax so errors surface before
  the delivery retry loop.
- `send()` validates `mail_from` with the existing `_is_valid_email_address()`
  regex, raising `ValueError` for syntactically invalid sender addresses.

## [1.0.3] - 2025-12-15
### Changed
- Lowered minimum Python version from 3.13 to 3.10, broadening compatibility.
- CI test matrix now covers Python 3.10, 3.11, 3.12, and 3.13.
- Replaced ``tomllib`` with ``rtoml`` in CI workflows for metadata extraction,
  enabling consistent TOML parsing across all supported Python versions.

## [1.0.2] - 2025-12-15
### Fixed
- Email subjects containing non-ASCII characters are now RFC 2047 encoded via
  `email.header.Header`, ensuring proper UTF-8 rendering across mail clients.

## [1.0.1] - 2025-10-16
### Changed
- Regular expression used for email validation is precompiled at import time,
  reducing repeated compilation overhead while keeping behaviour identical.

## [1.0.0] - 2025-10-16
### Added
- Pydantic-powered ``ConfMail`` configuration introduces STARTTLS and optional
  SMTP authentication, plus per-call overrides for credentials and timeouts.
- Unit tests that stub ``smtplib.SMTP`` exercise UTF-8 payloads, attachment
  handling, and multi-host fallbacks while keeping the suite deterministic.
- Optional integration test that sends real mail when ``TEST_SMTP_HOSTS`` and
  ``TEST_RECIPIENTS`` are defined (shell environment or project ``.env``),
  exercising UTF-8 content, HTML body, and attachment delivery against staging
  SMTP relays.
- CLI subcommand ``send`` exposes :func:`btx_lib_mail.lib_mail.send`,
  honouring ``BTX_MAIL_*`` environment variables or command-line overrides for
  hosts, recipients, sender, STARTTLS, credentials, and attachments.

### Changed
- ``lib_mail.send`` now renders messages as UTF-8, performs STARTTLS when
  configured, logs failed host attempts at warning level, and guarantees clean
  connection teardown via context managers.
- Documentation (README and module reference) now describes the mail helper
  surface, accepted ``smtphosts`` shapes, and the new security options.
- Dropped legacy compatibility branches for Python releases prior to 3.13 and
  refreshed type hints to use modern built-in generics throughout the CLI and
  mail modules.
- Raised the runtime ``pydantic`` floor to ``>=2.12.2`` so the configuration
  model tracks the latest validation improvements.
- STARTTLS is now enabled by default (``smtp_use_starttls=True``); disable it
  explicitly via CLI flags, environment variables, or `ConfMail` updates when
  targeting servers without STARTTLS support.
- Added support for ``BTX_MAIL_SMTP_TIMEOUT``/`--timeout`, allowing CLI users to
  adjust the SMTP socket timeout (default remains 30 seconds).
- GitHub Actions workflows now enable pip caching via ``actions/setup-python@v6``
  and pin ``github/codeql-action`` to ``v4.30.8`` to align with the October 2025
  ruleset without downgrading existing actions.
- ``pyproject.toml`` configures ``pyright`` with ``pythonVersion = "3.13"`` so
  static analysis matches the runtime baseline.
- Dependency audit (October 16, 2025) confirmed runtime (`rich-click 1.9.3`,
  ``lib_cli_exit_tools 2.1.0``, ``pydantic 2.12.2``) and development extras remain
  on their current stable releases; no version bumps were needed this cycle.

## [0.0.1] - 2025-10-15
### Added
- Static metadata portrait generated from ``pyproject.toml`` and exported via
  ``btx_lib_mail.__init__conf__``; automation keeps the constants in
  sync during tests and push workflows.
- Help-first CLI experience: invoking the command without subcommands now
  prints the rich-click help screen; ``--traceback`` without subcommands still
  executes the placeholder domain entry.
- `ProjectMetadata` now captures version, summary, author, and console-script
  name, providing richer diagnostics for automation scripts.

### Changed
- Refactored CLI helpers into prose-like functions with explicit docstrings for
  intent, inputs, outputs, and side effects.
- Overhauled module headers and system design docs to align with the clean
  narrative style; `docs/systemdesign/module_reference.md` reflects every helper.
- Scripts (`test`, `push`) synchronise metadata before running, ensuring the
  portrait stays current without runtime lookups.

### Fixed
- Eliminated runtime dependency on ``importlib.metadata`` by generating the
  metadata file ahead of time, removing a failure point in minimal installs.
- Hardened tests around CLI help output, metadata constants, and automation
  scripts to keep coverage exhaustive.
