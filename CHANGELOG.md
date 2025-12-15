# Changelog

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
