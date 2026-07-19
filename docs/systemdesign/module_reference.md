# Module Reference: btx_lib_mail

This document describes the modules that make up `btx_lib_mail` and the public
and notable internal components of each. It reflects the code as it currently
stands; for narrative usage and configuration guidance see the
[README](../../README.md).

`btx_lib_mail` is a small SMTP delivery library with a rich-click CLI. The
package is a CLI-first utility whose modules live in the adapter/transport layer,
with `behaviors.py` acting as a thin placeholder domain. `import-linter`
enforces that the CLI depends on the behaviour helpers only.

## Architecture at a glance

Delivery flows in one direction, from intent to SMTP side effects:

```
cli.cli_send_mail  (resolve CLI flags / env / .env)
  -> lib_mail.send  (validate, prepare, orchestrate)
       -> _prepare_recipients / _prepare_attachments / _prepare_hosts
       -> _resolve_delivery_options / _resolve_attachment_security_options
       -> _deliver_to_any_host   (compose once to a spool, failover across hosts)
            -> Transport.deliver  (SmtplibTransport: connect, STARTTLS, login,
                                   stream via BDAT or DATA)
```

Configuration is a Pydantic model (`ConfMail`) with a global `conf` instance;
per-call overrides passed to `send` win over `conf`. Resolved runtime knobs are
frozen dataclasses (`DeliveryOptions`, `AttachmentSecurityOptions`) so the
low-level helpers receive one immutable object each.

## Core components {#feature-cli-components}

The components below back the CLI surface and the delivery engine.

### btx_lib_mail.lib_mail {#module-btx-lib-mail-lib-mail}

The SMTP delivery boundary: configuration, input normalisation, message
rendering, attachment security, and the delivery orchestration.

#### AttachmentViolation {#lib-mail-attachmentviolation}

* **Purpose:** Enumerate the closed set of attachment security violation
  categories so callers match on a typed member instead of a bare string.
* **Type:** `class AttachmentViolation(str, Enum)` (a `str` mixin rather than the
  3.11+ `StrEnum`, to keep the Python 3.10 baseline). Members: `PATH_TRAVERSAL`,
  `SYMLINK`, `SENSITIVE_PATTERN`, `DIRECTORY`, `EXTENSION`, `SIZE`.
* **Notes:** Members subclass `str`, so `violation == "symlink"`, JSON
  serialisation, and `AttachmentViolation("symlink")` round-tripping all keep the
  original wire value.
* **Location:** src/btx_lib_mail/lib_mail.py

#### AttachmentSecurityError

* **Purpose:** Structured exception raised when an attachment violates a security
  policy, so callers can handle or report it.
* **Fields:** `path` (`pathlib.Path`), `reason` (`str`), `violation_type`
  (`AttachmentViolation`).
* **Notes:** `__str__` renders `violation_type.value` to keep the message stable
  across Python versions.
* **Location:** src/btx_lib_mail/lib_mail.py

#### AttachmentPayload {#lib-mail-attachmentpayload}

* **Purpose:** Name a validated attachment and point at its source file, so the
  bytes are read only while the message is streamed to the transport, never held
  in memory from preparation onward.
* **Fields:** `filename` (`str`), `source` (`pathlib.Path`). Immutable (`frozen=True`).
* **Location:** src/btx_lib_mail/lib_mail.py

#### ConfMail {#lib-mail-confmail}

* **Purpose:** Authoritative SMTP configuration (Pydantic `BaseModel`) merging CLI
  options, environment variables, and defaults with type and range checks.
* **Fields:** `smtphosts` (`list[str]`), `raise_on_missing_attachments` (`bool`),
  `raise_on_invalid_recipient` (`bool`), `smtp_username`/`smtp_password`
  (`str | None`), `smtp_use_starttls` (`bool`, default `True`),
  `smtp_starttls_verify` (`bool`, default `True`), `smtp_timeout` (`float`,
  default `30.0`), and the attachment security fields
  (`attachment_allowed_extensions`, `attachment_blocked_extensions`,
  `attachment_allowed_directories`, `attachment_blocked_directories`,
  `attachment_max_size_bytes`, `attachment_allow_symlinks`,
  `attachment_raise_on_security_violation`).
* **Validation:** coerces `smtphosts` from string/iterable, rejects a
  non-positive `smtp_timeout` and `attachment_max_size_bytes`, and normalises
  extension/directory sets.
* **Global:** `conf` is the shared instance used when per-call overrides are
  absent.
* **Location:** src/btx_lib_mail/lib_mail.py

##### ConfMail.resolved_credentials() {#lib-mail-confmail-resolved-credentials}

* **Purpose:** Return `(username, password)` when both are populated, else `None`,
  so callers do not juggle two separate optionals.
* **Location:** src/btx_lib_mail/lib_mail.py

#### DeliveryOptions {#lib-mail-deliveryoptions}

* **Purpose:** Freeze the resolved delivery knobs for one attempt.
* **Fields:** `credentials` (`tuple[str, str] | None`), `use_starttls` (`bool`),
  `starttls_verify` (`bool`), `timeout` (`float`).
* **Notes:** Resolved by `_resolve_delivery_options` from per-call overrides
  falling back to `conf`. `starttls_verify=False` keeps STARTTLS encryption but
  skips certificate/hostname validation (for internal self-signed relays); it has
  no effect when `use_starttls` is `False`.
* **Location:** src/btx_lib_mail/lib_mail.py

#### AttachmentSecurityOptions {#lib-mail-attachmentsecurityoptions}

* **Purpose:** Freeze the resolved attachment security options for one send.
* **Fields:** `allowed_extensions` (`frozenset[str] | None`),
  `blocked_extensions` (`frozenset[str]`), `allowed_directories`
  (`frozenset[Path] | None`), `blocked_directories` (`frozenset[Path]`),
  `max_size_bytes` (`int | None`), `allow_symlinks` (`bool`),
  `raise_on_violation` (`bool`).
* **Notes:** Resolved by `_resolve_attachment_security_options`; `None` means "use
  the `conf` default", an empty frozenset means "no restriction".
* **Location:** src/btx_lib_mail/lib_mail.py

#### send(...) {#lib-mail-send}

* **Purpose:** The library/CLI facade that turns validated intent (sender,
  recipients, bodies, attachments) into SMTP activity while honouring the
  delivery and security policies.
* **Input:** `mail_from`, `mail_recipients`, `mail_subject`, optional `mail_body`
  / `mail_body_html`, `smtphosts`, `attachment_file_paths`, and keyword overrides
  `credentials`, `use_starttls`, `starttls_verify`, `timeout`, the attachment
  security parameters, and `raise_on_missing_attachments` /
  `raise_on_invalid_recipient`. Omitted overrides fall back to `conf`.
* **Output:** `True` when every recipient is delivered. Failure raises rather than
  returning `False`.
* **Raises:** `ValueError` (no valid recipients / invalid sender),
  `FileNotFoundError` (missing required attachment), `AttachmentSecurityError`
  (policy violation in strict mode), `RuntimeError` (every host failed for a
  recipient).
* **Location:** src/btx_lib_mail/lib_mail.py

#### Delivery helpers

* `_deliver_to_any_host` composes the message once into a `SpooledTemporaryFile`
  and iterates the host tuple, delegating to the injected `Transport` until one
  accepts the message, logging a warning per failed host. The spool is reused
  across host attempts.
* `Transport` is a protocol (delivery seam); `SmtplibTransport` is the default
  adapter. It opens the `smtplib.SMTP` session, runs STARTTLS via
  `_build_starttls_context(verify=...)` when enabled, logs in when credentials are
  present, then streams the message to the socket in `_STREAM_CHUNK_SIZE` chunks:
  RFC 3030 `BDAT` when the server advertises `CHUNKING`, otherwise the `DATA` phase
  with `_DotStuffer` incremental dot-stuffing. `send` accepts a `transport=`
  override for testing or alternative transports.
* `_build_starttls_context(*, verify)` returns `ssl.create_default_context()`; when
  `verify` is `False` it clears `check_hostname` and sets `verify_mode` to
  `CERT_NONE` (encrypted but unverified).
* `_compose_to_spool` serialises the message (`EmailMessage` + `email.policy.SMTP`
  CRLF) into a spooled temp file, streaming each attachment's base64 from disk in
  chunks so a large payload is never buffered whole.
* **Location:** src/btx_lib_mail/lib_mail.py

#### Validators

* `validate_email_address(address)` raises `ValueError` when the address does not
  match `EMAIL_PATTERN`.
* `validate_smtp_host(host)` raises `ValueError` for a malformed host, accepting
  `hostname`, `hostname:port`, `[IPv6]`, and `[IPv6]:port`.
* Both are public; `_parse_smtp_host` reuses `validate_smtp_host` before splitting
  hostname and port.
* **Location:** src/btx_lib_mail/lib_mail.py

#### Attachment security checks (internal)

`_validate_attachment_security` orchestrates, in order: `_check_path_traversal`,
`_check_symlink`, `_check_sensitive_patterns`, `_check_directory_restrictions`,
`_check_extension`, and `_check_file_size`. Each raises `AttachmentSecurityError`
with the matching `AttachmentViolation` category. `_prepare_attachments` applies
them before reading file bytes, honouring `raise_on_violation` and
`raise_on_missing`.

#### Public constants

`DANGEROUS_EXTENSIONS_POSIX`, `DANGEROUS_EXTENSIONS_WINDOWS`,
`DANGEROUS_DIRECTORIES_POSIX`, `DANGEROUS_DIRECTORIES_WINDOWS`, and
`SENSITIVE_PATH_PATTERNS` provide the OS-appropriate blacklists. `EMAIL_PATTERN`
is the compiled address regex.

### btx_lib_mail.cli {#module-btx-lib-mail-cli}

The rich-click adapter that exposes the commands and keeps traceback handling
consistent across the console script and `python -m`.

* **Commands:** `info`, `hello`, `send`, `validate-email`, `validate-smtp-host`,
  `fail`, plus the root group `cli` and the placeholder `cli_main`.
* **Root group cli {#cli-root}:** registers the global `--traceback/--no-traceback`
  flag, mirrors it into `lib_cli_exit_tools.config`, and prints help when invoked
  without a subcommand (unless `--traceback` was explicitly set).
* **cli_send_mail {#cli-send-mail}:** the `send` command. Resolves `--host`,
  `--recipient`, `--sender`, `--subject`, `--body`, `--html-body`,
  `--attachment`, `--starttls/--no-starttls`,
  `--starttls-verify/--no-starttls-verify`, `--username`, `--password`,
  `--timeout`, and the `--attachment-*` security options, falling back to the
  `BTX_MAIL_*` environment variables (or a local `.env`). Precedence: CLI options,
  then environment variables, then `.env` entries, then `btx_lib_mail.lib_mail.conf`.
  Delegates to `send` and echoes a summary line.
* **Resolution helpers:** `_configured_value`, `_dotenv_value`, `_resolve_list`,
  `_resolve_bool`, `_resolve_optional_bool`, `_resolve_float`, `_resolve_int`,
  `_resolve_extensions`, `_resolve_directories`, `_resolve_credentials` parse
  boundary input (CLI string / env / `.env`) into typed values.
* **Traceback helpers:** `apply_traceback_preferences`
  {#cli-apply-traceback-preferences}, `snapshot_traceback_state`
  {#cli-snapshot-traceback-state}, `restore_traceback_state`
  {#cli-restore-traceback-state} keep `lib_cli_exit_tools` in sync and restorable.
* **Entry point main {#cli-main-entry}:** runs the command through
  `lib_cli_exit_tools`, choosing the traceback character budget, and restores the
  prior traceback state unless asked not to.
* **Location:** src/btx_lib_mail/cli.py

### btx_lib_mail.typed_click

Strictly-typed wrappers (`option`, `version_option`, `argument`) over the
rich-click decorators whose re-exported click `ParamType` is untyped. This module
is the single boundary that carries the `# pyright: ignore[reportUnknownMemberType]`
for that third-party gap, keeping the rest of the CLI layer strict-clean.

* **Location:** src/btx_lib_mail/typed_click.py

## Behaviour scaffold {#feature-cli-behavior-scaffold}

### btx_lib_mail.behaviors {#module-btx-lib-mail-behaviors}

The placeholder domain helpers backing the CLI scaffold.

* **emit_greeting(stream=None) {#behaviors-emit-greeting}:** writes
  `CANONICAL_GREETING` plus a newline to the stream (default `sys.stdout`) and
  flushes when possible.
* **raise_intentional_failure() {#behaviors-raise-intentional-failure}:** always
  raises `RuntimeError('I should fail')`, the vehicle for error-path and
  traceback tests.
* **noop_main() {#behaviors-noop-main}:** returns `None`; honours tooling that
  expects a `main` callable.
* **CANONICAL_GREETING:** the shared greeting line (`"Hello World"`).
* **Location:** src/btx_lib_mail/behaviors.py

## Module execution session helpers {#module-main-session-helpers}

### btx_lib_mail.__main__ {#module-btx-lib-mail-main}

Implements `python -m btx_lib_mail`, delegating to `cli.main` so exit semantics
match the console script.

* **_open_cli_session() {#module-main-open-cli-session}:** returns a
  `lib_cli_exit_tools.cli_session` context manager wired with the shared traceback
  limits.
* **_command_to_run() {#module-main-command-to-run}:** returns the root
  `cli.cli` command.
* **_command_name() {#module-main-command-name}:** returns
  `__init__conf__.shell_command`.
* **_module_main() {#module-main-module-main}:** opens the session and runs the
  command, returning the exit code.
* **Location:** src/btx_lib_mail/__main__.py

## Metadata

### btx_lib_mail.__init__conf__

Static project metadata as plain constants, kept in sync with `pyproject.toml` by
development automation so runtime code never queries packaging APIs.

* **Constants:** `name`, `title`, `version`, `homepage`, `author`,
  `author_email`, `shell_command`, and the layered-config identifiers
  `LAYEREDCONF_VENDOR`, `LAYEREDCONF_APP`, `LAYEREDCONF_SLUG`.
* **print_info():** renders the constants for the CLI `info` command.
* **Location:** src/btx_lib_mail/__init__conf__.py

## Package surface

### btx_lib_mail.__init__

Re-exports the public API. `__all__` covers: `AttachmentSecurityError`,
`AttachmentViolation`, `CANONICAL_GREETING`, `ConfMail`,
`DANGEROUS_DIRECTORIES_POSIX`, `DANGEROUS_DIRECTORIES_WINDOWS`,
`DANGEROUS_EXTENSIONS_POSIX`, `DANGEROUS_EXTENSIONS_WINDOWS`,
`SENSITIVE_PATH_PATTERNS`, `conf`, `emit_greeting`, `logger`, `noop_main`,
`print_info`, `raise_intentional_failure`, `send`, `validate_email_address`,
`validate_smtp_host`.

* **Location:** src/btx_lib_mail/__init__.py
