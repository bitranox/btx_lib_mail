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
  across Python versions. `__init__` runs `reason` through `_printable` before
  storing it (`reason` is built with an f-string at every raise site and usually
  embeds the offending path), and `__str__` runs `path` through `_printable` too,
  so neither `str(exc)` nor `repr(exc)` (which renders the cleaned `self.args`)
  can carry a forged line, whether this exception is logged or raised to the
  caller in strict mode (`attachment_raise_on_security_violation=True`, the
  default).
* **Location:** src/btx_lib_mail/lib_mail.py

#### AttachmentPayload {#lib-mail-attachmentpayload}

* **Purpose:** Name a validated attachment and point at its source file, so the
  bytes are read only while the message is streamed to the transport, never held
  in memory from preparation onward.
* **Fields:** `filename` (`str`), `source` (`pathlib.Path`). Immutable (`frozen=True`).
* **Location:** src/btx_lib_mail/lib_mail.py

#### ConfMail {#lib-mail-confmail}

* **Purpose:** Authoritative SMTP configuration (a `SecretSafeModel`, so its own
  validation errors are redacted) merging CLI options, environment variables, and
  defaults with type and range checks.
* **Fields:** `smtphosts` (`list[str]`), `raise_on_missing_attachments` (`bool`),
  `raise_on_invalid_recipient` (`bool`), `smtp_username` (`str | None`),
  `smtp_password` (`SecretStr | None`), `smtp_use_starttls` (`bool`, default
  `True`), `smtp_starttls_verify` (`bool`, default `True`), `smtp_timeout`
  (`float`, default `30.0`), and the attachment security fields
  (`attachment_allowed_extensions`, `attachment_blocked_extensions`,
  `attachment_allowed_directories`, `attachment_blocked_directories`,
  `attachment_max_size_bytes`, `attachment_allow_symlinks`,
  `attachment_raise_on_security_violation`, `attachment_allow_empty_blocklists`).
* **Validation:** coerces `smtphosts` from string/iterable and refuses a host
  carrying `@` or `/`, or any interior whitespace or control character (see
  `_refuse_credentials_in_host`; outer whitespace is trimmed first, so it does not
  count). `smtp_password` accepts `str`, `bytes` and `SecretStr` unchanged, coerces a
  whole `int` (not `bool`) to its decimal text, and refuses anything else without
  echoing it. `smtp_timeout` and `attachment_max_size_bytes` reject a non-positive
  value, and extension/directory sets are normalised. A model-level validator
  (`_refuse_an_empty_blocklist`) refuses an empty blocked extension or directory set
  whose allowlist is not set, unless `attachment_allow_empty_blocklists` is `True`.
* **Secret safety:** `credential_fields = frozenset({"smtp_password",
  "smtphosts"})`; a `ValidationError` raised while validating this model never
  carries the value at either location (see `secret_safety.SecretSafeModel`).
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
  security parameters, `raise_on_missing_attachments` /
  `raise_on_invalid_recipient`, `config`, and `transport`. Omitted overrides fall
  back to `config` when given, else to `conf`.
* **`config: ConfMail | None = None`:** settings used in place of the module-global
  `conf` for every value not passed explicitly; when given, `conf` is not read at
  all. Lets a caller hold its own `ConfMail` (or subclass) without mutating the
  global.
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
  accepts the message, logging one credential-free `WARNING` per failed host (built
  by `_describe_failure`, no traceback attached) and moving on, or a `DEBUG` line on
  success. The spool is reused across host attempts. `sender`, `host` and
  `recipient` logged in either the `DEBUG` line or the `WARNING` (message and
  `extra` alike) are all run through `_printable` before logging, as defense in
  depth: `_refuse_credentials_in_host` already refuses a host carrying interior
  whitespace or a control character before delivery starts, and `send()` validates
  `sender`/`recipient` before calling this function, so this cleaning guards against
  whatever reaches this function directly rather than through `send()`'s own
  validation (tests do exactly that).
* `_describe_failure(error)` returns a one-line, credential-free description of a
  delivery failure: for an `smtplib.SMTPResponseException` it is the exception class
  name plus the server's numeric code and reply text; for any other `OSError`
  (including one a custom `Transport` raises) it is the class name plus `str(error)`,
  logged as given; for anything else it is only the class name. The text is run
  through `_printable` and capped at `_FAILURE_TEXT_LIMIT` (200 characters) so a
  hostile or chatty server reply cannot forge extra log lines or flood the log.
* `_printable(text)` replaces every non-printable character (CR, LF, ESC, NUL, ...)
  in `text` with a space, so a server reply cannot inject control sequences into
  whatever renders the log record.
* `Transport` is a protocol (delivery seam); `SmtplibTransport` is the default
  adapter. It opens the `smtplib.SMTP` session, runs STARTTLS via
  `_build_starttls_context(verify=...)` when enabled, logs in when credentials are
  present via `_authenticate`, then streams the message to the socket in
  `_STREAM_CHUNK_SIZE` chunks: RFC 3030 `BDAT` when the server advertises
  `CHUNKING`, otherwise the `DATA` phase with `_DotStuffer` incremental
  dot-stuffing. `send` accepts a `transport=` override for testing or alternative
  transports.
* `_authenticate(smtp_connection, username, password)` calls `smtplib.SMTP.login`
  when both `username` and `password` are ASCII (the stdlib path, which tries
  CRAM-MD5, PLAIN and LOGIN in turn among the mechanisms the server advertises);
  otherwise it calls `_login_plain_utf8`,
  because stdlib `smtplib` encodes every AUTH exchange as ASCII and raises
  `UnicodeEncodeError` (quoting the whole AUTH string, password included, in its
  repr) on a non-ASCII credential.
* `_login_plain_utf8(smtp_connection, username, password)` authenticates with RFC
  4616 AUTH PLAIN, credentials encoded as UTF-8. Raises
  `smtplib.SMTPNotSupportedError` when the server offers no AUTH extension or no
  PLAIN mechanism, and `smtplib.SMTPAuthenticationError` (carrying only the server
  reply) when the server rejects the credentials or answers an unexpected code.
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
* `_refuse_credentials_in_host(host)` returns `host` unchanged, or raises
  `ValueError` (without echoing the value) when it carries `@` or `/`: a host string
  such as `user:password@relay` would put the password into every log line and
  error text that names the host. It also raises for any INTERIOR whitespace or
  control character (a newline or an escape sequence could forge a log line or a
  terminal control sequence); callers run it after `_normalise_host`, which trims
  OUTER whitespace, so an ordinary `" smtp.example.com "` still validates.
  `validate_smtp_host` calls it first, and `ConfMail`'s `smtphosts` coercion
  (`_collect_host_inputs`) calls it directly.
* `validate_email_address` and `validate_smtp_host` are public; `_parse_smtp_host`
  reuses `validate_smtp_host` before splitting hostname and port.
* `_prepare_recipients` validates each address with `validate_email_address`; in
  tolerant mode (`raise_on_invalid_recipient=False`) the entry that FAILED
  validation is, by definition, not provably free of control characters, so it is
  run through `_printable` before it reaches the `WARNING` (message and
  `extra["recipient"]` alike) or the `ValueError` message raised in strict mode.
* **Location:** src/btx_lib_mail/lib_mail.py

#### Attachment security checks (internal)

`_validate_attachment_security` orchestrates, in order: `_check_path_traversal`,
`_check_symlink`, `_check_sensitive_patterns`, `_check_directory_restrictions`,
`_check_extension`, and `_check_file_size`. Each raises `AttachmentSecurityError`
with the matching `AttachmentViolation` category. `_prepare_attachments` applies
them before reading file bytes, honouring `raise_on_violation` and
`raise_on_missing`. In tolerant mode (`raise_on_violation=False` /
`raise_on_missing=False`) it logs one `WARNING` per skipped attachment, running
the path (and, for a security violation, `exc.reason`, already cleaned by
`AttachmentSecurityError.__init__`) through `_printable` again, in both the
message and `extra["attachment_path"]`, as defense in depth; a
`FileNotFoundError` raised in strict mode is cleaned the same way.

#### Public constants

`DANGEROUS_EXTENSIONS_POSIX`, `DANGEROUS_EXTENSIONS_WINDOWS`,
`DANGEROUS_DIRECTORIES_POSIX`, `DANGEROUS_DIRECTORIES_WINDOWS`, and
`SENSITIVE_PATH_PATTERNS` provide the OS-appropriate blacklists. `EMAIL_PATTERN`
is the compiled address regex.

### btx_lib_mail.secret_safety {#module-btx-lib-mail-secret-safety}

Credential-safe validation errors for pydantic models that hold secrets.

#### SecretSafeModel {#secret-safety-secretsafemodel}

* **Purpose:** Base class for a pydantic model holding a credential, so every
  `ValidationError` it raises has had its inputs rebuilt to remove the secret.
  `ConfMail` is a subclass.
* **Mechanism:** wraps the model's whole core schema (`__get_pydantic_core_schema__`),
  so it covers field validation, validated assignment (and assignment to a frozen
  model, via an explicit `__setattr__` override), model-level validators,
  `model_validate`, `model_validate_strings`, this model's own `model_validate_json`
  (an explicit override, also for malformed JSON), `TypeAdapter(Model).validate_python`,
  and validation of this model nested in a list or in another model.
* **Class variable:** `credential_fields: ClassVar[frozenset[str]] = frozenset()` -
  a subclass lists its credential field names here; every alias of those fields is
  covered automatically. Checked at class definition (`__pydantic_init_subclass__`,
  `_check_credential_fields`): an undeclared name, a value that is not a set of str,
  or an annotated `credential_fields` that became a field raises `TypeError`.
* **Assignment rollback:** the `__setattr__` override saves the instance state and
  restores it when the assignment raises, because pydantic keeps a new value that a
  `mode="after"` model validator then refuses.
* **Not covered:** malformed JSON handed to `TypeAdapter(Model).validate_json`, and
  malformed JSON handed to `model_validate_json` of a plain outer model that merely
  nests a `SecretSafeModel` field - the JSON parser fails before either model's
  schema runs. An outer model that nests a `SecretSafeModel` field AND defines its
  own model-level validator must itself inherit `SecretSafeModel` and list the
  nested field, because its own model-level errors quote its own input.
* **Location:** src/btx_lib_mail/secret_safety.py

#### redact_validation_error(exc, *, credential_fields, declared_names=frozenset()) {#secret-safety-redact-validation-error}

* **Purpose:** Return a copy of `exc` whose error inputs and `ctx` cannot carry a
  credential; the function `SecretSafeModel` wraps its schema with, callable
  directly to redact a `ValidationError` from a plain (non-`SecretSafeModel`) model.
* **Rule:** an error's input is kept only when it is a plain scalar (`str`, `bytes`,
  `int`, `float`, `bool`, `None`, `Decimal`, a date/time value, or an `Enum` member
  whose value is one of these); every other input becomes `REDACTED_INPUT`. An error
  is always hidden when it is model-level, an `extra_forbidden` error, or at a
  location in `credential_fields` (or an alias of one). A hidden error keeps no
  `ctx`, and its message is scrubbed best-effort by walking the input (mapping keys
  and values, collection members, object attributes, Enum values) and replacing
  every text it finds, in its verbatim, `repr()`, `ascii()` or JSON-escaped form. A
  mapping key equal to a name in `declared_names` is not walked (so a message
  naming a field keeps the name), but a VALUE equal to such a name still is. An
  input too large or deep to walk within the bound has its whole message replaced.
  The rebuild never raises; a failure it cannot rebuild faithfully keeps only its
  type and location, and total failure yields one opaque `redacted_error`.
* **Usage note:** raise the returned error OUTSIDE the `except` block that caught
  the original, or the unredacted error survives as `__context__`.
* **Location:** src/btx_lib_mail/secret_safety.py

#### REDACTED_INPUT {#secret-safety-redacted-input}

* **Purpose:** The string (`"[redacted]"`) a hidden error's `input` is replaced by.
* **Location:** src/btx_lib_mail/secret_safety.py

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
`AttachmentViolation`, `CANONICAL_GREETING`, `ConfMail`, `DeliveryOptions`,
`DANGEROUS_DIRECTORIES_POSIX`, `DANGEROUS_DIRECTORIES_WINDOWS`,
`DANGEROUS_EXTENSIONS_POSIX`, `DANGEROUS_EXTENSIONS_WINDOWS`, `REDACTED_INPUT`,
`SecretSafeModel`, `SENSITIVE_PATH_PATTERNS`, `Transport`, `conf`,
`emit_greeting`, `logger`, `noop_main`, `print_info`,
`raise_intentional_failure`, `redact_validation_error`, `send`,
`validate_email_address`, `validate_smtp_host`.

* **Location:** src/btx_lib_mail/__init__.py
