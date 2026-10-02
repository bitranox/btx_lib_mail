# Changelog

## [Unreleased]

### Added

- `BtxMailError`, the common base of every exception the library raises on purpose, with
  `InvalidInputError` (also a `ValueError`), `ConfigurationError` (also a pydantic
  `ValidationError`), `AttachmentNotFoundError` (also a `FileNotFoundError`) and
  `DeliveryError` (also a `RuntimeError`, with `failed_recipients` and `hosts`).
  `AttachmentSecurityError` derives from it too. Each keeps the builtin it replaces as a
  second base, so existing `except ValueError:` (and so on) clauses still catch it; messages
  and CLI exit codes are unchanged, and the CLI's stderr line names the new class
  (`InvalidInputError: ...` instead of `ValueError: ...`).
- `SecretSafeModel.validation_error_class` and `redact_validation_error(error_class=...)` name
  the `ValidationError` subclass a model's errors are raised as.
- Sensitive-path patterns `/.netrc`, `/.pgpass`, `/.git-credentials`, `/.docker/config.json`,
  `/.pypirc`, `/.npmrc` and `/gh/hosts.yml`.
- `AttachmentViolation.CHANGED`: an attachment path that became a symlink or another file
  after it was checked.
- `AttachmentViolation.FILENAME`: an attachment whose file name holds a control character
  (Unicode category `Cc`: CR, LF, NUL, ESC, DEL, ...).
- `ConfMail.smtp_delivery_deadline` / `send(delivery_deadline=)` / `--delivery-deadline` /
  `BTX_MAIL_SMTP_DELIVERY_DEADLINE`: an upper bound in seconds for one SMTP session. The
  socket timeout bounds each read or write, so a server answering one byte at a time kept a
  session open indefinitely; past the deadline the socket is shut down and the host counts
  as failed (`TimeoutError`). Unset by default.
- CLI: `--json`/`-j` and `--json-bare` on the command group. Every subcommand prints one JSON
  document (`{"ok", "command", "data", "skipped"}`); a failure prints
  `{"ok": false, "command", "error": {"type", "message"}}` instead of a traceback, with the
  exit code it has without `--json`. `skipped` lists attachments and recipients `send` left
  out in warn mode. The exit codes are documented in `docs/cli.md`.
- CLI: `--password-file PATH` (`-` reads stdin) keeps the password out of the process list.
- CLI: `--env-file PATH` (or `BTX_MAIL_ENV_FILE`) names a `KEY=value` file to read instead of
  `./.env`. Either file is read once and must be UTF-8 and at most 64 KiB.
- `CliContext`, the typed `ctx.obj`; its `transport` lets an application embedding the CLI
  (or a test) deliver through its own `Transport`.
- A WARNING when credentials are sent with STARTTLS off, naming the host.
- `ConfMail.recipient_max_count` (default `1000`) and `ConfMail.attachment_max_count` (default
  `100`), with `--recipient-max-count` / `BTX_MAIL_RECIPIENT_MAX_COUNT` and
  `--attachment-max-count` / `BTX_MAIL_ATTACHMENT_MAX_COUNT` on the CLI: one `send()` call
  with more recipients (counted after duplicates are dropped) or more attachments is refused
  with `InvalidInputError` before any delivery or file check. `None` lifts a limit.

### Changed

- `str()` and `repr()` of a `ConfigurationError` drop pydantic's per-error
  `For further information visit https://errors.pydantic.dev/<version>/...` line, which named
  the installed pydantic version and described pydantic rather than the refused setting. The
  CLI already left it out; a library caller now gets the same text. `errors()` is pydantic's,
  unchanged.
- A subject longer than 4096 characters is refused with `InvalidInputError` before the first
  delivery (`mail_subject has N characters, more than the 4096 allowed`). Folding a subject
  costs more than linear time and ran once per recipient before anything was sent, so an
  unbounded subject let a caller spend seconds of CPU per recipient.
- The default `attachment_blocked_extensions` is the union of `DANGEROUS_EXTENSIONS_POSIX` and
  `DANGEROUS_EXTENSIONS_WINDOWS` on every platform, so a Linux or macOS sender now refuses
  `.exe`, `.bat`, `.ps1`, `.dll`, `.lnk` and the rest of the Windows list by default (and a
  Windows sender `.sh`, `.py`, ...). The recipient's system decides what an attachment runs
  as, not the sender's. The blocked-directory default stays per platform.
- The extension check drops trailing dots and spaces before reading the extension, so
  `x.exe.` and `x.sh ` are refused like `x.exe` and `x.sh`.
- Sensitive-path patterns ignore case on macOS and Windows: `.SSH/config` and
  `.AWS/CREDENTIALS` are refused there (they are `~/.ssh/config` on those file systems). On
  Linux the match stays exact, where `.SSH/config` is a different file.
- `lib_mail.py` is split into private modules (`_config`, `_attachments`, `_validation`,
  `_compose`, `_transport`, `_common`) behind `btx_lib_mail.lib_mail`, which keeps `send()`
  and re-exports the public names (`__all__`). Importing from `btx_lib_mail` or
  `btx_lib_mail.lib_mail` is unchanged; a private helper imported from `lib_mail` now lives
  in its own module.
- `btx_lib_mail.cli` is a package: the public names (`cli`, `main`, `CliContext`, the
  commands, `CLICK_CONTEXT_SETTINGS`, the traceback limits and helpers) are importable from
  `btx_lib_mail.cli` as before, and the console scripts still run `btx_lib_mail.cli:main`.
  The private helpers moved into submodules (`_settings_sources`, `_output`, `_traceback`,
  `_commands`, `_send_command`, `_dispatch`); one imported from `btx_lib_mail.cli` now lives
  there, some under a name without the leading underscore.
- `validate_email_address()`, and with it every sender and recipient check, refuses an address
  longer than RFC 5321 allows: more than 64 characters before the `@`, or more than 254 in all.
  The message names the length (`invalid email address: 255 characters, more than the 254 RFC
  5321 allows`) instead of quoting the address. A malformed address within those lengths keeps
  its message; one that is malformed AND too long, which was refused before with the address
  quoted, is now refused with the length message.
- The path-traversal check refuses a `..` path COMPONENT only: `report..final.txt` is now
  accepted, `a/../b` is still refused with the same message.
- Each attachment is opened once, right after its checks, and compared with what was
  checked (same file, still a regular file, size within the limit); the message body is
  encoded once per `send()` from that open file, and each recipient's message is its own
  header lines followed by that body, read in place. Scratch disk for a large attachment is
  its encoded size (about 1.37x) once, however many recipients there are. Attachments are no longer re-read and re-encoded per
  recipient, and the files are closed before `send()` returns.
- A subject containing a control character other than TAB is refused with
  `InvalidInputError` before the first delivery (`mail_subject must not contain control
  characters (only TAB is allowed)`); CR and LF keep the email package's message. Before,
  NUL, ESC and the rest were sent raw.

### Fixed

- A recipient holding KELVIN SIGN (U+212A) was lower-cased to an ASCII `k` before it was
  validated, so a non-ASCII address was silently rewritten to a different, valid one and sent
  there, while the same text as sender was refused. Only an ASCII recipient is lower-cased
  now; a non-ASCII one is refused like the sender.
- CLI: an env file (`--env-file`, `BTX_MAIL_ENV_FILE`) that is a device or FIFO passed the
  64 KiB size check (it reports size 0) and was then read without a bound: `/dev/zero` ran out
  of memory and a FIFO blocked for a writer. The file is now opened without blocking, refused
  unless it is a regular file (`is not a regular file`, exit 2), and read at most one byte past
  the limit.
- CLI: a `--password-file` that is not UTF-8 raised a bare `UnicodeDecodeError` (exit 22) whose
  message quoted the offending byte and its offset in the password. It is now a usage error,
  `--password-file: is not UTF-8 text`, exit 2, like an env file that is not UTF-8.
- An attachment the operating system refuses to open (no read permission, the open-file
  limit, an I/O error) raised the bare `OSError` (`PermissionError: [Errno 13] ...`), and
  `raise_on_missing_attachments=False` could not skip it. It is now reported like a missing
  file: `AttachmentNotFoundError('Attachment File "<path>" can not be read (EACCES)')`, or a
  warning and a skip when that setting is `False`. (The CLI already refused an unreadable
  `--attachment` as a usage error.)
- `send(attachment_file_paths=...)` accepts `str` entries as well as `pathlib.Path`; a `str`
  raised `AttributeError` before. Any other entry type is refused with `InvalidInputError`.
- An attachment whose name is not valid Unicode text (an invalid UTF-8 byte in a POSIX name)
  raised a bare `UnicodeEncodeError` while composing, even in warn mode, and a path holding
  NUL raised a bare `ValueError` from `os.lstat`. Both are refused as
  `AttachmentViolation.FILENAME`, so warn mode skips them.
- A subject holding U+2028 or U+2029, or a subject or body holding a lone surrogate (what an
  invalid UTF-8 byte in argv decodes to on POSIX), raised a bare `ValueError` or
  `UnicodeEncodeError` from the email package. Both are now refused before the first delivery
  with `InvalidInputError`: the separators with the same line-break message as CR and LF, a
  surrogate with `mail_subject|mail_body|mail_body_html must be valid Unicode text`. A
  subject with a surrogate was sent before as an undecodable `unknown-8bit` header.
- `send(attachment_blocked_extensions=...)` and `send(attachment_allowed_extensions=...)` are
  normalised like the `ConfMail` fields (lower case, leading dot): `{".EXE"}` now blocks
  `x.exe`, and `{"PDF"}` allows `r.pdf`. A keyword set in another spelling let an executable
  through or refused an allowed file.
- Each host attempt starts at the first byte of the message. A custom `Transport` that read
  the message and then failed handed the next host an empty stream.
- CLI: a `--json` failure reports `failed_recipients` and `hosts` for a `DeliveryError`, and
  the `skipped` items of that run; JSON mode is read from the options before the subcommand
  only, so an option value such as `--body --json` no longer switches it on.
- CLI: an env-file value loses one matching pair of surrounding quotes only; a password that
  starts or ends with a quote character keeps it.
- CLI: every command's `--help` shows a plain description instead of docstring markup.
- `python -m btx_lib_mail` runs the same entry point as the console scripts. It ran a
  separate session before, so a usage error exited `1` there and `2` from `btx-lib-mail`.
- An attachment path swapped after the checks (for example replaced by a symlink to
  `/etc/passwd` while recipient 1 was being delivered) no longer reaches later recipients:
  every recipient receives the bytes of the file that was checked. A file that grows past
  `attachment_max_size_bytes` after the check is refused while it is read (`SIZE`), instead
  of being sent whole.
- An attachment deleted or changed while delivery runs no longer abandons the remaining
  recipients, and a message spool is closed when composing it fails (no `ResourceWarning`).
- `smtp_timeout` (and `send(timeout=)`) refuses NaN and infinity (`smtp_timeout must be a
  finite number of seconds, got nan`) instead of failing later as an unrelated delivery
  error. A non-positive value keeps its `must be positive` message.
- An attachment whose file name holds CR, LF, VT or FF raised a bare `ValueError` from the
  header serialiser halfway through composing, outside the `BtxMailError` family and past
  warn mode; NUL, ESC and DEL went into the `Content-Disposition` header raw. Such a name is
  now an attachment security refusal (`FILENAME`), raised in strict mode and logged and
  skipped in warn mode, before any delivery.
- The source distribution ships only the package's `.py` files and `py.typed`, the tests,
  the Markdown docs, `README.md`, `LICENSE`, `CHANGELOG.md` and `pyproject.toml` (an include
  list), plus the `PKG-INFO` and root `.gitignore` hatchling always adds. Earlier sdists also
  carried repository working files such as `handover.md`, `OPEN-WORK.md` and
  `reset_git_history.sh`.

## [3.1.0] 2026-10-02 11:58:41

### Changed

- The `send` command builds one validated `ConfMail` (a copy of `conf` with each resolved
  option assigned) and passes it to `send()` as `config=`, instead of passing each setting as a
  separate keyword. `ConfMail`'s checks now run on CLI and environment input before any
  delivery, and settings the CLI has no option for keep their `conf` value.
- The `send` command names a refused EHLO name `smtp_local_hostname` (the field) rather than
  `local_hostname` (the `send()` keyword): `ValueError: smtp_local_hostname must be non-empty
  printable ASCII without spaces`, still exit code `22`.
- When one `send` command has several faults, a refused setting (host, timeout, EHLO name,
  attachment size) is now reported before a refused sender, recipient or attachment, because
  settings are checked when they are read.
- `validate_smtp_host` (and so `ConfMail.smtphosts` and the CLI) refuses a port that is not
  plain ASCII digits: a sign (`host:+25`), a digit separator (`host:2_5`) or non-ASCII digits
  (Arabic-Indic or fullwidth) are refused as `invalid smtp port in "<host>"`. Python's `int()`
  accepted them before. A port the range check already refused (`host:-25`) keeps its
  `port must be 1-65535` message.

### Fixed

- A whitespace-only `BTX_MAIL_SMTP_USE_STARTTLS` or `BTX_MAIL_SMTP_STARTTLS_VERIFY` (in the
  environment, or quoted in `.env`) keeps the default (`true`) instead of switching STARTTLS or
  certificate verification off. An unset or empty value already kept the default.
- `--attachment-max-size 0` (or `BTX_MAIL_ATTACHMENT_MAX_SIZE=0`, or a negative size) is
  refused as `ValueError: attachment_max_size_bytes must be positive, got 0` (exit code `22`).
  Before, the CLI passed it straight to `send()`, which refused every attachment as larger than
  the limit.

## [3.0.1] 2026-10-02 00:26:45

### Fixed

- A host 2.x already refused is refused with its 2.x message again. 3.0.0 ran its new checks
  before the port check, so `smtp.test.com:587:extra` was refused as an unbracketed IPv6
  address instead of `invalid smtp port`, and a consumer test pinning the 2.x message went red.
  The port and bracket checks now run first; the comma, extra-colon and empty-name checks run
  only on hosts they let through. The one 2.x text that stays changed is the range message
  without its `, got <port>` suffix (3.0.0, a credential leak).
- A host name with a second colon (`smtp.example.com:587:25`) is refused as `more than one ":"`,
  rather than as an IPv6 address it is not.

## [3.0.0] 2026-10-01 18:44:25

### Changed (breaking)

- `ConfMail` checks every `smtphosts` entry with `validate_smtp_host` at construction,
  `model_validate` and assignment, so a malformed host raises `ValidationError` (`loc`
  `("smtphosts",)`) when the configuration is built; before, `ConfMail` refused only userinfo, a
  path and control characters, and a bad port or an unclosed IPv6 bracket first failed at
  `send()`. The refusal does not repeat the host: `smtphosts` is a credential field.
- A blank `smtphosts` entry (an empty string, whitespace only) is dropped, so an empty
  environment value means "no hosts"; before, it was kept as `""` and skipped later by `send()`.
- `validate_smtp_host` also refuses a comma (`a.example.com,b.example.com`: two hosts in one
  string, which it read as host `a.example.com:25,b.example.com` on port 25), a port with no host
  name (`:25`, `[]:25`) and an IPv6 address without brackets (`fe80::1`, which it read as host
  `fe80:` on port 1). The CLI still accepts `--host a.example.com,b.example.com` and a
  comma-separated `BTX_MAIL_SMTP_HOSTS`: it splits on commas before validating.

### Fixed

- The out-of-range port message no longer ends in `, got <port>`. `ConfMail` scrubs the host from
  its errors as a whole string, and the re-quoted port escaped that scrub, so an all-digit secret
  written after a colon (`mailer:98765432`) reached the message.

### Documentation

- `docs/api.md`, `docs/configuration.md`, `docs/cli.md`, the module reference and the
  `python-send-mail` skill describe the host checks.

## [2.0.0] 2026-10-01 13:18:45

### Changed (breaking)

- `ConfMail` refuses a key that is not one of its fields (`extra="forbid"`). Construction and
  `model_validate` raise `ValidationError` with an `extra_forbidden` error naming the key, never
  its value; before, the key was dropped without a word. The `send()` keyword names are not field
  names, so `ConfMail(use_starttls=False, timeout=5)` used to leave STARTTLS on and the 30 s
  timeout in force; it now fails. A caller or loader that passes keys `ConfMail` does not have
  must map them onto the field names (`smtp_use_starttls`, `smtp_timeout`, ...) or leave them
  out; a subclass that must accept extra keys sets `model_config = ConfigDict(extra="ignore")`.

### Documentation

- The README, `docs/api.md`, `docs/configuration.md`, the module reference and the
  `python-send-mail` skill state the refusal; the skill shows a loader that maps config keys onto
  field names instead of passing the rest through.

### Development

- The `cryptography` dev floor is raised to 50.0.2.

## [1.8.0] 2026-09-29 14:14:27

### Added

- `ConfMail.smtp_local_hostname`, `send(local_hostname=)`, the CLI's
  `--local-hostname` and `BTX_MAIL_SMTP_LOCAL_HOSTNAME` set the name announced
  in `EHLO`. It must be non-empty printable ASCII without spaces; anything else
  is refused before a connection opens. `DeliveryOptions` gains
  `local_hostname: str | None = None`.

### Changed

- Without a configured name, the default `EHLO` name (smtplib's rule: the
  host's FQDN, else an address literal) is now looked up once per process and
  reused. smtplib ran that reverse DNS lookup for every connection, and
  delivery opens one per recipient, so a host with slow reverse DNS paid it
  per recipient (about 35 s each on macOS CI runners).

### Documentation

- `docs/configuration.md` and `docs/api.md` taught `ConfMail.model_update()`, which does
  not exist; they now update `conf` field by field (assignment is validated).
- `docs/api.md` lists the `send(transport=)` keyword, and the attachment-security keyword
  table shows their real default `None` (the config's value applies) instead of the
  effective defaults, which read as if passing `None` disabled a check.
- `docs/configuration.md` documents `raise_on_missing_attachments` and
  `raise_on_invalid_recipient`; `.env.example` lists `BTX_MAIL_SMTP_STARTTLS_VERIFY` and
  `BTX_MAIL_SMTP_LOCAL_HOSTNAME`.
- The module reference describes the import-linter layers contract and `typed_click`
  as they are.
- The python-send-mail skill covers the EHLO name, one connection per recipient, and
  the `smtp_` prefix of `ConfMail` fields (an unknown `ConfMail` key is ignored, not
  refused).

### Build

- The `[tool.pip-audit]` ignore list is empty. None of its 13 ids fired: with no
  ignores, pip-audit reports nothing on the resolved dev tree for Python 3.10-3.14 or on
  any project venv (each id named a package absent from the tree or one already past its
  fix).

### Tests

- The in-process aiosmtpd test servers set their own server name, so they no
  longer call `socket.getfqdn()`. That reverse DNS lookup took about 30 s on
  macOS CI runners, so every wire test there timed out at start and was
  skipped; the retry-then-skip wrapper that hid this is gone, and a start
  failure now fails the test (only the port bind race is retried).

## [1.7.0] 2026-09-29 11:30:27

### Security

- `ConfMail` refuses an empty `attachment_blocked_extensions` or
  `attachment_blocked_directories` when the matching allowlist
  (`attachment_allowed_extensions` / `attachment_allowed_directories`) is not
  set, because such a set blocks nothing. A configuration file writing `[]` to
  mean "use the defaults" used to switch executable and system-directory
  blocking off silently; it is now a `ValidationError` at load (and on
  assignment to `conf`). New field `attachment_allow_empty_blocklists: bool =
  False` opts into blocking nothing on purpose. An explicit
  `send(attachment_blocked_*=frozenset())` keyword is not affected.
- `SecretSafeModel` checks `credential_fields` when a subclass is defined and
  raises `TypeError` for a name that is not a declared field (a typo, or an
  alias listed instead of its field), for a value that is not a set of str (a
  plain `"password"` was read as its letters), and for an annotated
  `credential_fields` (pydantic turned it into a field, leaving the inherited
  empty set in charge). Each of those silently protected nothing.

### Fixed

- A validated assignment on a `SecretSafeModel` (so on `ConfMail` and `conf`)
  that a model-level `mode="after"` validator refuses is rolled back. pydantic
  writes the new value before that validator runs and kept it after the error.
  The rollback covers any exception the validator raises; it is shallow, so a
  value the validator mutated in place before raising stays mutated.

### Changed / Breaking

- `ConfMail(attachment_blocked_extensions=frozenset())` (or `_directories`)
  without an allowlist now raises unless `attachment_allow_empty_blocklists=True`
  is also passed.
- A `SecretSafeModel` subclass with an invalid `credential_fields` now fails at
  import with `TypeError`. That includes a base class listing a field that only
  its subclasses declare: list it in the subclass that declares the field.

## [1.6.0] 2026-09-29 01:04:40

### Security

- The per-host delivery WARNING no longer attaches the exception. A non-ASCII
  SMTP password made smtplib raise `UnicodeEncodeError`, whose repr quotes the
  whole AUTH string, and structured loggers (for example lib_log_rich JSON dumps)
  wrote the password out in full. Upgrade to stop the leak. Applications with
  their own settings model for SMTP credentials are NOT covered by this release
  until they build that model on `ConfMail` or `SecretSafeModel`.
- `ConfMail` validation errors never carry the password (not in `str()`,
  `errors()` or `json()`), including errors raised by a subclass's own
  model-level validators.
- `validate_smtp_host()` (and the CLI `validate-smtp-host`, which calls it)
  now refuse a host containing `@` or `/` (for example `smtp://user:pw@host`),
  or interior whitespace or a control character (outer whitespace is still
  trimmed), without echoing the value. The same refusal applies wherever a
  host reaches `send()` or a `ConfMail` build/assignment; such hosts were
  previously quoted in the log, in the delivery `RuntimeError`, and in
  `repr()` / `model_dump_json()` of the config.
- `DeliveryOptions` no longer prints its credentials in `repr()`.
- Host, recipient, sender and attachment-path values are passed through a
  control-character cleaner before they reach any log line, log `extra` or
  raised error text (a recipient or a filename containing a newline or an ESC
  sequence could forge log lines or inject terminal sequences);
  `AttachmentSecurityError` cleans its reason and rendered path.
- A hidden validation error's message is scrubbed of the input's text
  (best-effort: verbatim, repr, ascii and JSON-escaped forms; a transformed
  value is not recognised).
- `str(ValidationError)` of any `ConfMail` error (`hide_input_in_errors=True`)
  no longer shows `input_value=` for any field, credential or not; `.errors()`
  still carries a kept scalar's input (a non-credential field such as
  `smtp_timeout` keeps its value there, just not in the printed string).
- The per-host delivery WARNING is now logged after the `except` block that
  caught the failure has exited, not from inside it. Two things follow: a
  broken log handler or formatter can no longer chain that failure onto its
  own traceback via `__context__` ("During handling of the above exception
  ..."), and `sys.exc_info()` is empty by the time the warning is emitted, so
  a log sink that reads it during emit (rather than relying on `__context__`)
  no longer sees the delivery error either.

### Added

- `send(config=...)`: deliver with a given `ConfMail` instead of the global
  `conf`; when `config` is passed, `conf` is not read.
- `SecretSafeModel`, `redact_validation_error`, `REDACTED_INPUT` for settings
  models that hold credentials; `DeliveryOptions` and `Transport` exported.
- Non-ASCII SMTP credentials authenticate with UTF-8 AUTH PLAIN (RFC 4616).
- `redact_validation_error(..., declared_names=...)`: keyword-only; mapping
  keys equal to declared field names are not scrubbed from messages.
- The shipped python-send-mail skill documents `send(config=)`, non-ASCII
  credentials and AUTH PLAIN, that `send()` raises `RuntimeError` (never
  `SMTPNotSupportedError`) when every host failed, and how a settings model
  extends `credential_fields`.

### Changed

- **Breaking:** every host list entry carrying `@` or `/` (userinfo or a URL)
  is now refused up front with `ValueError` before any delivery, and a
  `ConfMail` built or assigned such a host raises `ValidationError` at that
  point instead of at send time. This changes behaviour for every such entry
  except one: at 1.5.x, `host.rsplit(":", 1)` read everything after the LAST
  `:` as the port, so `smtp://user:pw@relay:25`, `user@relay` and the
  commonest userinfo form `user:pw@relay:587` all parsed as a valid
  hostname[:port] pair (the whole `user:...@relay` text became the
  "hostname"), reached delivery, and failed over to the next host, quoting
  the password in the per-host log line and in the `RuntimeError` raised
  once every host failed. They are now refused eagerly instead. Only the
  port-less `user:pw@relay` was already refused at 1.5.x, by the same
  `rsplit` accident: with no second `:`, `rsplit` handed `pw@relay` to the
  port parser, which rejected it as non-numeric and quoted the whole string,
  password included, in `ValueError: invalid smtp port in "..."`. It is now
  refused deliberately, without quoting the value. Remove the entry and pass
  the credentials as `smtp_username` / `smtp_password`.
- The per-host WARNING reads `can not send mail to "<rcpt>" via host "<host>":
  <failure>` (one line, control characters replaced) and carries `error_type`
  and `smtp_code` extras; the traceback is no longer attached.
- `smtp_password` accepts an int as its decimal text; float, bool and container
  values are refused with only their type named.
- The `ConfMail` / `SecretSafeModel` redaction keeps an error's input only for
  simple scalar types (str, bytes, int, float, bool, None, Decimal,
  date/datetime/time/timedelta, and an Enum whose value is such a scalar); any
  other input (a dict, list, dataclass, namespace, ...) is shown as
  `"[redacted]"` in every error, not only at credential fields. Hidden custom
  validation errors keep their message but lose their `ctx`.
- Hosts with interior whitespace or control characters are refused (such hosts
  could never deliver).

## [1.5.2] 2026-07-30 18:08:05

### Changed

- **The shipped skill's plugin version now tracks the package version.** bmk 3.14.0 raises
  `.claude-plugin/plugin.json` to the package version on bump, push and release, and never lowers
  it. An install re-fetches a skill only when that version changes, so the two numbers drifting
  apart meant a skill edit could ship to nobody. No functional change to the library.

## [1.5.1] 2026-07-24 16:48:37

### Fixed
- Latest `ruff` (0.16) widened its default rule set to ~920 rules; CI went red
  because this repo had no explicit `[tool.ruff.lint].select`. Pinned the
  bitranox curated select (plus Pydantic `runtime-evaluated-base-classes` for
  `ConfMail` and library/test per-file-ignores) so a future `ruff` release
  cannot silently re-explode the policy again.
- `PLR0917`/`FBT001` on internal CLI/`lib_mail` helpers: made the boolean
  argument keyword-only and updated every call site; `send()`,
  `cli_send_mail()`, and the documented `apply_traceback_preferences()` stayed
  positional-compatible with a narrow `noqa` since they are public API.
- Replaced two `try`/`except ValueError` directory-membership loops with
  `Path.is_relative_to()` (no exception needed), replaced two `try`/`except`
  loops flagged by `PLR2004`/`PERF203`/`SIM105` with named SMTP reply-code
  constants and `contextlib.suppress`, and named the dot-stuffer's raw byte
  literals via `ord(".")`/`ord("\n")`.

### Changed
- Removed the ad hoc "unused noqa" cleanups that had drifted out of sync with
  the enabled rule set; every remaining `noqa`/`nosec` now matches a rule that
  is actually enabled.

## [1.5.0] 2026-07-19

### Added
- Streamed attachment delivery with bounded memory: the message is composed once
  into a disk-backed spool and streamed to the SMTP socket in fixed-size chunks,
  so peak memory stays roughly constant regardless of attachment size. Raise or
  unset `attachment_max_size_bytes` (default 25 MiB) to send a very large file.
- RFC 3030 BDAT/CHUNKING: when the server advertises `CHUNKING` the message is
  sent with `BDAT` framing; otherwise the classic `DATA` phase is used with
  incremental dot-stuffing. Selected automatically per host.
- `Transport` protocol and default `SmtplibTransport`, with an optional
  `send(..., transport=...)` override (a delivery seam for testing or alternative
  transports).
- A bundled Claude Code usage skill (`python-send-mail`): the repo now installs
  as a single-plugin marketplace, and the skill is mirrored into `bitranox-skills`
  as `coding-python-send-mail`. The CLI runs zero-install via `uvx btx-lib-mail`.

### Changed
- Attachment bytes are read at send time: `AttachmentPayload` carries the source
  `Path` instead of eager `content: bytes`. Message assembly moved to
  `email.message.EmailMessage` with `email.policy.SMTP` (CRLF line endings).
- Package `description` and `keywords` corrected from the template placeholder.
- README rewritten as an intro plus quickstart; the reference material moved into
  `docs/` (installation, CLI, configuration, streaming, attachment security,
  public API).

### Dev
- Added `aiosmtpd` and `cryptography` as dev-only dependencies for the real-server
  delivery e2e tests (DATA, BDAT, STARTTLS with authentication, and a memory bound).

## [1.4.0] 2026-07-19

### Added
- STARTTLS certificate-verification control: `ConfMail.smtp_starttls_verify`
  (default `True`), the `send(..., starttls_verify=...)` parameter, the
  `--starttls-verify/--no-starttls-verify` CLI flag, and the
  `BTX_MAIL_SMTP_STARTTLS_VERIFY` environment variable. Setting it to `False`
  keeps STARTTLS encryption but skips certificate/hostname validation, for
  internal self-signed relays.
- `AttachmentViolation` public enum (a `str` enum) naming the attachment
  security violation categories.

### Changed
- `ConfMail.smtp_password` is now a `pydantic.SecretStr`, masked in `repr()` and
  `model_dump()`; `resolved_credentials()` returns the plaintext for SMTP login,
  and a plain string is still coerced. Type-checkers that pass a bare `str`
  explicitly must wrap it in `SecretStr(...)`.
- `AttachmentSecurityError.violation_type` is now an `AttachmentViolation` member
  instead of a bare string. Members subclass `str`, so `== "symlink"` comparisons
  keep working.
- The import-linter contract now enforces the `cli -> lib_mail -> behaviors`
  layering (previously only `cli -> behaviors`).

### Fixed
- Email validation no longer accepts a literal `|` in the top-level domain
  (the character class `[A-Z|a-z]` is corrected to `[A-Za-z]`).

## [1.3.2] - 2026-06-14

### Changed
- Added a `typed_click.py` facade wrapping rich-click's `option` / `version_option` / `argument` decorators behind explicit, fully-known signatures, keeping the CLI strict-clean under pyright 1.1.410 (`reportUnknownMemberType`) without disabling the rule (ignore isolated to the facade).
- Bumped `lib_cli_exit_tools` floor to `>=2.3.2`.
- Migrated build automation from the in-repo `scripts/` package to the external `bmk` tooling (`uvx bmk`); removed the obsolete `scripts/` directory and `[tool.scripts.test]` config.

## [1.3.1] - 2026-02-01

### Added
- Per-call `raise_on_missing_attachments` parameter in `send()` to override
  `conf.raise_on_missing_attachments` on a per-call basis (`None` uses default,
  `True` raises on missing, `False` logs warning and skips).
- Per-call `raise_on_invalid_recipient` parameter in `send()` to override
  `conf.raise_on_invalid_recipient` on a per-call basis (`None` uses default,
  `True` raises on invalid, `False` logs warning and skips).

### Changed
- `_prepare_recipients()` and `_prepare_attachments()` now accept explicit
  parameters instead of reading directly from the global `conf` object,
  enabling per-call override behaviour.

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
- Removed unnecessary `cast(Any, ...)` from the `smtp_timeout` assignment test;
  pyright already accepts `float -> float` without suppression.

### Changed
- Clarified the `cast(Any, ...)` comment in `test_conf_mail_assignment_validates`
  to document it as a deliberate type-mismatch bypass for Pydantic's runtime
  field-validator coercion (`str -> list[str]`), not a missing-stub workaround.

## [1.2.0] - 2026-01-27
### Added
- Public `validate_email_address()` for email syntax validation (API + CLI).
- Public `validate_smtp_host()` for SMTP host format validation with IPv6
  bracket support (API + CLI).
- CLI subcommands `validate-email` and `validate-smtp-host`.

### Changed
- SMTP host validation now supports IPv6 bracketed addresses (`[::1]:25`).

### Removed
- `_is_valid_email_address()`  -  replaced by `validate_email_address()`.
- `_split_host_and_port()`  -  replaced by `validate_smtp_host()` and `_parse_smtp_host()`.

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
