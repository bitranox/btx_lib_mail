# Module Reference: btx_lib_mail

## Status

Production library, published to PyPI. The version is in `pyproject.toml` and
`src/btx_lib_mail/__init__conf__.py`; the changes per release are in `CHANGELOG.md`.

## Links & References

**Repository:** https://github.com/bitranox/btx_lib_mail
**PyPI:** https://pypi.org/project/btx-lib-mail/
**Documentation:** README.md, docs/api.md, docs/cli.md, docs/configuration.md,
docs/attachment-security.md, docs/streaming.md, docs/installation.md, CHANGELOG.md
**Related Files:**

* src/btx_lib_mail/__init__.py (public API surface)
* src/btx_lib_mail/lib_mail.py (`send()` and the public face of the mail modules)
* src/btx_lib_mail/_config.py, _attachments.py, _validation.py, _compose.py,
  _transport.py, _common.py, _descriptor_path.py (private modules behind `lib_mail`)
* src/btx_lib_mail/errors.py (`BtxMailError` and its subclasses)
* src/btx_lib_mail/secret_safety.py (credential-safe pydantic validation errors)
* src/btx_lib_mail/cli/ (package), typed_click.py, __main__.py (command-line adapter)
* src/btx_lib_mail/behaviors.py, __init__conf__.py (scaffold helpers, static metadata)

---

## Problem Statement

Sending mail from Python with the standard library alone leaves every caller to solve
the same problems again:

1. `smtplib` and `email` buffer a whole message, attachments and their base64
   expansion included, so a large attachment costs a multiple of its size in memory.
2. Neither implements the client side of RFC 3030 BDAT/CHUNKING.
3. A path handed in as an attachment can be a private key, a system file, an
   executable, a symlink, or a file swapped after it was checked.
4. A password in configuration leaks through pydantic validation errors, `repr`,
   exception text and log lines unless every one of those is guarded.
5. A script needs to fail over across relays, report failures without tracebacks, and
   be drivable by a machine (structured output, stable exit codes).

---

## Solution Overview

1. **Streamed delivery** - the message is composed once into a spooled temp file and
   streamed to the socket in fixed chunks, as BDAT when the server offers CHUNKING,
   otherwise through the DATA phase with incremental dot-stuffing.
2. **Attachment security** - path traversal, symlink, sensitive-path, directory,
   extension and size rules, then each file is opened once and compared with what was
   checked, so the bytes sent are those of the checked file.
3. **Secret safety** - `ConfMail` keeps the password in a `SecretStr` and inherits
   `SecretSafeModel`, whose validation errors never carry a credential.
4. **One error base** - every refusal and delivery failure is a `BtxMailError`, each
   also an instance of the builtin a caller would otherwise catch.
5. **Machine-drivable CLI** - `--json` envelopes, documented exit codes, settings from
   options, the environment or a named env file, and a transport seam for embedding.

---

## Architecture Integration

**Layer Structure** (enforced by the import-linter layers contract in `pyproject.toml`;
a module imports only from layers below it, and modules in one layer do not import
each other):

```
cli                                         (rich-click adapter; also typed_click, __main__)
lib_mail                                    (send() and the public re-exports)
_compose                                    (message assembly)
_config | _transport                        (ConfMail and conf | Transport, SmtplibTransport)
_attachments | _validation                  (attachment security | address and host checks)
_common | _descriptor_path | secret_safety | errors
                                            (logger and printable | the path of an open file |
                                             SecretSafeModel | exceptions)
behaviors                                   (scaffold helpers)
```

**Data Flow:**

```
cli.cli_send_mail   options > environment > --env-file > conf, assigned onto one ConfMail copy
  -> lib_mail.send  resolve keywords against config (or conf)
       -> _validation.prepare_recipients / prepare_hosts, check_subject
       -> _attachments.prepare_attachments   check each path, open each file once
       -> _compose.compose_body_once         encode body and attachments once into a spool
       -> per recipient: _compose.message_for (its header lines + the shared body, read in place)
            -> lib_mail._deliver_to_any_host  failover across hosts
                 -> Transport.deliver          SmtplibTransport: connect, STARTTLS, AUTH, BDAT or DATA
```

**Dependencies:**

* **Runtime:** `pydantic` (configuration model, secret-safe errors), `rich-click`
  (CLI), `lib_cli_exit_tools` (signals, error rendering, exit codes).
* **Development:** pytest, aiosmtpd (real in-process SMTP server for wire tests), ruff,
  pyright, bandit, import-linter, pip-audit (the `[dev]` extra).

---

## Core Components

### `__init__` Module (Public API)

Re-exports the public surface so callers import from `btx_lib_mail` and never from a
private module. `__all__`: `send`, `conf`, `ConfMail`, `logger`, `validate_email_address`,
`validate_smtp_host`, `DeliveryOptions`, `Transport`, the errors (`BtxMailError`,
`InvalidInputError`, `ConfigurationError`, `AttachmentNotFoundError`, `DeliveryError`,
`AttachmentSecurityError`), `AttachmentViolation`, the security constants
(`DANGEROUS_EXTENSIONS_POSIX`, `DANGEROUS_EXTENSIONS_WINDOWS`,
`DANGEROUS_DIRECTORIES_POSIX`, `DANGEROUS_DIRECTORIES_WINDOWS`, `SENSITIVE_PATH_PATTERNS`),
the secret-safety names (`SecretSafeModel`, `redact_validation_error`, `REDACTED_INPUT`),
and the scaffold helpers (`CANONICAL_GREETING`, `emit_greeting`, `noop_main`,
`print_info`, `raise_intentional_failure`).

**Location:** src/btx_lib_mail/__init__.py

---

### `lib_mail` Module (Delivery Entry Point)

#### `send(...) -> bool`

**Purpose:** Turn validated intent (sender, recipients, subject, bodies, attachments)
into SMTP delivery under the configured delivery and security policies.

**Input:** `mail_from`, `mail_recipients`, `mail_subject`, `mail_body`,
`mail_body_html`, `smtphosts`, `attachment_file_paths` (these seven may be passed
positionally), then keyword-only `credentials`, `use_starttls`, `starttls_verify`,
`timeout`, `local_hostname`, `delivery_deadline`, the `attachment_*` security
overrides, `raise_on_missing_attachments`, `raise_on_invalid_recipient`, `config` and
`transport`. A keyword left at `None` takes its value from `config`, else from the
module-global `conf`.

**Output:** `True` when every recipient was delivered; a failure raises.

**Raises:** `InvalidInputError` (refused sender, recipient, host, subject, EHLO name,
timeout or deadline; no valid recipient), `AttachmentNotFoundError`,
`AttachmentSecurityError`, `DeliveryError` (every host failed for a recipient; carries
`failed_recipients` and `hosts`). All are `BtxMailError`. Every refusal happens before
the first delivery.

**Location:** src/btx_lib_mail/lib_mail.py

#### Delivery internals

* `_DeliveryPlan` bundles the hosts, the resolved `DeliveryOptions` and the transport for
  one call. `_resolve_delivery_options` and `_resolve_attachment_security_options` merge
  the keywords with the config in use.
* `_deliver_to_any_host(sender, recipient, message, plan)` rewinds the message and tries
  each host in order until the transport accepts it; each failed host logs one credential-free `WARNING`
  built by `_describe_failure` (an SMTP reply: class, code and text; another `OSError`:
  class and text; anything else: class only; control characters cleaned, capped at 200
  characters), the success path one `DEBUG` line. `_deliver_composed` builds a recipient's
  message, delivers it, and closes it.
* `DEFAULT_TRANSPORT` (an `SmtplibTransport`) is read from this module at call time, so a
  test can replace it here.

**Location:** src/btx_lib_mail/lib_mail.py

---

### `_config` Module (Settings)

#### `ConfMail`

**Purpose:** The validated SMTP and attachment-security settings model; `conf` is the
module-global instance `send()` reads when no `config` is passed.

**Fields:** `smtphosts`, `raise_on_missing_attachments`, `raise_on_invalid_recipient`,
`recipient_max_count`, `smtp_username`, `smtp_password` (`SecretStr`), `smtp_use_starttls`,
`smtp_starttls_verify`, `smtp_timeout`, `smtp_local_hostname`,
`smtp_delivery_deadline`, and the `attachment_*` fields. Defaults and meanings are
tabled in [docs/api.md](../api.md#confmail-fields).

**Validation:** hosts through `validate_smtp_host` (a blank entry is dropped);
`smtp_password` accepts text or a whole int; `smtp_timeout` and `smtp_delivery_deadline`
positive and finite; `smtp_local_hostname` printable ASCII without spaces; extension and
directory sets normalised; an empty blocked set without its allowlist refused unless
`attachment_allow_empty_blocklists`; an unknown key refused (`extra="forbid"`).
Assignment is validated too. Every refusal is a `ConfigurationError` whose input is
redacted at the credential fields (`smtp_password`, `smtphosts`).

**Location:** src/btx_lib_mail/_config.py

---

### `_attachments` Module (Attachment Security)

* Constants: `DANGEROUS_EXTENSIONS_POSIX`, `DANGEROUS_EXTENSIONS_WINDOWS` (both blocked
  by default on every platform, through `default_blocked_extensions`),
  `DANGEROUS_DIRECTORIES_POSIX`, `DANGEROUS_DIRECTORIES_WINDOWS` (the running platform's
  set is the default), `SENSITIVE_PATH_PATTERNS` (matched ignoring case on macOS and
  Windows, exactly elsewhere: `_PATHS_IGNORE_CASE`).
* `AttachmentViolation` - `str` enum: `PATH_TRAVERSAL`, `SYMLINK`, `SENSITIVE_PATTERN`,
  `DIRECTORY`, `EXTENSION`, `SIZE`, `CHANGED`, `FILENAME`.
* `AttachmentSecurityError(BtxMailError)` - `path`, `reason` (control characters
  replaced), `violation_type`.
* `AttachmentPayload` - `filename`, `source` (the checked, resolved path), `handle` (the
  file opened once), `size_limit`.
* `AttachmentSecurityOptions` - the resolved rules for one call.
* `coerce_attachment_paths(entries)` - each `str` or `pathlib` entry as a `Path`; any
  other type is an `InvalidInputError`.
* `normalise_extensions(values)`, `normalise_directories(values)` - the extension and
  directory sets as `ConfMail` and the `send()` keywords both read them.
* `prepare_attachments(paths, security, *, raise_on_missing)` - refuses more paths than
  `security.max_count`, then for each path the path checks (`_validate_attachment_security`:
  NUL anywhere, traversal component, final-component symlink, then on the resolved path the
  file name (control character, invalid Unicode), sensitive pattern, directories and
  extension), then
  `_open_attachment`: `lstat`, open with `O_NOFOLLOW`/`O_NONBLOCK` where the platform
  has them, `fstat` must show the same device and inode and a regular file, size within
  the limit, and the path the kernel reports for the open file (`_check_descriptor_path`,
  through `_descriptor_path.descriptor_path`) passes the same path checks when it differs
  from the checked one. A swapped path is `CHANGED`; an open the OS refuses is reported like a missing
  file (`can not be read (EACCES)`). Warn mode logs and skips via `log_violation`;
  every handle is closed on failure, and by `send()` through `close_attachments`.

**Location:** src/btx_lib_mail/_attachments.py

---

### `_compose` Module (Message Assembly)

* `compose_body_once(content, *, raise_on_violation)` - encodes the recipient-independent
  part (`MessageContent`: bodies and attachments) once into a `SpooledTemporaryFile` (in
  memory below 1 MiB, on disk above), CRLF via `email.policy.SMTP`, each attachment's
  base64 streamed from its open file in `57 * 1024`-byte reads and counted against its
  size limit. In warn mode a file that grew past the limit is left out and the body
  composed again.
* `envelope_header_lines(...)` - each recipient's `Subject`, `From`, `To`, `Date`; `Subject` and `From` are folded once per call.
* `message_for(header_lines, body)` - a read-only, seekable stream of those header lines
  followed by the shared body spool, read in place (no copy); closing it leaves the body open.
* `check_subject(subject)` - refuses CR or LF (with the email package's own message), any
  other control character except TAB, the line separators U+2028/U+2029 (with the CR/LF
  message), a lone surrogate, and more than `SUBJECT_MAX_CHARACTERS` (4096), checked last.
* `check_body(*, plain_body, html_body)` - refuses a body holding a lone surrogate.

**Location:** src/btx_lib_mail/_compose.py

---

### `_transport` Module (Delivery Seam)

* `Transport` - protocol: `deliver(*, host, sender, recipient, message, delivery)`
  delivers one composed message or raises.
* `DeliveryOptions` - `credentials` (not in `repr`), `use_starttls`, `starttls_verify`,
  `timeout`, `local_hostname`, `deadline`.
* `SmtplibTransport` - opens an `smtplib.SMTP` session (EHLO name: the configured one,
  else `_default_local_hostname()`, smtplib's rule computed once per process), STARTTLS
  with `_build_starttls_context(verify=...)`, a `WARNING` when credentials go out with
  STARTTLS off, AUTH through `_authenticate` (stdlib login for ASCII credentials, RFC 4616
  AUTH PLAIN in UTF-8 otherwise), then streams the message in `STREAM_CHUNK_SIZE`
  (64 KiB) pieces: `BDAT` when the server advertises CHUNKING, else `DATA` with
  `_DotStuffer`. `_session_deadline` bounds the session when `deadline` is set: a
  watchdog thread shuts the socket down and the failure becomes a `TimeoutError`.

**Location:** src/btx_lib_mail/_transport.py

---

### `_validation` Module (Checks)

* `validate_email_address(address)` - `InvalidInputError` unless `EMAIL_PATTERN` matches.
* `validate_smtp_host(host)` - accepts `host`, `host:port`, `[IPv6]`, `[IPv6]:port`.
  Refuses, without echoing the value, a host carrying `@` or `/` or an interior
  whitespace or control character; then refuses a bad bracket or a port that is not ASCII
  digits in 1-65535, and after that a comma, an unbracketed IPv6 address or an empty host
  name; last, bracket content that is not an IP address and a name DNS can never resolve
  (an empty label, a label's leading or trailing `-`, over 63 per label or 253 in all).
* `prepare_recipients`, `prepare_hosts`, `parse_smtp_host`, `collect_host_inputs`,
  `check_local_hostname`, `check_timeout`, `check_seconds` - the shared checks `send()`
  and `ConfMail` run.
* `require_text`, `require_flag`, `require_number`, `require_ceiling`, `require_collection`,
  `require_credentials` - the type checks for `send()` arguments and keyword overrides, each an
  `InvalidInputError` naming the argument (`timeout must be a number of seconds, got str`).

**Location:** src/btx_lib_mail/_validation.py

---

### `_common` Module

`logger` (`logging.getLogger("btx_lib_mail")`) and `printable(text)`, which replaces
every non-printable character with a space so no caller-, file- or server-supplied text
can forge a log line, and `is_valid_unicode(text)`, the UTF-8 test the subject, body and
attachment-name checks share (each raises its own error).

**Location:** src/btx_lib_mail/_common.py

---

### `errors` Module

`BtxMailError` and its subclasses `InvalidInputError` (`ValueError`),
`ConfigurationError` (pydantic `ValidationError`), `AttachmentNotFoundError`
(`FileNotFoundError`) and `DeliveryError` (`RuntimeError`, with `failed_recipients` and
`hosts`).

**Location:** src/btx_lib_mail/errors.py

---

### `secret_safety` Module

* `SecretSafeModel` - pydantic base whose every validation error is rebuilt without a
  credential: the core schema is wrapped, and so are assignment, `model_validate*` and
  construction (a metaclass `__call__`, since an `__init__` override would make pydantic
  drop `strict=`). `credential_fields` names the fields whose input is always hidden;
  `validation_error_class` names the `ValidationError` subclass raised (`ConfMail`:
  `ConfigurationError`). A refused assignment is rolled back.
* `redact_validation_error(exc, *, credential_fields, declared_names=frozenset(),
  error_class=ValidationError)` - the rebuild, usable on any pydantic model's error;
  raise the result outside the `except` block that caught the original.
* `REDACTED_INPUT` - `"[redacted]"`.

Not covered: malformed JSON given to `TypeAdapter(Model).validate_json` or to a plain
outer model's `model_validate_json`, where the JSON parser fails before the model runs.

**Location:** src/btx_lib_mail/secret_safety.py

---

### `cli` Module (Transport Adapter)

* **Group `cli`:** `--traceback/--no-traceback`, `--json`/`-j`, `--json-bare`, `--version`;
  stores a `CliContext` (`traceback`, `json_output`, `json_bare`, `transport`) in
  `ctx.obj`, keeping a transport an embedding caller passed through `obj=`.
* **Commands:** `info`, `hello`, `send`, `validate-email`, `validate-smtp-host`, `fail`.
  Each prints through `emit` (`_output`), which writes the human line or the JSON envelope.
* **`send`:** `Sources` (`_settings_sources`) reads the environment, then the env file `env_file_to_read`
  picks: the one named by `--env-file` / `BTX_MAIL_ENV_FILE`, else `./.env` when it is a
  regular file (parsed once by `read_env_file`, UTF-8, at most 64 KiB). Resolved values are assigned onto one copy of `conf`, so
  `ConfMail`'s checks run before delivery; a refusal is re-raised as `InvalidInputError`
  with the validator's message (`refusals_as_value_error`). `--password-file` reads one
  line (`-` is stdin). `collect_skipped` (a logger filter) gathers the warn-mode skips for
  the envelope's `skipped`.
* **`main(argv)`:** runs the group through `lib_cli_exit_tools.run_cli`; with `--json` or
  `--json-bare` in argv, `_json_exception_handler` prints a failure as JSON on stdout and
  returns the exit code the plain run would give. Traceback state is restored afterwards.

**Location:** src/btx_lib_mail/cli/ - `__init__.py` is the public surface (`cli`, `main`,
`CliContext`, the commands, the traceback helpers); the private submodules hold one concern
each: `_settings_sources`, `_output`, `_traceback`, `_commands`, `_send_command`, `_dispatch`.

### `typed_click` Module (Type Boundary)

Typed wrappers (`option`, `version_option`, `argument`) over rich-click's decorators,
whose own types are partially unknown to pyright: a typed `Protocol` plus a `cast`
forwards to the real decorators.

**Location:** src/btx_lib_mail/typed_click.py

### `__main__` Module (Module Entry Point)

`python -m btx_lib_mail` runs `cli.main()`, the function the console scripts run, so exit
codes, traceback handling and JSON failure reports are identical.

**Location:** src/btx_lib_mail/__main__.py

---

## Behaviour Scaffold

### `behaviors` Module

`CANONICAL_GREETING` (`"Hello World"`), `emit_greeting(*, stream=None)`,
`raise_intentional_failure()` (always `RuntimeError("I should fail")`) and `noop_main()`:
the placeholder paths the `hello`, `fail` and bare `--traceback` invocations exercise.

**Location:** src/btx_lib_mail/behaviors.py

### `__init__conf__` Module

Static metadata constants kept in sync with `pyproject.toml` (`name`, `title`, `version`,
`homepage`, `author`, `author_email`, `shell_command`, and the layered-config
identifiers) and `print_info()`, which renders them for `info`.

**Location:** src/btx_lib_mail/__init__conf__.py

---

## Implementation Details

**Memory:** peak memory while composing is about one 57 KiB read plus the 1 MiB spool
buffer, and while streaming about one 64 KiB chunk, independent of attachment size
(pinned by `tests/test_streaming.py` and `tests/test_transfer_memory.py`). The trade is
temporary disk for a message above 1 MiB: the encoded body, about 1.37x the attachment,
once per `send()` however many recipients there are.

**Ordering of refusals:** sender, recipients, attachment rules, attachments, hosts,
delivery options, subject; every one before the first delivery.

**Logging:** every caller-, file- or server-supplied value in a log line or exception
message goes through `printable`; no log line carries a password.

---

## Testing Approach

* `tests/test_lib_mail.py` - configuration, validators, attachment rules, orchestration
  through an injected `Transport`.
* `tests/test_attachment_integrity.py` - open once, encode once, swaps, growth, closed
  handles, subject and timeout refusals.
* `tests/test_streaming.py`, `tests/test_transfer_memory.py`, `tests/test_deadline.py` -
  wire behaviour against a real in-process server (`tests/smtp_test_server.py`, the
  `data_server` fixture in `tests/conftest.py`), memory bounds, the delivery deadline.
* `tests/test_cli.py`, `tests/test_cli_send.py`, `tests/test_module_entry.py` - the CLI,
  driven with `CliContext(transport=...)` or a real server; no test patches the package's
  own `send`.
* `tests/test_errors.py`, `tests/test_secret_safety.py`, `tests/test_behaviors.py`,
  `tests/test_metadata.py`.

Doctests run through `--doctest-modules`; markers `os_agnostic`, `os_windows`, `os_macos`,
`os_posix`, `os_linux`, `local_only` (real SMTP through `TEST_SMTP_*`). Coverage gate:
`fail_under = 85`.

---

## Known Limitations

* A symlinked directory along an attachment path is followed (`allow_symlinks` governs
  the last component); every rule runs on the resolved target.
* A directory swapped for a symlink between the path checks and the open is not detected
  by the device/inode comparison, which covers the file itself.
* SMTPS (implicit TLS on port 465) is not supported; use STARTTLS.
* `send()` sends a separate message per recipient; there is no Cc or Bcc.

---

## Security Considerations

* Credentials: `SecretStr` in `ConfMail`, hidden from `repr`, `model_dump`, validation
  errors, `DeliveryOptions` repr and failure logs; a host carrying `user:password@` is
  refused without echoing it; the CLI offers `--password-file`. The CLI reads `./.env`
  unless `--env-file` names another file, so a `.env` is trusted like the command line.
* Transport: STARTTLS on and certificate verification on by default; STARTTLS fails
  closed when the server does not offer it; credentials sent without TLS are logged as a
  warning.
* Input: header injection (CR/LF/NUL in sender, recipient, subject, filename) refused or
  encoded; dot-stuffing and CRLF normalisation keep the DATA phase unambiguous.
* Attachments: see the `_attachments` section and
  [docs/attachment-security.md](../attachment-security.md).
