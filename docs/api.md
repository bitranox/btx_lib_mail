# Public API reference

Everything importable from `btx_lib_mail` is described here; the internal design is in
[the module reference](systemdesign/module_reference.md). Run
`python -c "import btx_lib_mail as m; help(m)"` for the docstrings of the installed version.

## Configuration Surface

#### `btx_lib_mail.conf: ConfMail`

`conf` is the global configuration instance used whenever a `send` caller does
not supply per-call overrides or a `config=`. Change it field by field
(`conf.smtp_timeout = 10.0`, validated on assignment); rebinding the name
(`btx_lib_mail.conf = ConfMail(...)`) has no effect on `send()`, which keeps reading the
original object. To use a different settings object, pass it as `send(config=...)`.

#### `ConfMail` fields

**SMTP Settings:**

| Field                          | Type                | Default | Description                                                                                                                                                                                                                                                                                                                                             |
|--------------------------------|---------------------|---------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `smtphosts`                    | `list[str]`         | `[]`    | Ordered SMTP hosts (`"host[:port]"`, `"[IPv6]:port"`). Each entry is checked with `validate_smtp_host` at construction and assignment; a blank entry is dropped. An empty list requires callers to supply `smtphosts` when sending.                                                                                                                     |
| `raise_on_missing_attachments` | `bool`              | `True`  | When `True`, missing attachments raise `AttachmentNotFoundError` (a `FileNotFoundError`); otherwise a warning is logged and delivery proceeds without the attachment.                                                                                                                                                                                   |
| `raise_on_invalid_recipient`   | `bool`              | `True`  | When `True`, invalid recipient addresses raise `InvalidInputError` (a `ValueError`); otherwise a warning is logged and the address is skipped.                                                                                                                                                                                                          |
| `recipient_max_count`          | `int \| None`       | `1000`  | Most recipients one `send()` call accepts, counted after duplicates are dropped; more is refused with `InvalidInputError` before any delivery. `None` sets no limit; when set, positive.                                                                                                                                                                |
| `smtp_username`                | `str \| None`       | `None`  | Username used for SMTP authentication. Must be paired with `smtp_password`.                                                                                                                                                                                                                                                                             |
| `smtp_password`                | `SecretStr \| None` | `None`  | Password paired with `smtp_username`. Ignored when either value is missing. Masked in `repr()` and `model_dump()`; call `.get_secret_value()` for the plaintext. A plain `str` or an `int` is coerced; a validation error of `ConfMail` never carries it.                                                                                               |
| `smtp_use_starttls`            | `bool`              | `True`  | Enables `STARTTLS` negotiation before authentication. Set to `False` for servers that do not support STARTTLS.                                                                                                                                                                                                                                          |
| `smtp_starttls_verify`         | `bool`              | `True`  | Verifies the server certificate and hostname during `STARTTLS`. Set to `False` for internal self-signed relays (encrypted, unverified).                                                                                                                                                                                                                 |
| `smtp_timeout`                 | `float`             | `30.0`  | Socket timeout in seconds applied to SMTP connections. Must be positive and finite (NaN and infinity are refused).                                                                                                                                                                                                                                      |
| `smtp_local_hostname`          | `str \| None`       | `None`  | Name announced in `EHLO`. When `None`, this host's name is looked up once per process and reused (an address literal such as `[192.0.2.7]` when it has no dot). Set it where reverse DNS is slow. Must be non-empty printable ASCII without spaces.                                                                                                     |
| `smtp_delivery_deadline`       | `float \| None`     | `None`  | Upper bound in seconds for one SMTP session (one recipient via one host), from the open connection to the final reply. `smtp_timeout` bounds each socket operation, so a server answering one byte at a time never trips it; this bounds the whole session, after which the host counts as failed. `None` sets no bound; when set, positive and finite. |

**Attachment Security Settings:**

| Field                                    | Type                      | Default                   | Description                                                                                                                                                                                                                         |
|------------------------------------------|---------------------------|---------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `attachment_allowed_extensions`          | `frozenset[str] \| None`  | `None`                    | When set, only these extensions are allowed (whitelist mode). `None` uses blacklist mode.                                                                                                                                           |
| `attachment_blocked_extensions`          | `frozenset[str]`          | POSIX and Windows dangers | Extensions to reject. Ignored when `attachment_allowed_extensions` is set. Defaults to the dangerous extensions of BOTH families on every platform, because the recipient's system decides what runs.                               |
| `attachment_allowed_directories`         | `frozenset[Path] \| None` | `None`                    | When set, attachments must reside under one of these directories (whitelist mode).                                                                                                                                                  |
| `attachment_blocked_directories`         | `frozenset[Path]`         | OS-specific sensitive     | Directories from which attachments cannot be read. Ignored when `attachment_allowed_directories` is set. Defaults to the running platform's sensitive system directories.                                                           |
| `attachment_max_size_bytes`              | `int \| None`             | `26_214_400` (25 MiB)     | Maximum attachment size in bytes. `None` disables size checking.                                                                                                                                                                    |
| `attachment_max_count`                   | `int \| None`             | `100`                     | Most attachments one `send()` call accepts; more is refused with `InvalidInputError` before any file is opened. `None` sets no limit; when set, positive.                                                                           |
| `attachment_allow_symlinks`              | `bool`                    | `False`                   | When `False`, an attachment path whose last component is a symlink is rejected; when `True`, it is resolved and validated. A symlinked directory along the path is followed either way, and every rule runs on the resolved target. |
| `attachment_raise_on_security_violation` | `bool`                    | `True`                    | When `True`, security violations raise `AttachmentSecurityError`; when `False`, they log a warning and skip the attachment.                                                                                                         |
| `attachment_allow_empty_blocklists`      | `bool`                    | `False`                   | When `False`, an empty blocked extension or directory set whose allowlist is not set is refused, because it blocks nothing. `True` blocks nothing on purpose.                                                                       |

Common helpers:

- `ConfMail.model_validate(data: dict[str, Any]) -> ConfMail`  -  validate crude
  configuration (dicts, strings, iterables) into a typed instance.
- A refused setting raises `ConfigurationError`, a pydantic `ValidationError` (so also a
  `ValueError`) that is also a `BtxMailError`, from construction, every `model_validate*`
  method and assignment.
- A key that is not a `ConfMail` field is refused (`extra="forbid"`): construction and
  `model_validate` raise `ConfigurationError` with an `extra_forbidden` error naming the key,
  never its value. The `send()` keyword names are not field names, so
  `ConfMail(use_starttls=False, timeout=5)` is refused; the fields are `smtp_use_starttls`
  and `smtp_timeout`. A subclass inherits the refusal; one that must accept extra keys sets
  `model_config = ConfigDict(extra="ignore")` itself.
- Assignment to a field (`conf.smtp_timeout = 10.0`) is validated like construction
  (`validate_assignment=True`); there is no bulk-update method, so update the global
  `conf` field by field, or pass your own instance with `send(config=...)`.
- `ConfMail.resolved_credentials() -> tuple[str, str] | None`  -  return the
  `(username, password)` pair when both credential fields are populated.

## Functions

#### `emit_greeting(*, stream: TextIO | None = None) -> None`

Writes the canonical `"Hello World\n"` line to `stream` (defaults to
`sys.stdout`) and flushes the stream when it exposes a `flush()` method.
Useful for smoke tests and quick health probes.

#### `raise_intentional_failure() -> None`

Raises `RuntimeError("I should fail")` unconditionally. The CLI and tests use
this helper to validate traceback handling and exit-code mapping without
crafting bespoke exceptions.

#### `noop_main() -> None`

Returns `None` immediately. The CLI uses this placeholder when the user opts in
to running the domain stub (for example via `--traceback` without a
subcommand), ensuring the scaffold remains predictable.

#### `send(...) -> bool`

Entry point for SMTP delivery. Returns `True` when all recipients succeed and
raises when every host fails for at least one recipient. The first seven parameters may be
passed positionally; every other one is keyword-only.

**Core Parameters:**

| Parameter                      | Type                             | Default | Notes                                                                                                                                                                                               |
|--------------------------------|----------------------------------|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `mail_from`                    | `str`                            | -       | Envelope sender address (`local@domain`).                                                                                                                                                           |
| `mail_recipients`              | `str \| Sequence[str]`           | -       | One address or a sequence. Each is stripped of surrounding whitespace and quotes, lower-cased, deduplicated and validated.                                                                          |
| `mail_subject`                 | `str`                            | -       | UTF-8 subject line. A line break, a control character other than TAB, or invalid Unicode is refused with `InvalidInputError` before any delivery.                                                   |
| `mail_body`                    | `str`                            | `""`    | Optional plain-text body.                                                                                                                                                                           |
| `mail_body_html`               | `str`                            | `""`    | Optional HTML body (UTF-8).                                                                                                                                                                         |
| `smtphosts`                    | `Sequence[str] \| None`          | `None`  | Host override. Falls back to `smtphosts` of the config in use (the passed `config`, else the global `conf`).                                                                                        |
| `attachment_file_paths`        | `Sequence[pathlib.Path] \| None` | `None`  | Iterable of attachment paths. Missing files raise unless `raise_on_missing_attachments` is `False` on the config in use.                                                                            |
| `credentials`                  | `tuple[str, str] \| None`        | `None`  | Keyword-only, like every parameter below. `(username, password)` override. Defaults to `resolved_credentials()` of the config in use.                                                               |
| `use_starttls`                 | `bool \| None`                   | `None`  | When `None`, the helper uses `smtp_use_starttls` of the config in use.                                                                                                                              |
| `starttls_verify`              | `bool \| None`                   | `None`  | When `None`, the helper uses `smtp_starttls_verify` of the config in use. `False` skips certificate verification.                                                                                   |
| `timeout`                      | `float \| None`                  | `None`  | When `None`, the helper uses `smtp_timeout` of the config in use.                                                                                                                                   |
| `local_hostname`               | `str \| None`                    | `None`  | Name announced in `EHLO`. When `None`, the helper uses `smtp_local_hostname` of the config in use, else this host's name (looked up once per process). An unusable name raises `InvalidInputError`. |
| `delivery_deadline`            | `float \| None`                  | `None`  | Upper bound in seconds for one SMTP session. When `None`, the helper uses `smtp_delivery_deadline` of the config in use. A non-positive or non-finite value raises `InvalidInputError`.             |
| `raise_on_missing_attachments` | `bool \| None`                   | `None`  | `True` raises `AttachmentNotFoundError` for a missing attachment, `False` logs a warning and sends without it. `None` uses `raise_on_missing_attachments` of the config in use.                     |
| `raise_on_invalid_recipient`   | `bool \| None`                   | `None`  | `True` raises `InvalidInputError` for an invalid recipient, `False` logs a warning and skips it. `None` uses `raise_on_invalid_recipient` of the config in use.                                     |
| `config`                       | `ConfMail \| None`               | `None`  | Settings used in place of the global `conf` for every value not passed explicitly. When `config` is passed, `conf` is not read at all.                                                              |
| `transport`                    | `Transport \| None`              | `None`  | Delivery adapter; `None` uses `SmtplibTransport` (importable from `btx_lib_mail.lib_mail`). Inject a test double or an alternative transport here (see [Transport](#transport)).                    |

**Attachment Security Parameters (keyword-only):**

| Parameter                                | Type                      | Default | Notes                                                                                                                                                                                          |
|------------------------------------------|---------------------------|---------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `attachment_allowed_extensions`          | `frozenset[str] \| None`  | `None`  | Override allowed extensions (whitelist mode). `None` uses the config in use's value (no allowlist by default). Normalised like the config field: `{"PDF"}` and `{".pdf"}` are the same set.    |
| `attachment_blocked_extensions`          | `frozenset[str] \| None`  | `None`  | Override blocked extensions. `None` uses the config in use's value (the POSIX and Windows dangerous extensions by default). Normalised like the config field (lower case, leading dot).        |
| `attachment_allowed_directories`         | `frozenset[Path] \| None` | `None`  | Override allowed directories (whitelist mode). `None` uses the config in use's value (no allowlist by default).                                                                                |
| `attachment_blocked_directories`         | `frozenset[Path] \| None` | `None`  | Override blocked directories. `None` uses the config in use's value (the running platform's sensitive directories by default). Ignored when an allowlist is in force.                          |
| `attachment_max_size_bytes`              | `int \| None`             | `None`  | Override max attachment size. `None` uses the config in use's value (25 MiB by default), so `None` here never disables the check; set `attachment_max_size_bytes=None` on the config for that. |
| `attachment_allow_symlinks`              | `bool \| None`            | `None`  | Override symlink policy. `None` uses the config in use's value (`False` by default).                                                                                                           |
| `attachment_raise_on_security_violation` | `bool \| None`            | `None`  | Override security violation behaviour. `None` uses the config in use's value (`True` by default).                                                                                              |

An empty `attachment_blocked_extensions` or `attachment_blocked_directories` set means
"block nothing"; it is not a way to ask for the OS defaults. `ConfMail` therefore refuses
such an empty set, at construction and on assignment, unless the matching allowlist
(`attachment_allowed_extensions` / `attachment_allowed_directories`) is set or
`attachment_allow_empty_blocklists=True` opts into blocking nothing. A configuration loader
whose files write `[]` to mean "use the defaults" must drop that key before building
`ConfMail`; to get the OS defaults, leave the field at its factory default. An explicit
`send(attachment_blocked_extensions=frozenset())` (or `_directories`) blocks nothing for
that one call and is not checked, while passing `None` uses the value on the config in use
(the passed `config`, else the global `conf`).

#### Default Blocked Extensions

Both lists below, on every platform. The extension is read after trailing dots and
spaces are dropped (Windows saves `x.exe.` as `x.exe`) and compared without case.

**`DANGEROUS_EXTENSIONS_POSIX`:**
```
.sh, .bash, .zsh, .ksh, .csh, .py, .pyw, .pyc, .pyo, .pl, .pm, .rb, .php,
.js, .mjs, .cjs, .so, .dylib, .bin, .run, .appimage, .elf, .out,
.jar, .war, .ear, .deb, .rpm, .apk
```

**`DANGEROUS_EXTENSIONS_WINDOWS`:**
```
.exe, .com, .bat, .cmd, .msi, .msp, .msc, .ps1, .ps2, .psc1, .psc2,
.vbs, .vbe, .js, .jse, .ws, .wsf, .wsc, .wsh, .scr, .pif, .hta,
.cpl, .inf, .reg, .dll, .ocx, .sys, .drv, .lnk, .scf, .url,
.gadget, .application, .jar, .war, .ear
```

#### Default Blocked Directories

**POSIX (Linux/macOS):**
```
/etc, /var, /root, /boot, /sys, /proc, /dev, /usr/bin, /usr/sbin, /bin, /sbin
```

**Windows:**
```
C:\Windows, C:\Windows\System32, C:\Program Files, C:\Program Files (x86), C:\ProgramData
```

#### Sensitive Path Patterns (always blocked, all platforms)

Matched as substrings of the resolved path (forward slashes); ignoring case on macOS and
Windows, whose file systems do, and exactly on Linux:

```
/.ssh/, /id_rsa, /id_ed25519, /id_ecdsa, /authorized_keys, /known_hosts,
/.gnupg/, /private.key, /secret, /.env, /credentials, /password, /token,
/.aws/credentials, /.kube/config, /.netrc, /.pgpass, /.git-credentials,
/.docker/config.json, /.pypirc, /.npmrc, /gh/hosts.yml
```

**Raises:** every exception below is a `BtxMailError` (see [Exceptions](#exceptions)).

- `InvalidInputError` (a `ValueError`)  -  a refused sender, recipient, host, subject (a line
  break, a control character other than TAB, or invalid Unicode), body (invalid Unicode), EHLO name, timeout or delivery deadline, or no valid
  recipient left after validation.
- `AttachmentNotFoundError` (a `FileNotFoundError`)  -  when a required attachment is missing
  or is not a regular file (a directory, a FIFO) and `raise_on_missing_attachments` is `True`.
- `AttachmentSecurityError`  -  when an attachment violates security policies and
  `attachment_raise_on_security_violation` is `True`, including a file that changed or
  grew past the size limit after it was checked (see
  [attachment security](attachment-security.md)).
- `DeliveryError` (a `RuntimeError`)  -  when every configured host fails for a recipient; its
  message lists recipients and host roster, and `failed_recipients` / `hosts` carry them as
  tuples.

An `OSError` the operating system raises while opening an attachment that exists (for
example `PermissionError` on an unreadable file) is not a `BtxMailError`; it propagates
unchanged, before any delivery.

**Per-host failure log:** when a host raises during delivery, `send` logs one
credential-free `WARNING` for that host and moves on to the next one; no traceback is
attached. The message is `can not send mail to "<recipient>" via host "<host>": <description>`,
where `<description>` is built by `_describe_failure`: for an `smtplib.SMTPResponseException`
(a server reply) it is `<ExceptionClassName> <smtp_code> <reply text>`; for any other `OSError`
(including a custom `Transport`'s own `OSError`) it is `<ExceptionClassName>: <error text>`,
logged as given; for anything else it is only the exception class name. The description text
has its control characters (CR, LF, ESC, NUL, ...) replaced by spaces and is capped at 200
characters; `<host>` and `<recipient>` are run through the same control-character cleaning
(`printable`), but are not capped at 200 characters, since a description text is the one value
this log line takes from an untrusted server reply. A host carrying interior whitespace or a
control character is refused before any delivery is attempted (`ConfMail` construction/assignment
and `send()`-time host validation both refuse it, without echoing the value), so this cleaning of
`<host>` is defense in depth rather than the only guard; a hostile or chatty server reply, on the
other hand, reaches this log line as `<description>` and relies on the cleaning above to not forge
extra log lines or flood the log.
The log record also carries `extra={"sender": ..., "recipient": ..., "host": ..., "error_type":
..., "smtp_code": ...}` (`smtp_code` is `None` when the exception has none; `sender`, `recipient`
and `host` are the same cleaned values used in the message), so a structured log sink can filter
or aggregate by any of them without re-parsing the message text. The same cleaning (`printable`
on every caller- or filesystem-supplied value, in the message and in `extra` alike) also applies
to the success-path `DEBUG` log line (`mail sent to "<recipient>" via host "<host>"`), the
`WARNING` logged for a recipient that fails validation in tolerant mode (and the `ValueError` it
raises in strict mode) together with the two attachment-path `WARNING`s (a security violation, a
missing file), and `AttachmentSecurityError`'s own `str()`/`repr()` when it propagates to the
caller in strict mode - none of these log a caller- or filesystem-supplied string unclean.

## Exceptions

Every exception the library raises on purpose derives from `BtxMailError`, so
`except BtxMailError:` catches any refusal or delivery failure. Each concrete class also
subclasses the builtin in the "Also a" column, so `except ValueError:` (and so on) catches
it too, and the CLI exit code follows that builtin.

| Class                     | Also a                     | Raised when                                                                              |
|---------------------------|----------------------------|------------------------------------------------------------------------------------------|
| `BtxMailError`            | `Exception`                | Base class; never raised itself.                                                         |
| `InvalidInputError`       | `ValueError`               | An argument value is refused (`send()`, `validate_email_address`, `validate_smtp_host`). |
| `ConfigurationError`      | pydantic `ValidationError` | A `ConfMail` setting is refused (construction, `model_validate*`, assignment).           |
| `AttachmentNotFoundError` | `FileNotFoundError`        | A required attachment is missing or not a regular file.                                  |
| `AttachmentSecurityError` | -                          | An attachment breaks a security rule; see `violation_type`.                              |
| `DeliveryError`           | `RuntimeError`             | Every host failed for at least one recipient; see `failed_recipients`, `hosts`.          |

`AttachmentSecurityError` carries `path` (the offending path), `reason` (a one-line
description, control characters replaced) and `violation_type`, an `AttachmentViolation`
member: `PATH_TRAVERSAL`, `SYMLINK`, `SENSITIVE_PATTERN`, `DIRECTORY`, `EXTENSION`, `SIZE`,
`CHANGED` or `FILENAME`. The members are strings (`violation_type == "symlink"` holds). Branch on the
member, never on the message text.

## Validators

- `validate_email_address(address: str) -> None` raises `InvalidInputError` unless the
  address matches `EMAIL_PATTERN` (`local@domain.tld`) and keeps to RFC 5321's lengths: at most
  64 characters before the `@` and 254 in all. A refusal for length names the length, not the
  address.
- `validate_smtp_host(host: str) -> None` raises `InvalidInputError` unless `host` is one of
  `hostname`, `hostname:port`, `[IPv6]`, `[IPv6]:port`, with a port of ASCII digits in
  1-65535. A host carrying `@` or `/` or an interior whitespace or control character is
  refused without the value appearing in the message; a comma (two hosts in one string)
  and an unbracketed IPv6 address are refused too.

## Transport

`send()` hands each recipient's message to a `Transport`, an object with one method:

```python
def deliver(self, *, host: str, sender: str, recipient: str, message: IO[bytes], delivery: DeliveryOptions) -> None: ...
```

`message` is a readable, seekable binary stream positioned at its first byte; `send()` rewinds
it before every host attempt. `deliver` returns on success and raises on any failure, so the
next host is tried. An `OSError` it raises is logged with its text, anything else by type name
only; never put a credential into the text of an `OSError`. `DeliveryOptions` is a frozen
dataclass with `credentials` (`tuple[str, str] | None`, left out of `repr`), `use_starttls`,
`starttls_verify`, `timeout`, `local_hostname` and `deadline`. The default transport,
`SmtplibTransport` (importable from `btx_lib_mail.lib_mail`), speaks SMTP; a test passes its
own transport through `send(transport=...)` and asserts on what it received, with no server
and no patching:

```python
from typing import IO

from btx_lib_mail import DeliveryOptions, send


class RecordingTransport:
    def __init__(self) -> None:
        self.sent: list[tuple[str, bytes]] = []

    def deliver(self, *, host: str, sender: str, recipient: str, message: IO[bytes], delivery: DeliveryOptions) -> None:
        self.sent.append((recipient, message.read()))


transport = RecordingTransport()
send("alerts@example.com", "oncall@example.com", "build failed", "See CI.", smtphosts=["smtp.example.com"], transport=transport)
assert transport.sent[0][0] == "oncall@example.com"
```

## Logging and metadata

- `logger` is the library's `logging.Logger` (`"btx_lib_mail"`). It logs one `WARNING` per
  failed host, per skipped attachment and per skipped recipient, and a `DEBUG` line per
  delivery; no record carries a password.
- `print_info()` prints the package metadata (name, version, homepage, author), as the CLI's
  `info` command does. `CANONICAL_GREETING` is the `"Hello World"` text `emit_greeting()`
  writes.

## Secret safety

`btx_lib_mail.secret_safety` provides the building blocks `ConfMail` uses to keep a
credential out of a `pydantic.ValidationError`:

- **`SecretSafeModel`**  -  base class for a pydantic model that holds a credential.
  A subclass lists its credential field names in the class variable
  `credential_fields: ClassVar[frozenset[str]]`; every alias of those fields (via
  `Field(alias=...)` or `validation_alias=...`) is covered automatically, with no need
  to list the alias separately. `credential_fields` is checked when the subclass is
  defined: a name that is not a declared field (a typo, or an alias listed instead of
  its field), a value that is not a set of str (a plain `"password"` would be read as
  its letters), or an annotated `credential_fields` that pydantic turns into a field
  raises `TypeError` at class definition. A validated assignment that a model-level
  validator refuses is rolled back, so the instance keeps its previous values.
  `ConfMail` is one such subclass
  (`credential_fields = frozenset({"smtp_password", "smtphosts"})`; `smtphosts` is
  included because a host string carrying `user:password@` is refused there, and that
  refusal must not echo the value).
  The class variable `validation_error_class: ClassVar[type[ValidationError]]`
  (`ValidationError` by default) names the class of every error the model raises; set it
  to a `ValidationError` subclass to give the errors a base of your own. `ConfMail` sets
  `ConfigurationError`.
- **`redact_validation_error(exc, *, credential_fields, declared_names=frozenset(), error_class=ValidationError)`**  -
  the function `SecretSafeModel` wraps its schema with; call it directly to redact a
  `ValidationError` from a plain (non-`SecretSafeModel`) pydantic model; `error_class`
  names the class of the returned error (a `ValidationError` subclass). Raise the
  returned error OUTSIDE the `except` block that caught the original, never inside it:
  raising inside keeps the unredacted original as `__context__` (`from None` only hides
  it from the printed traceback; the attribute still holds it). The safe shape:
  ```python
  error: ValidationError | None = None
  try:
      Model(**data)
  except ValidationError as caught:
      error = caught
  if error is not None:
      raise redact_validation_error(error, credential_fields=frozenset({"password"}))
  ```
- **`REDACTED_INPUT`**  -  the string (`"[redacted]"`) a hidden error's `input` is
  replaced by.

**What is covered:** every place pydantic can raise a `ValidationError` on a
`SecretSafeModel` subclass or an instance of one: `__init__`, every `model_validate*`
method (`model_validate`, `model_validate_strings`, and this model's own
`model_validate_json`, including malformed JSON handed to it directly), validated
assignment (`model_config = ConfigDict(validate_assignment=True)`) and assignment to a
frozen model, `TypeAdapter(Model).validate_python`, and validation of this model nested
inside a list, a dict, or another model's field.

**What is NOT covered**, because the error is raised before any hook of the model runs:
malformed JSON handed to `TypeAdapter(Model).validate_json`, and malformed JSON handed
to `model_validate_json` of a plain `BaseModel` that merely *nests* a `SecretSafeModel`
field. In both cases the JSON parser fails first and its `json_invalid` error quotes the
whole JSON text as its input, before pydantic ever reaches the nested model's schema.

**Outer models with their own model-level validator:** a model that nests a
`SecretSafeModel` field and also defines its own `@model_validator` must itself inherit
`SecretSafeModel` and list the nested field name in its own `credential_fields`, because
a model-level validator error on the OUTER model quotes the outer model's own input (the
whole mapping being validated), not the inner model's.

**The redaction rule** (see `redact_validation_error`'s docstring in
`src/btx_lib_mail/secret_safety.py` for the full statement): an error's `input` is kept
only when it is a plain scalar: `str`, `bytes`, `int`, `float`, `bool`, `None`,
`Decimal`, a `date`/`datetime`/`time`/`timedelta`, or an `Enum` member whose value is one
of these. Every other input is replaced by `REDACTED_INPUT`. An error is always hidden
when it is model-level, an `extra_forbidden` error, or located at a name in
`credential_fields` (or one of its aliases). A hidden error keeps no `ctx`, and its
message is scrubbed on a best-effort basis: the walk covers the input verbatim and in its
`repr()`, `ascii()` and JSON-escaped forms; a mapping key equal to a declared field name
(passed as `declared_names`) is not treated as a secret and is left in the message, but a
VALUE equal to such a name is still scrubbed; a value a developer transforms before
writing it into a message (`.strip()`, a slice, a hash) is not recognised and is not
covered. The rebuild never raises: when one error cannot be rebuilt faithfully, that
error keeps only its type and location (message and input replaced by `REDACTED_INPUT`);
only when the whole rebuild fails is the entire `ValidationError` replaced by one opaque
`redacted_error` (fails closed).

