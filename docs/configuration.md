# Configuration

The `btx_lib_mail.lib_mail` module provides a lightweight SMTP helper whose
behaviour is driven by the `ConfMail` Pydantic model. Configuration can be set
globally via `btx_lib_mail.conf` or supplied per call.

```python
from btx_lib_mail import conf, send

conf.smtphosts = ["smtp.example.com:587", "smtp.backup.example.com"]
conf.smtp_use_starttls = True
conf.smtp_username = "mailer"
conf.smtp_password = "DUMMY-PLANTED-password"

send(
    mail_from="alerts@example.com",
    mail_recipients=["oncall@example.com"],
    mail_subject="build failed",
    mail_body="See CI logs for details",
)
```

Per-call overrides are keyword arguments (only the message and `smtphosts` /
`attachment_file_paths` may be passed positionally). For each setting `send()` uses, in
order: the keyword, if not `None`; else the field of the `config=` it was given; else the
field of the global `conf`. When `config=` is passed, `conf` is not read at all, so an
application can keep its own `ConfMail` (per tenant, per test) without touching the
global. The environment and env files play no part here; they are the CLI's sources (see
below).

```python
from btx_lib_mail import send

send(
    mail_from="sender@example.com",
    mail_recipients=("primary@example.com", "secondary@example.com"),
    mail_subject="Status update",
    mail_body="All systems operational.",
    smtphosts=("smtp-main.example.com:587", "smtp-dr.example.com:587"),
    credentials=("smtp-user", "DUMMY-PLANTED-password"),
    use_starttls=True,
    timeout=15,
)
```

When configuration is sourced from files or secrets managers, validate and apply
it through the Pydantic model to keep type safety intact:

```python
from btx_lib_mail import ConfMail, conf

settings = {
    "smtphosts": ["smtp.example.com:587"],
    "smtp_username": "svc-user",
    "smtp_password": "DUMMY-PLANTED-password",
    "smtp_use_starttls": True,
    "smtp_timeout": 20.0,
}
conf_update = ConfMail.model_validate(settings)  # validates the whole mapping at once
for field_name in conf_update.model_fields_set:  # copy only the keys the mapping set
    setattr(conf, field_name, getattr(conf_update, field_name))
```

Key behaviours:

- A key that is not a `ConfMail` field is refused with a `ConfigurationError` (a pydantic
  `ValidationError`, and a `BtxMailError`) naming the key (never its value). Map your source's names onto the field names before
  validating, and leave out keys that belong to something else: the `send()`
  keyword names (`use_starttls`, `timeout`, `credentials`) are not field names,
  so passing them to `ConfMail` fails instead of being dropped.
- `smtphosts` may be a string (single host), list, or tuple; items can include
  an explicit `host:port` override. Each entry is checked with
  `validate_smtp_host` when the model is built or assigned, so a port outside
  1-65535 or not plain ASCII digits (`+25`, `2_5`), an unclosed IPv6 bracket, an IPv6 address without
  brackets (`fe80::1`), a port with no host name (`:25`) or two hosts in one
  entry (`a.example.com,b.example.com`) raises a `ConfigurationError` at load time
  instead of failing the first delivery. A blank entry (an empty environment
  value, a trailing comma) is dropped, and surrounding whitespace and quotes are
  stripped; the model keeps duplicates. `send()` drops exact duplicates and tries the
  hosts in order.
- STARTTLS is enabled by default (`smtp_use_starttls=True`). The helper performs
  the handshake with the system SSL context before authenticating; set the flag
  to `False` when connecting to servers that do not support STARTTLS.
- Certificate verification is on by default (`smtp_starttls_verify=True`). For an
  internal relay whose certificate is self-signed or has a hostname mismatch, set
  `smtp_starttls_verify=False` (or pass `starttls_verify=False` / use
  `--no-starttls-verify`): the traffic stays encrypted but the certificate is not
  validated. This trades away MITM protection, so prefer adding the relay's CA to
  the trust store where you can.
- Credentials are optional. If both `smtp_username` and `smtp_password` are
  provided, `send` will call `SMTP.login`. The helper also accepts
  one-off credentials via the `credentials=` argument.
- Messages are always rendered as UTF-8; attachments retain their binary
  payload via base64 encoding. Failed hosts are logged at WARNING level and the
  helper proceeds to the next configured server before raising.
- A missing or unreadable attachment file raises `AttachmentNotFoundError` (a `FileNotFoundError`) and an
  invalid recipient address raises `InvalidInputError` (a `ValueError`) by default (`raise_on_missing_attachments=True`,
  `raise_on_invalid_recipient=True`). Set either to `False` on the config, or pass it to
  `send()`, to log a warning and skip the file or address instead. Neither has a CLI flag
  or environment variable.
- The socket timeout defaults to `conf.smtp_timeout` (30 seconds). Override the
  value via the `timeout=` argument, the `--timeout` CLI flag, or the
  `BTX_MAIL_SMTP_TIMEOUT` environment variable / `--env-file` entry. It bounds each socket
  operation; `smtp_delivery_deadline` (`delivery_deadline=`, `--delivery-deadline`,
  `BTX_MAIL_SMTP_DELIVERY_DEADLINE`) bounds a whole SMTP session, which a server answering
  one byte at a time never lets the socket timeout end. It is unset by default.
- The client announces itself in `EHLO` with `smtp_local_hostname` when set
  (or `local_hostname=`, `--local-hostname`, `BTX_MAIL_SMTP_LOCAL_HOSTNAME`).
  Unset, it uses this host's fully qualified name, looked up by reverse DNS
  once per process and reused for every connection; set a name where that
  lookup is slow or returns something a relay rejects.

## Credentials

- **Non-ASCII passwords need AUTH PLAIN.** An ASCII username and password use
  `smtplib.SMTP.login`, which tries CRAM-MD5, PLAIN and LOGIN in turn, among the
  mechanisms the server advertises. A username or password with a non-ASCII character
  (an umlaut, a non-Latin script) instead goes through RFC 4616 AUTH PLAIN with the
  credentials encoded as UTF-8, because stdlib `smtplib`'s own login path encodes every
  AUTH exchange as ASCII and raises `UnicodeEncodeError` on anything else. A server that
  offers only LOGIN (and XOAUTH2), never PLAIN, refuses a non-ASCII credential with
  `smtplib.SMTPNotSupportedError` instead of a mid-handshake encoding crash. Microsoft
  365 and Exchange are reported to advertise no PLAIN mechanism (not verified in this
  repo); test against your own server before relying on a non-ASCII credential.
  `send()` never raises `smtplib.SMTPNotSupportedError` itself: it is caught per host
  (like every delivery failure), named in that host's `WARNING` log line
  (`extra["error_type"] == "SMTPNotSupportedError"`), and `send()` raises `DeliveryError`
  (a `RuntimeError`) once every configured host has failed. Do not write
  `except smtplib.SMTPNotSupportedError` around `send()`; catch `DeliveryError`, or inspect
  `error_type` in the log record.
- **All-digit passwords from environment layers.** A layered config loader (env vars,
  some dotenv readers) can parse an all-digit value as a number before it reaches
  `ConfMail`; `smtp_password` accepts an `int` and coerces it to its decimal text, so the
  password still works. But if the original password had a leading zero (`0123`), the
  loader has already lost it when it parsed the digits as a number, and `ConfMail` cannot
  restore what it never saw. Quote the value in a TOML config file (`smtp_password =
  "0123"`) so the loader keeps it as text in the first place.
- **Host strings never carry credentials, whitespace, or control characters.** A host
  string in `smtphosts` must be `host[:port]`; it must not carry `user:password@` or a
  path, and it must not carry an interior whitespace or control character (a newline or
  an escape sequence could forge a log line or a terminal control sequence wherever a
  failed host is later logged). `ConfMail` refuses such a host at load time
  (`ConfigurationError`, without echoing the value); pass credentials as `smtp_username` and `smtp_password` (or
  `credentials=` on `send`) instead of folding them into the host. Outer whitespace and
  quotes are trimmed first, so an ordinary `" smtp.example.com "` from an env file still validates.
- **Failover repeats the same credential.** For an ASCII password the server rejects,
  `smtplib` still tries CRAM-MD5, PLAIN and LOGIN in turn before giving up, and
  `smtphosts` failover then sends that same credential to every remaining host. A wrong
  password can therefore count several failed logins per `send()` call against an
  account-lockout policy.
- **Never put a secret into a custom validator's error message.** `ConfMail`'s own
  validation errors never carry the password (see the "Secret safety" section of
  `docs/api.md`), but that redaction scrubs a hidden error's MESSAGE only on a
  best-effort basis: it recognises the input's verbatim text and its `repr()`, `ascii()`
  and JSON-escaped forms, never a value a validator has transformed first (stripped,
  sliced, hashed). Do not write a custom validator that formats a credential into its
  own `raise ValueError(...)` message.
- **Tracebacks with local variables still show the raw input.** Rendering a traceback
  with local variables attached (`traceback.format_exception(..., capture_locals=True)`,
  or an error-reporting integration such as Sentry that captures frame variables) shows
  the unredacted input through pydantic's own validation frames, because the redaction
  rebuilds the `ValidationError` object and cannot reach into a traceback frame that
  already ran. Do not enable frame-variable capture in a process that validates
  credentials.
- **`TypeAdapter(Model).validate_json` on malformed JSON is not covered**, and neither is
  `model_validate_json` of a plain `BaseModel` that merely nests a `SecretSafeModel`
  field: the JSON parser fails before either model's schema runs, and its
  `json_invalid` error quotes the whole JSON text as its input. Call the
  `SecretSafeModel` subclass's own `model_validate_json` directly (`ConfMail.model_validate_json(text)`)
  to get the redaction; it is covered from `__init__` and every `model_validate*` method
  onward.
- **`ConfMail.model_construct(...)` and `existing.model_copy(update=...)` both skip
  validation.** `model_construct` builds an instance directly from the fields you give
  it, and `model_copy(update=...)` applies the update without re-validating the model;
  neither refuses a host carrying `user:password@` or rejects a malformed password.
  Use either only for data you already trust.

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

## Environment variables and precedence

The `send` command resolves each setting in this order:
1. **CLI options** passed to `btx_lib_mail send`.
2. **Environment variables** exported in the shell (`BTX_MAIL_*` keys below).
3. Entries in the `KEY=value` env file: the one named by `--env-file` (or
   `BTX_MAIL_ENV_FILE`), otherwise `.env` in the working directory when it is a file.
4. Defaults baked into `btx_lib_mail.conf`.

Environment variables understood by the CLI:

**SMTP Settings:**

| Variable                          | Purpose                                                                                                        | Example                                   |
|-----------------------------------|----------------------------------------------------------------------------------------------------------------|-------------------------------------------|
| `BTX_MAIL_SMTP_HOSTS`             | Comma-separated list of SMTP hosts (each `host[:port]`).                                                       | `smtp1.example.com:587,smtp2.example.com` |
| `BTX_MAIL_RECIPIENTS`             | Comma-separated list of recipient emails.                                                                      | `primary@example.com,backup@example.com`  |
| `BTX_MAIL_SENDER`                 | Envelope sender; defaults to the first recipient when unset.                                                   | `alerts@example.com`                      |
| `BTX_MAIL_RECIPIENT_MAX_COUNT`    | Most recipients one run accepts (defaults to `1000`).                                                          | `5000`                                    |
| `BTX_MAIL_SMTP_USE_STARTTLS`      | Boolean (`1`/`true`/`yes`/`on` or `0`/`false`/`no`/`off`) enabling STARTTLS; blank keeps the default (`true`). | `true`                                    |
| `BTX_MAIL_SMTP_STARTTLS_VERIFY`   | Boolean flag verifying the server certificate during STARTTLS; blank keeps the default (`true`).               | `false`                                   |
| `BTX_MAIL_SMTP_USERNAME`          | Username used when STARTTLS/authentication is required.                                                        | `smtp-user`                               |
| `BTX_MAIL_SMTP_PASSWORD`          | Password paired with the SMTP username.                                                                        | `DUMMY-PLANTED-password`                  |
| `BTX_MAIL_SMTP_TIMEOUT`           | Socket timeout in seconds (defaults to `30`).                                                                  | `12.5`                                    |
| `BTX_MAIL_SMTP_LOCAL_HOSTNAME`    | Name announced in EHLO (defaults to this host's name, looked up once).                                         | `relay-client.example.com`                |
| `BTX_MAIL_SMTP_DELIVERY_DEADLINE` | Upper bound in seconds for one SMTP session (default: none).                                                   | `300`                                     |
| `BTX_MAIL_ENV_FILE`               | Path of a `KEY=value` file to read the other settings from (same as `--env-file`).                             | `/etc/btx-mail/relay.env`                 |

**Attachment Security Settings:**

| Variable                                | Purpose                                                   | Example                |
|-----------------------------------------|-----------------------------------------------------------|------------------------|
| `BTX_MAIL_ATTACHMENT_ALLOWED_EXT`       | Comma-separated allowed extensions (whitelist mode).      | `.pdf,.txt,.docx`      |
| `BTX_MAIL_ATTACHMENT_BLOCKED_EXT`       | Comma-separated blocked extensions (overrides defaults).  | `.exe,.bat,.sh`        |
| `BTX_MAIL_ATTACHMENT_ALLOWED_DIRS`      | Comma-separated allowed directories (whitelist mode).     | `/home/user/docs,/tmp` |
| `BTX_MAIL_ATTACHMENT_BLOCKED_DIRS`      | Comma-separated blocked directories (overrides defaults). | `/etc,/root`           |
| `BTX_MAIL_ATTACHMENT_MAX_SIZE`          | Max attachment size in bytes.                             | `26214400`             |
| `BTX_MAIL_ATTACHMENT_MAX_COUNT`         | Most attachments one run accepts (defaults to `100`).     | `10`                   |
| `BTX_MAIL_ATTACHMENT_ALLOW_SYMLINKS`    | Boolean flag allowing symlinks.                           | `false`                |
| `BTX_MAIL_ATTACHMENT_RAISE_ON_SECURITY` | Boolean flag to raise on violations (vs. warn and skip).  | `true`                 |

The env file is optional: `send` reads `.env` in the working directory when it is a
regular file, and `--env-file PATH` (or `BTX_MAIL_ENV_FILE`) names another file to read
instead. The CLI trims whitespace, honours quoted values, and treats empty strings as
unset; the first occurrence of a key wins, and the file must be UTF-8 and at most 64 KiB.
Exporting an environment variable always overrides the file; explicit CLI flags override
both. A `.env` can set the relay and relax security settings, so run `send` only from a
directory whose `.env` you trust (see
[the CLI reference](cli.md#where-send-settings-come-from)).

> **Note:** Environment and env-file lookups occur only in the CLI adapter. If you
> import `btx_lib_mail.send()` directly, configure `btx_lib_mail.conf` yourself
> (for example via `ConfMail.model_validate`) and pass per-call overrides
> explicitly.

- Integration testing: set `TEST_SMTP_HOSTS` and `TEST_RECIPIENTS` either in
  your shell environment or the project `.env` file (comma-separated values) to
  let `pytest` deliver a real message (UTF-8 plain text, HTML, and an
  attachment) via your staging SMTP infrastructure. Optional variables include
  `TEST_SENDER`, `TEST_SMTP_USE_STARTTLS`, `TEST_SMTP_USERNAME`, and
  `TEST_SMTP_PASSWORD`. Tests skip automatically when these variables are not
  present.
  - `TEST_SMTP_HOSTS`: comma-separated hostnames or `host:port` entries tried
    in order (e.g. `smtp1.example.com:587,smtp2.example.com`).
  - `TEST_RECIPIENTS`: comma-separated email addresses that should receive the
    smoke message.
  - `TEST_SENDER`: optional envelope sender; defaults to the first recipient
    when unset.
  - `TEST_SMTP_USE_STARTTLS`: optional boolean toggle (`1`, `true`, `yes`,
    `on`) enabling STARTTLS before authentication.
  - `TEST_SMTP_USERNAME`/`TEST_SMTP_PASSWORD`: optional credentials used when
    both values are supplied.

