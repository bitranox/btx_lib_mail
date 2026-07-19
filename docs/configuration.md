# Configuration

The `btx_lib_mail.lib_mail` module provides a lightweight SMTP helper whose
behaviour is driven by the `ConfMail` Pydantic model. Configuration can be set
globally via `btx_lib_mail.conf` or supplied per call.

```python
from btx_lib_mail import conf, send

conf.smtphosts = ["smtp.example.com:587", "smtp.backup.example.com"]
conf.smtp_use_starttls = True
conf.smtp_username = "mailer"
conf.smtp_password = "s3cr3t"

send(
    mail_from="alerts@example.com",
    mail_recipients=["oncall@example.com"],
    mail_subject="build failed",
    mail_body="See CI logs for details",
)
```

Per-call overrides can be supplied positionally or via keyword arguments. When a
value is omitted, the helper falls back to the precedence order documented
below.

```python
from btx_lib_mail import send

send(
    mail_from="sender@example.com",
    mail_recipients=("primary@example.com", "secondary@example.com"),
    mail_subject="Status update",
    mail_body="All systems operational.",
    smtphosts=("smtp-main.example.com:587", "smtp-dr.example.com:587"),
    credentials=("smtp-user", "smtp-pass"),
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
    "smtp_password": "svc-pass",
    "smtp_use_starttls": True,
    "smtp_timeout": 20.0,
}
conf_update = ConfMail.model_validate(settings)
conf.model_update(conf_update.model_dump())
```

Key behaviours:

- `smtphosts` may be a string (single host), list, or tuple; items can include
  an explicit `host:port` override. Hosts are normalised, deduplicated, and
  tried in order.
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
- The socket timeout defaults to `conf.smtp_timeout` (30 seconds). Override the
  value via the `timeout=` argument, the `--timeout` CLI flag, or the
  `BTX_MAIL_SMTP_TIMEOUT` environment variable / `.env` entry.

## Environment variables and precedence

### Environment Variables and Precedence {#mail-env-variables}

The CLI and library coordinate configuration using the following precedence:
1. **CLI options** passed to `btx_lib_mail send`.
2. **Environment variables** exported in the shell (`BTX_MAIL_*` keys below).
3. Matching entries in the project `.env` file (used by `_configured_value`).
4. Defaults baked into `btx_lib_mail.conf`.

Environment variables understood by the CLI:

**SMTP Settings:**

| Variable                        | Purpose                                                                         | Example                                   |
|---------------------------------|---------------------------------------------------------------------------------|-------------------------------------------|
| `BTX_MAIL_SMTP_HOSTS`           | Comma-separated list of SMTP hosts (each `host[:port]`).                        | `smtp1.example.com:587,smtp2.example.com` |
| `BTX_MAIL_RECIPIENTS`           | Comma-separated list of recipient emails.                                       | `primary@example.com,backup@example.com`  |
| `BTX_MAIL_SENDER`               | Envelope sender; defaults to the first recipient when unset.                    | `alerts@example.com`                      |
| `BTX_MAIL_SMTP_USE_STARTTLS`    | Boolean flag (`1`, `true`, `yes`, `on`) enabling STARTTLS.                      | `true`                                    |
| `BTX_MAIL_SMTP_STARTTLS_VERIFY` | Boolean flag verifying the server certificate during STARTTLS (default `true`). | `false`                                   |
| `BTX_MAIL_SMTP_USERNAME`        | Username used when STARTTLS/authentication is required.                         | `smtp-user`                               |
| `BTX_MAIL_SMTP_PASSWORD`        | Password paired with the SMTP username.                                         | `s3cr3t`                                  |
| `BTX_MAIL_SMTP_TIMEOUT`         | Socket timeout in seconds (defaults to `30`).                                   | `12.5`                                    |

**Attachment Security Settings:**

| Variable                                | Purpose                                                   | Example                |
|-----------------------------------------|-----------------------------------------------------------|------------------------|
| `BTX_MAIL_ATTACHMENT_ALLOWED_EXT`       | Comma-separated allowed extensions (whitelist mode).      | `.pdf,.txt,.docx`      |
| `BTX_MAIL_ATTACHMENT_BLOCKED_EXT`       | Comma-separated blocked extensions (overrides defaults).  | `.exe,.bat,.sh`        |
| `BTX_MAIL_ATTACHMENT_ALLOWED_DIRS`      | Comma-separated allowed directories (whitelist mode).     | `/home/user/docs,/tmp` |
| `BTX_MAIL_ATTACHMENT_BLOCKED_DIRS`      | Comma-separated blocked directories (overrides defaults). | `/etc,/root`           |
| `BTX_MAIL_ATTACHMENT_MAX_SIZE`          | Max attachment size in bytes.                             | `26214400`             |
| `BTX_MAIL_ATTACHMENT_ALLOW_SYMLINKS`    | Boolean flag allowing symlinks.                           | `false`                |
| `BTX_MAIL_ATTACHMENT_RAISE_ON_SECURITY` | Boolean flag to raise on violations (vs. warn and skip).  | `true`                 |

`.env` files are optional. When present, the CLI trims whitespace, honours
quoted values, and treats empty strings as unset. Exporting an environment
variable always overrides `.env`; explicit CLI flags override both.

> **Note:** Environment and `.env` lookups occur only in the CLI adapter. If you
> import `btx_lib_mail.send()` directly, configure `btx_lib_mail.conf` yourself
> (for example via `ConfMail.model_validate`) and pass per-call overrides
> explicitly.
> Only the `.env` file in the current working directory is considered; parent
> directories are not searched.

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

