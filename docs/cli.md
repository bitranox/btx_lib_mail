# Command-line interface

The CLI leverages [rich-click](https://github.com/ewels/rich-click) so prompts render with Rich styling while keeping the familiar click ergonomics.

```bash
btx_lib_mail info
btx_lib_mail hello
btx_lib_mail fail
btx_lib_mail --traceback fail
btx_lib_mail send --subject "Ping" --body "Smoke test" --recipient ops@example.com --host smtp.example.com
btx-lib-mail info
python -m btx_lib_mail info
```

The `send` subcommand accepts CLI flags or the `BTX_MAIL_*` environment
variables documented below, making it easy to smoke-test SMTP environments
without writing a custom script.

For library use you can import the documented helpers directly:

```python
import btx_lib_mail as btpc

btpc.emit_greeting()
try:
    btpc.raise_intentional_failure()
except RuntimeError as exc:
    print(f"caught expected failure: {exc}")

btpc.print_info()
```


### CLI Commands {#public-api-cli}

The CLI wraps the same behaviour through rich-click. Highlights:

| Command                           | Purpose                                                      |
|-----------------------------------|--------------------------------------------------------------|
| `btx_lib_mail info`               | Print project metadata via `print_info()`.                   |
| `btx_lib_mail hello`              | Emit the canonical greeting.                                 |
| `btx_lib_mail fail`               | Trigger `raise_intentional_failure()` to inspect tracebacks. |
| `btx_lib_mail send`               | Deliver an email using `send()`.                             |
| `btx_lib_mail validate-email`     | Validate email address syntax.                               |
| `btx_lib_mail validate-smtp-host` | Validate SMTP host format (IPv6-aware).                      |

#### `send` Command Options

**Core Options:**

| Option                                   | Description                                                                                              |
|------------------------------------------|----------------------------------------------------------------------------------------------------------|
| `--host HOST`                            | SMTP host (repeat or comma-separated). Env: `BTX_MAIL_SMTP_HOSTS`.                                       |
| `--recipient EMAIL`                      | Recipient address (repeat or comma-separated). Env: `BTX_MAIL_RECIPIENTS`.                               |
| `--sender EMAIL`                         | Envelope sender. Env: `BTX_MAIL_SENDER`.                                                                 |
| `--subject TEXT`                         | Mail subject line (required).                                                                            |
| `--body TEXT`                            | Plain-text email body (required).                                                                        |
| `--html-body TEXT`                       | Optional HTML body content.                                                                              |
| `--attachment PATH`                      | Attachment file path (repeat for multiple).                                                              |
| `--starttls/--no-starttls`               | Force STARTTLS negotiation. Env: `BTX_MAIL_SMTP_USE_STARTTLS`.                                           |
| `--starttls-verify/--no-starttls-verify` | Verify the server certificate during STARTTLS (default: verify). Env: `BTX_MAIL_SMTP_STARTTLS_VERIFY`.   |
| `--username TEXT`                        | SMTP username. Env: `BTX_MAIL_SMTP_USERNAME`.                                                            |
| `--password TEXT`                        | SMTP password. Env: `BTX_MAIL_SMTP_PASSWORD`.                                                            |
| `--timeout FLOAT`                        | Socket timeout in seconds. Env: `BTX_MAIL_SMTP_TIMEOUT`.                                                 |
| `--local-hostname NAME`                  | Name announced in EHLO (default: this host's name, looked up once). Env: `BTX_MAIL_SMTP_LOCAL_HOSTNAME`. |

**Attachment Security Options:**

| Option                                                 | Description                                                                                                              |
|--------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| `--attachment-allowed-ext EXTS`                        | Allowed extensions (comma-separated, e.g., `.pdf,.txt`). Enables whitelist mode. Env: `BTX_MAIL_ATTACHMENT_ALLOWED_EXT`. |
| `--attachment-blocked-ext EXTS`                        | Blocked extensions (comma-separated). Overrides defaults. Env: `BTX_MAIL_ATTACHMENT_BLOCKED_EXT`.                        |
| `--attachment-allowed-dir PATH`                        | Allowed directory (repeat for multiple). Enables whitelist mode. Env: `BTX_MAIL_ATTACHMENT_ALLOWED_DIRS`.                |
| `--attachment-blocked-dir PATH`                        | Blocked directory (repeat for multiple). Overrides defaults. Env: `BTX_MAIL_ATTACHMENT_BLOCKED_DIRS`.                    |
| `--attachment-max-size BYTES`                          | Max attachment size in bytes. Env: `BTX_MAIL_ATTACHMENT_MAX_SIZE`.                                                       |
| `--attachment-allow-symlinks/--attachment-no-symlinks` | Allow or reject symlinked attachments. Env: `BTX_MAIL_ATTACHMENT_ALLOW_SYMLINKS`.                                        |
| `--attachment-strict/--attachment-warn`                | Raise on security violation (strict) or log warning and skip (warn). Env: `BTX_MAIL_ATTACHMENT_RAISE_ON_SECURITY`.       |

`python -m btx_lib_mail` delegates to the same command group, so the examples
above apply verbatim.

### Invalid `--host` values

`--host` (and `BTX_MAIL_SMTP_HOSTS`) is validated before any delivery is attempted. A
host carrying `@` or `/` (for example `smtp://user:pw@relay`, which would put a
credential into the host field) or an interior whitespace or control character is
refused with an `InvalidInputError` (a `ValueError`) that never echoes the value:

```console
$ btx-lib-mail send --host "user:pw@relay" --sender a@example.com \
    --recipient b@example.com --subject s --body b
InvalidInputError: SMTP host must be host[:port]; it must not contain '@' or '/' (pass credentials as smtp_username and smtp_password)
```

The CLI does not catch this itself; it surfaces through `lib_cli_exit_tools`, which maps
a `ValueError` to a non-zero exit code (`22`, `errno.EINVAL`) and prints the message to
stderr. Pass credentials via `--username`/`--password` instead of folding them into
`--host`. The same check runs for `validate-smtp-host`.

The host syntax is checked the same way, also before any delivery: a port outside 1-65535
or not plain ASCII digits (`+25`, `2_5`), an unclosed IPv6 bracket, an IPv6 address without brackets (`fe80::1`) and
a port with no host name (`:25`) are refused with exit code `22`. These messages quote the
host; a value carrying `@` never reaches them, because the check above refuses it first. `--host
a.example.com,b.example.com` is two hosts, because the CLI splits each value on commas
first; `validate-smtp-host` checks one host and refuses a comma.

### Invalid settings

`send` assigns every resolved option and environment value onto one `ConfMail`, so the
model's own checks run before any delivery. A value it refuses is reported as an
`InvalidInputError` (a `ValueError`) carrying the check's message (exit code `22`), for example a timeout or attachment size that
is not positive:

```console
$ BTX_MAIL_ATTACHMENT_MAX_SIZE=0 btx-lib-mail send --host relay.example.com \
    --recipient b@example.com --subject s --body b
InvalidInputError: attachment_max_size_bytes must be positive, got 0
```

A value that cannot be parsed at all (`BTX_MAIL_SMTP_TIMEOUT=abc`) is still reported as
`BadParameter`.
