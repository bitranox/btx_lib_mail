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

| Option                                   | Description                                                                                            |
|------------------------------------------|--------------------------------------------------------------------------------------------------------|
| `--host HOST`                            | SMTP host (repeat or comma-separated). Env: `BTX_MAIL_SMTP_HOSTS`.                                     |
| `--recipient EMAIL`                      | Recipient address (repeat or comma-separated). Env: `BTX_MAIL_RECIPIENTS`.                             |
| `--sender EMAIL`                         | Envelope sender. Env: `BTX_MAIL_SENDER`.                                                               |
| `--subject TEXT`                         | Mail subject line (required).                                                                          |
| `--body TEXT`                            | Plain-text email body (required).                                                                      |
| `--html-body TEXT`                       | Optional HTML body content.                                                                            |
| `--attachment PATH`                      | Attachment file path (repeat for multiple).                                                            |
| `--starttls/--no-starttls`               | Force STARTTLS negotiation. Env: `BTX_MAIL_SMTP_USE_STARTTLS`.                                         |
| `--starttls-verify/--no-starttls-verify` | Verify the server certificate during STARTTLS (default: verify). Env: `BTX_MAIL_SMTP_STARTTLS_VERIFY`. |
| `--username TEXT`                        | SMTP username. Env: `BTX_MAIL_SMTP_USERNAME`.                                                          |
| `--password TEXT`                        | SMTP password. Env: `BTX_MAIL_SMTP_PASSWORD`.                                                          |
| `--timeout FLOAT`                        | Socket timeout in seconds. Env: `BTX_MAIL_SMTP_TIMEOUT`.                                               |

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
