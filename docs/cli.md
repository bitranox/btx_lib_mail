# Command-line interface

The CLI leverages [rich-click](https://github.com/ewels/rich-click) so help and error output render with Rich styling while keeping the familiar click ergonomics.

```bash
btx_lib_mail info
btx_lib_mail hello
btx_lib_mail fail
btx_lib_mail --traceback fail
btx_lib_mail send --subject "Ping" --body "Smoke test" --recipient ops@example.com --host smtp.example.com
btx_lib_mail send --env-file relay.env --subject "Ping" --body "Smoke test"
btx_lib_mail --json send --subject "Ping" --body "Smoke test" --recipient ops@example.com --host smtp.example.com
btx-lib-mail info
python -m btx_lib_mail info
```

The `send` subcommand accepts CLI flags, the `BTX_MAIL_*` environment variables, or a
`KEY=value` file named with `--env-file`, making it easy to smoke-test SMTP
environments without writing a custom script. `python -m btx_lib_mail` runs the same
entry point as the `btx_lib_mail` / `btx-lib-mail` console scripts, so everything below
(exit codes and `--json` included) applies to all three.

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


## CLI Commands

The CLI wraps the same behaviour through rich-click. Highlights:

| Command                           | Purpose                                                      |
|-----------------------------------|--------------------------------------------------------------|
| `btx_lib_mail info`               | Print project metadata via `print_info()`.                   |
| `btx_lib_mail hello`              | Emit the canonical greeting.                                 |
| `btx_lib_mail fail`               | Trigger `raise_intentional_failure()` to inspect tracebacks. |
| `btx_lib_mail send`               | Deliver an email using `send()`.                             |
| `btx_lib_mail validate-email`     | Validate email address syntax.                               |
| `btx_lib_mail validate-smtp-host` | Validate SMTP host format (IPv6-aware).                      |

### Global options

These go BEFORE the subcommand (`btx_lib_mail --json send ...`) and apply to every
subcommand.

| Option                       | Description                                                                                  |
|------------------------------|----------------------------------------------------------------------------------------------|
| `--traceback/--no-traceback` | Show the full Python traceback on an error (default: one summary line on stderr).            |
| `--json`, `-j`               | Print one JSON envelope on stdout (see [Machine-readable output](#machine-readable-output)). |
| `--json-bare`                | Print the JSON payload (or the error object) alone, without the envelope.                    |
| `--version`                  | Print the version.                                                                           |
| `--help`, `-h`               | Show help (also on every subcommand).                                                        |

`--json` and `--json-bare` exclude each other (exit `2`). Without a subcommand the CLI prints
its help and exits `0`; `--version`, `--help` and that help are plain text even with `--json`.

### `send` Command Options

**Core Options:**

| Option                                   | Description                                                                                                                                                                           |
|------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--host HOST`                            | SMTP host (repeat or comma-separated). Env: `BTX_MAIL_SMTP_HOSTS`.                                                                                                                    |
| `--recipient EMAIL`                      | Recipient address (repeat or comma-separated). Env: `BTX_MAIL_RECIPIENTS`.                                                                                                            |
| `--sender EMAIL`                         | Envelope sender. Env: `BTX_MAIL_SENDER`; without either, the first recipient.                                                                                                         |
| `--recipient-max-count N`                | Most recipients one run accepts (default `1000`). Env: `BTX_MAIL_RECIPIENT_MAX_COUNT`.                                                                                                |
| `--subject TEXT`                         | Mail subject line (required).                                                                                                                                                         |
| `--body TEXT`                            | Plain-text email body (required).                                                                                                                                                     |
| `--html-body TEXT`                       | Optional HTML body content.                                                                                                                                                           |
| `--attachment PATH`                      | Attachment file path (repeat for multiple).                                                                                                                                           |
| `--env-file PATH`                        | Read unset `BTX_MAIL_*` settings from this `KEY=value` file instead of `./.env`. Env: `BTX_MAIL_ENV_FILE`.                                                                            |
| `--starttls/--no-starttls`               | Negotiate STARTTLS before sending (default: on); `--no-starttls` sends unencrypted, for a relay that offers no TLS. Env: `BTX_MAIL_SMTP_USE_STARTTLS`.                                |
| `--starttls-verify/--no-starttls-verify` | Verify the server certificate during STARTTLS (default: verify). Env: `BTX_MAIL_SMTP_STARTTLS_VERIFY`.                                                                                |
| `--username TEXT`                        | SMTP username. Env: `BTX_MAIL_SMTP_USERNAME`.                                                                                                                                         |
| `--password TEXT`                        | SMTP password. Env: `BTX_MAIL_SMTP_PASSWORD`. Visible to other users in the process list; prefer `--password-file` or the environment.                                                |
| `--password-file PATH`                   | Read the SMTP password from the first line of this file; `-` reads stdin. Excludes `--password`.                                                                                      |
| `--timeout FLOAT`                        | Socket timeout in seconds, per socket operation (default `30`). Env: `BTX_MAIL_SMTP_TIMEOUT`.                                                                                         |
| `--delivery-deadline SECONDS`            | Upper bound for one SMTP session (one recipient via one host); a server that answers a byte at a time never trips `--timeout`. Default: none. Env: `BTX_MAIL_SMTP_DELIVERY_DEADLINE`. |
| `--local-hostname NAME`                  | Name announced in EHLO (default: this host's name, looked up once). Env: `BTX_MAIL_SMTP_LOCAL_HOSTNAME`.                                                                              |

**Attachment Security Options:**

| Option                                                 | Description                                                                                                                                                                        |
|--------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--attachment-allowed-ext EXTS`                        | Allowed extensions (comma-separated, e.g., `.pdf,.txt`; given twice, the last wins). Enables whitelist mode, which replaces the blocklist. Env: `BTX_MAIL_ATTACHMENT_ALLOWED_EXT`. |
| `--attachment-blocked-ext EXTS`                        | Blocked extensions (comma-separated; given twice, the last wins). Overrides defaults; an empty value counts as unset and keeps them. Env: `BTX_MAIL_ATTACHMENT_BLOCKED_EXT`.       |
| `--attachment-allowed-dir PATH`                        | Allowed directory (repeat for multiple). Enables whitelist mode. Env: `BTX_MAIL_ATTACHMENT_ALLOWED_DIRS`.                                                                          |
| `--attachment-blocked-dir PATH`                        | Blocked directory (repeat for multiple). Overrides defaults. Env: `BTX_MAIL_ATTACHMENT_BLOCKED_DIRS`.                                                                              |
| `--attachment-max-size BYTES`                          | Max attachment size in bytes (default 25 MiB). Env: `BTX_MAIL_ATTACHMENT_MAX_SIZE`.                                                                                                |
| `--attachment-max-count N`                             | Most attachments one run accepts (default `100`). Env: `BTX_MAIL_ATTACHMENT_MAX_COUNT`.                                                                                            |
| `--attachment-allow-symlinks/--attachment-no-symlinks` | Allow or reject symlinked attachments (default: reject). Env: `BTX_MAIL_ATTACHMENT_ALLOW_SYMLINKS`.                                                                                |
| `--attachment-strict/--attachment-warn`                | Raise on security violation (strict, the default) or log warning and skip (warn). Env: `BTX_MAIL_ATTACHMENT_RAISE_ON_SECURITY`.                                                    |

`python -m btx_lib_mail` delegates to the same entry point, so the examples
above apply verbatim.

## Where `send` settings come from

For each setting, the first of these that sets it wins:

1. the command-line option;
2. the environment variable (`BTX_MAIL_*`);
3. the file named by `--env-file` (or `BTX_MAIL_ENV_FILE`);
4. the value on `btx_lib_mail.conf`.

The recipients have no `conf` value, so with none from the first three sources `send` stops
with a usage error; the sender, when no option or variable names one, is the first recipient.
An empty or whitespace-only value in the environment or the file counts as unset, so a blank
variable does not hide the file's value. The env file holds
`KEY=value` lines (a line ends at LF, with one CR before it dropped); blank lines, `#` comments and lines without `=` are skipped, a value
loses surrounding whitespace and ONE matching pair of quotes (`"x"` or `'x'`; a lone quote
character stays), the first occurrence of a key wins, and the file must be UTF-8 and at most 64 KiB. It may be
a regular file, a pipe or a character device, so `--env-file /dev/null` ignores `./.env` and
`--env-file <(...)` reads a process substitution; a FIFO with no writer reads as empty. A shell-style `export KEY=value` line is not recognised (its key reads as
`export KEY`). Booleans accept `1`, `true`, `yes`, `on` and `0`, `false`, `no`, `off` in any
case; a value that cannot be parsed (`BTX_MAIL_SMTP_TIMEOUT=abc`, `BTX_MAIL_SMTP_USE_STARTTLS=maybe`)
is a usage error, exit code `2`.

Authentication needs both a username and a password; with only one of them the mail is
sent without authenticating. `--password-file` reads the first line (up to the first LF, one CR before it dropped) of a UTF-8 file of at most
4096 characters; an empty first line counts as no password, so `BTX_MAIL_SMTP_PASSWORD`
applies. `--attachment-allowed-dir` and `--attachment-blocked-dir` split each value on
commas, like `--host` and `--recipient`.

Without `--env-file`, `send` reads `.env` in the working directory when it is a regular
file; a named file replaces it, and a key the named file lacks is not looked up in
`./.env`. A `.env` is trusted like the command line: in a cloned repository or a shared
folder it can redirect `BTX_MAIL_SMTP_HOSTS` to a host that holds a valid certificate for
its own name (so a verified STARTTLS still hands it the password), switch STARTTLS off, or
lift the attachment blocklists. Run `send` from a directory whose `.env` you trust, or name
the file with `--env-file`.

When credentials are sent with STARTTLS off, the library logs a warning naming the host;
the delivery is not refused, since an internal relay may offer no TLS.

## Machine-readable output

With `--json`, every subcommand prints exactly one JSON document on stdout:

```json
{"ok": true, "command": "send", "data": {"sender": "a@example.com", "recipients": ["b@example.com"], "hosts": ["relay.example.com"]}, "skipped": []}
```

On failure, the document names the error type and its message (never a traceback, even
with `--traceback`), and the exit code is the one the same failure has without `--json`.
`error.type` is the exception's class name: a `BtxMailError` subclass for a refusal by the
library, or a click exception (`UsageError`, `BadParameter`, `MissingParameter`,
`NoSuchOption`, `NoSuchCommand`) for a usage error. `command` is the word in the subcommand's
position (the first argument that is not a group option) when it names a command, and `null`
otherwise. A `DeliveryError` also carries `failed_recipients` and `hosts`; no other error does:

```json
{"ok": false, "command": "validate-email", "error": {"type": "InvalidInputError", "message": "invalid email address: 'nope'"}, "skipped": []}
{"ok": false, "command": "send", "error": {"type": "DeliveryError", "message": "...", "failed_recipients": ["b@example.com"], "hosts": ["relay.example.com"]}, "skipped": []}
```

`skipped` lists what `send` left out, on success and on failure alike, as `{"kind":
"attachment" | "recipient", "value": ..., "reason": ...}`: the attachments `--attachment-warn`
left out for breaking a security rule (a missing attachment still fails, exit `2`), and, when
an application embedding the CLI sets `raise_on_missing_attachments=False` or
`raise_on_invalid_recipient=False` on `conf`, the attachments and recipients those skip. So a
partial delivery is distinguishable from a complete one. `--json-bare` prints `data` (or the
`error` object) alone. Warnings and notes always go to stderr, never into the JSON on stdout.
Only `--json`, `-j` or `--json-bare` given BEFORE the subcommand switch JSON on; the same text
as an option value (`--body --json`), or after a mistyped subcommand, does not.

| Command              | `data`                                                                                           |
|----------------------|--------------------------------------------------------------------------------------------------|
| `info`               | `name`, `title`, `version`, `homepage`, `author`, `author_email`, `shell_command`                |
| `hello`              | `greeting`                                                                                       |
| `send`               | `sender`, `recipients` (those delivered to: trimmed, lower-cased when ASCII, each once), `hosts` |
| `validate-email`     | `address`, `valid`                                                                               |
| `validate-smtp-host` | `host`, `valid`                                                                                  |

## Exit codes

The same in every output mode and for every entry point:

| Code                | Meaning                                                                                                                                                                                                                                                                                                                                                           |
|---------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `0`                 | Success.                                                                                                                                                                                                                                                                                                                                                          |
| `1`                 | Delivery failed for a recipient on every host (`DeliveryError`), an attachment broke a security rule (`AttachmentSecurityError`), or another error.                                                                                                                                                                                                               |
| `2`                 | Usage error: a missing, unparseable or conflicting option (`--password` with `--password-file`, `--json` with `--json-bare`), an unknown command, no host or recipient from any source, an env file or password file that is missing, unreadable, too large or not UTF-8, an attachment that cannot be read, or a missing attachment (`AttachmentNotFoundError`). |
| `22` (Windows `87`) | A value was refused (`InvalidInputError`): sender, recipient, host, subject, timeout, size, ...                                                                                                                                                                                                                                                                   |
| `130`               | Interrupted (Ctrl+C).                                                                                                                                                                                                                                                                                                                                             |

A run whose standard output reader has gone away (a broken pipe) is outside this table: nobody
receives the result, and the code is `1` when click meets the broken pipe while it prints, or `120`
when the interpreter does at exit, so it can differ between output modes. A run started with
standard output already closed exits as the table says, since nothing is written.

## Invalid `--host` values

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
stderr. Pass credentials via `--username` with `--password-file` (or
`BTX_MAIL_SMTP_PASSWORD`) instead of folding them into `--host`. The same check runs for `validate-smtp-host`.

The host syntax is checked the same way, also before any delivery: a port outside 1-65535
or not plain ASCII digits (`+25`, `2_5`), an unclosed IPv6 bracket, an IPv6 address without brackets (`fe80::1`),
bracket content that is not an IP address (`[zz]`), a name with an empty label (`a..b`), a label
starting or ending with `-` or longer than 63 characters, a name over 253 characters, and a port
with no host name (`:25`) are refused with exit code `22`. These messages quote the
host, except the two length refusals, which give the length instead; a value carrying `@` never reaches them, because the check above refuses it first. `--host
a.example.com,b.example.com` is two hosts, because the CLI splits each value on commas
first; `validate-smtp-host` checks one host and refuses a comma.

## Invalid settings

`send` assigns every resolved option and environment value onto one `ConfMail`, so the
model's own checks run before any delivery. A value it refuses is reported as an
`InvalidInputError` (a `ValueError`) carrying the check's message (exit code `22`), for example a timeout or attachment size that
is not positive:

```console
$ BTX_MAIL_ATTACHMENT_MAX_SIZE=0 btx-lib-mail send --host relay.example.com \
    --recipient b@example.com --subject s --body b
InvalidInputError: attachment_max_size_bytes must be positive, got 0
```

A value that cannot be parsed at all (`BTX_MAIL_SMTP_TIMEOUT=abc`) is a usage error instead:
`Error: Invalid value: Unrecognised float value for BTX_MAIL_SMTP_TIMEOUT: 'abc'`, exit code `2`.
