# btx_lib_mail

<!-- Badges -->
[![CI](https://github.com/bitranox/btx_lib_mail/actions/workflows/ci.yml/badge.svg)](https://github.com/bitranox/btx_lib_mail/actions/workflows/ci.yml)
[![CodeQL](https://github.com/bitranox/btx_lib_mail/actions/workflows/codeql.yml/badge.svg)](https://github.com/bitranox/btx_lib_mail/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Open in Codespaces](https://img.shields.io/badge/Codespaces-Open-blue?logo=github&logoColor=white&style=flat-square)](https://codespaces.new/bitranox/btx_lib_mail?quickstart=1)
[![PyPI](https://img.shields.io/pypi/v/btx_lib_mail.svg)](https://pypi.org/project/btx_lib_mail/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/btx_lib_mail.svg)](https://pypi.org/project/btx_lib_mail/)
[![Code Style: Ruff](https://img.shields.io/badge/Code%20Style-Ruff-46A3FF?logo=ruff&labelColor=000)](https://docs.astral.sh/ruff/)
[![codecov](https://codecov.io/gh/bitranox/btx_lib_mail/graph/badge.svg?token=UFBaUDIgRk)](https://codecov.io/gh/bitranox/btx_lib_mail)
[![Maintainability](https://qlty.sh/badges/041ba2c1-37d6-40bb-85a0-ec5a8a0aca0c/maintainability.svg)](https://qlty.sh/gh/bitranox/projects/btx_lib_mail)
[![Known Vulnerabilities](https://snyk.io/test/github/bitranox/btx_lib_mail/badge.svg)](https://snyk.io/test/github/bitranox/btx_lib_mail)
[![security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)

Mail Library - send Mails easy
- TLS by default
- Rich CLI Interface, entry point styled with rich-click (rich output + click ergonomics)
- Exit-code and messaging helpers powered by lib_cli_exit_tools
- can be used as Commandline Mailer

## Install

```bash
pip install btx_lib_mail
```

For alternative install paths (pipx, uv, source builds, etc.), see
[INSTALL.md](INSTALL.md). All supported methods register both the
`btx_lib_mail` and `btx-lib-mail` commands on your PATH.

### Python 3.13+ Baseline

- The project targets **Python 3.13 and newer only**. Helpers freely rely on conveniences
  such as `Path.unlink(missing_ok=True)` and modern `contextlib` utilities.
- **Dependency audit (October 16, 2025):** runtime requirements continue to
  match the latest stable releases (`rich-click>=1.9.3`,
  `lib_cli_exit_tools>=2.1.0`, `pydantic>=2.12.2`). Development extras were
  reconfirmed via `python -m pip index versions …`, with no upgrades required.
- GitHub Actions jobs keep using the rolling runners (`ubuntu-latest`,
  `macos-latest`, `windows-latest`) and now cache pip downloads via
  `actions/setup-python@v6` while pinning CodeQL to `v4.30.8`, preserving
  parity with the latest 2025 ruleset.


## Usage

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


## Mail Configuration

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
- Credentials are optional. If both `smtp_username` and `smtp_password` are
  provided, `send` will call `SMTP.login`. The helper also accepts
  one-off credentials via the `credentials=` argument.
- Messages are always rendered as UTF-8; attachments retain their binary
  payload via base64 encoding. Failed hosts are logged at WARNING level and the
  helper proceeds to the next configured server before raising.
- The socket timeout defaults to `conf.smtp_timeout` (30 seconds). Override the
  value via the `timeout=` argument, the `--timeout` CLI flag, or the
  `BTX_MAIL_SMTP_TIMEOUT` environment variable / `.env` entry.

## Public API Reference {#public-api}

All public interfaces are documented in
`docs/systemdesign/module_reference.md#feature-cli-components`. The summary
below mirrors that source so the README can be used as a quick reference.

### Configuration Surface {#public-api-config}

#### `btx_lib_mail.conf: ConfMail` {#public-api-conf}

`conf` is the global configuration instance used whenever a `send` caller does
not supply per-call overrides. Update it directly or replace it wholesale with
`ConfMail.model_validate()`.

#### `ConfMail` fields {#public-api-confmail-fields}

| Field                          | Type          | Default | Description                                                                                                                             |
|--------------------------------|---------------|---------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `smtphosts`                    | `list[str]`   | `[]`    | Ordered SMTP hosts (`"host[:port]"`). An empty list requires callers to supply `smtphosts` when sending.                                |
| `raise_on_missing_attachments` | `bool`        | `True`  | When `True`, missing attachments raise `FileNotFoundError`; otherwise a warning is logged and delivery proceeds without the attachment. |
| `raise_on_invalid_recipient`   | `bool`        | `True`  | When `True`, invalid recipient addresses raise `ValueError`; otherwise a warning is logged and the address is skipped.                  |
| `smtp_username`                | `str \| None` | `None`  | Username used for SMTP authentication. Must be paired with `smtp_password`.                                                             |
| `smtp_password`                | `str \| None` | `None`  | Password paired with `smtp_username`. Ignored when either value is missing.                                                             |
| `smtp_use_starttls`            | `bool`        | `True`  | Enables `STARTTLS` negotiation before authentication. Set to `False` for servers that do not support STARTTLS.                          |
| `smtp_timeout`                 | `float`       | `30.0`  | Socket timeout in seconds applied to SMTP connections.                                                                                  |

Common helpers:

- `ConfMail.model_validate(data: dict[str, Any]) -> ConfMail` — validate crude
  configuration (dicts, strings, iterables) into a typed instance.
- `ConfMail.model_update(new_values: dict[str, Any]) -> ConfMail` — update an
  existing instance in place.
- `ConfMail.resolved_credentials() -> tuple[str, str] | None` — return the
  `(username, password)` pair when both credential fields are populated.

### Functions {#public-api-functions}

#### `emit_greeting(*, stream: TextIO | None = None) -> None` {#public-api-emit-greeting}

Writes the canonical `"Hello World\n"` line to `stream` (defaults to
`sys.stdout`) and flushes the stream when it exposes a `flush()` method.
Useful for smoke tests and quick health probes.

#### `raise_intentional_failure() -> None` {#public-api-raise-intentional-failure}

Raises `RuntimeError("I should fail")` unconditionally. The CLI and tests use
this helper to validate traceback handling and exit-code mapping without
crafting bespoke exceptions.

#### `noop_main() -> None` {#public-api-noop-main}

Returns `None` immediately. The CLI uses this placeholder when the user opts in
to running the domain stub (for example via `--traceback` without a
subcommand), ensuring the scaffold remains predictable.

#### `send(...) -> bool` {#public-api-send}

Entry point for SMTP delivery. Returns `True` when all recipients succeed and
raises when every host fails for at least one recipient. Parameters:

| Parameter               | Type                    | Default        | Notes                                                                                                    |
|-------------------------|-------------------------|----------------|----------------------------------------------------------------------------------------------------------|
| `mail_from`             | `str`                   | —              | Envelope sender address (`local@domain`).                                                                |
| `mail_recipients`       | `str                    | Sequence[str]` | Deduplicated, validated recipient addresses.                                                             |
| `mail_subject`          | `str`                   | —              | UTF-8 subject line.                                                                                      |
| `mail_body`             | `str`                   | `""`           | Optional plain-text body.                                                                                |
| `mail_body_html`        | `str`                   | `""`           | Optional HTML body (UTF-8).                                                                              |
| `smtphosts`             | `Sequence[str]          | None`          | Host override. Falls back to `conf.smtphosts`.                                                           |
| `attachment_file_paths` | `Sequence[pathlib.Path] | None`          | Iterable of attachment paths. Missing files raise unless `conf.raise_on_missing_attachments` is `False`. |
| `credentials`           | `tuple[str, str]        | None`          | `(username, password)` override. Defaults to `conf.resolved_credentials()`.                              |
| `use_starttls`          | `bool                   | None`          | When `None`, the helper uses `conf.smtp_use_starttls`.                                                   |
| `timeout`               | `float                  | None`          | When `None`, the helper uses `conf.smtp_timeout`.                                                        |

**Raises:**

- `ValueError` — after validation if no valid recipients remain.
- `FileNotFoundError` — when a required attachment is missing and
  `raise_on_missing_attachments` is `True`.
- `RuntimeError` — when every configured host fails for a recipient (the error
  lists recipients and host roster).

### CLI Commands {#public-api-cli}

The CLI wraps the same behaviour through rich-click. Highlights:

| Command              | Purpose                                                      | Key Options                                                                                                                                                                                                                                        |
|----------------------|--------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `btx_lib_mail info`  | Print project metadata via `print_info()`.                   | —                                                                                                                                                                                                                                                  |
| `btx_lib_mail hello` | Emit the canonical greeting.                                 | —                                                                                                                                                                                                                                                  |
| `btx_lib_mail fail`  | Trigger `raise_intentional_failure()` to inspect tracebacks. | `--traceback/--no-traceback` toggles verbosity.                                                                                                                                                                                                    |
| `btx_lib_mail send`  | Deliver an email using `send()`.                             | `--host`, `--recipient`, `--sender`, `--subject`, `--body`, `--html-body`, `--attachment`, `--starttls/--no-starttls`, `--username`, `--password`, `--timeout`. Each flag defaults to the matching `BTX_MAIL_*` environment variable when omitted. |

`python -m btx_lib_mail` delegates to the same command group, so the examples
above apply verbatim.

### Environment Variables and Precedence {#mail-env-variables}

The CLI and library coordinate configuration using the following precedence:
1. **CLI options** passed to `btx_lib_mail send`.
2. **Environment variables** exported in the shell (`BTX_MAIL_*` keys below).
3. Matching entries in the project `.env` file (used by `_configured_value`).
4. Defaults baked into `btx_lib_mail.conf`.

Environment variables understood by the CLI:

| Variable                     | Purpose                                                      | Example                                   |
|------------------------------|--------------------------------------------------------------|-------------------------------------------|
| `BTX_MAIL_SMTP_HOSTS`        | Comma-separated list of SMTP hosts (each `host[:port]`).     | `smtp1.example.com:587,smtp2.example.com` |
| `BTX_MAIL_RECIPIENTS`        | Comma-separated list of recipient emails.                    | `primary@example.com,backup@example.com`  |
| `BTX_MAIL_SENDER`            | Envelope sender; defaults to the first recipient when unset. | `alerts@example.com`                      |
| `BTX_MAIL_SMTP_USE_STARTTLS` | Boolean flag (`1`, `true`, `yes`, `on`) enabling STARTTLS.   | `true`                                    |
| `BTX_MAIL_SMTP_USERNAME`     | Username used when STARTTLS/authentication is required.      | `smtp-user`                               |
| `BTX_MAIL_SMTP_PASSWORD`     | Password paired with the SMTP username.                      | `s3cr3t`                                  |
| `BTX_MAIL_SMTP_TIMEOUT`      | Socket timeout in seconds (defaults to `30`).                | `12.5`                                    |

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


## Further Documentation

- [Install Guide](INSTALL.md)
- [Development Handbook](DEVELOPMENT.md)
- [Contributor Guide](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Module Reference](docs/systemdesign/module_reference.md)
- [License](LICENSE)
