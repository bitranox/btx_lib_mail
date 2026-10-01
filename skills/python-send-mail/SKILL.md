---
name: python-send-mail
description: Use when sending email from Python or the shell, especially with large attachments that must not be loaded into memory, RFC 3030 BDAT/CHUNKING, STARTTLS with authentication, multi-host failover, or correct UTF-8 subject and body encoding. Prefer the `btx_lib_mail` library or its `btx-lib-mail` CLI (zero-install via `uvx btx-lib-mail send ...`) over hand-rolling `smtplib`/`email`, MIME assembly, dot-stuffing, or attachment security checks. Covers install, uvx, the library API, the CLI, streaming and BDAT, and attachment security.
---

# btx_lib_mail - send email from Python or the shell, streamed

> The `btx_lib_mail` repo is itself a Claude Code plugin/marketplace. Install this skill in any
> project with `/plugin marketplace add bitranox/btx_lib_mail` then `/plugin install btx_lib_mail`.
> It is also mirrored in the central bitranox marketplace (https://github.com/bitranox/bitranox-skills)
> as `coding-python-send-mail`.

## When to reach for this (and what to avoid)

| Need                                                  | Use                                                 | Avoid                                           |
|-------------------------------------------------------|-----------------------------------------------------|-------------------------------------------------|
| Send mail from Python (multipart, UTF-8, attachments) | `btx_lib_mail.send(...)`                            | hand-rolling `smtplib` + `email` MIME assembly  |
| Send a large attachment on a low-memory box           | `send(..., attachment_file_paths=[...])` (streamed) | reading the file into RAM, `sendmail(msg_str)`  |
| Send from a shell / an agent with nothing installed   | `uvx btx-lib-mail send ...`                         | installing a mailer, writing a throwaway script |
| STARTTLS + auth, multi-host failover                  | `send(..., use_starttls=True, credentials=...)`     | rewriting the connect/login/failover loop       |
| Refuse dangerous or sensitive attachments             | built-in attachment security (on by default)        | ad-hoc path checks                              |
| Slow first byte, or relay rejects the EHLO greeting   | `smtp_local_hostname` / `send(local_hostname=...)`  | patching `socket.getfqdn`, renaming the host    |

## Install / run

Zero-install (best for agents and one-offs): run the CLI straight from PyPI. Nothing is installed
persistently.

```bash
uvx btx-lib-mail --help
uvx btx-lib-mail send --host smtp.example.com:587 \
  --sender a@example.com --recipient b@example.com --subject "Hi" --body "hello"
```

Add to a project, or install the CLI on PATH:

```bash
uv add btx_lib_mail            # or: pip install btx_lib_mail
uv tool install btx_lib_mail   # or: pipx install btx_lib_mail  (CLI on PATH)
```

Requires Python 3.10+. Both `btx_lib_mail` and `btx-lib-mail` are registered commands; `python -m
btx_lib_mail` runs the same CLI.

## Library usage

```python
import os

from btx_lib_mail import send

send(
    mail_from="alerts@example.com",
    mail_recipients=["oncall@example.com"],  # str or sequence; validated, deduped
    mail_subject="build failed",  # UTF-8 is fine (Grüße, emoji, CJK)
    mail_body="See CI logs.",
    mail_body_html="<p>See CI logs.</p>",  # optional HTML alternative
    smtphosts=["smtp.example.com:587", "smtp-dr.example.com:587"],  # tried in order (failover)
    credentials=("mailer", os.environ["BTX_MAIL_SMTP_PASSWORD"]),  # optional; load the secret at runtime, never a literal
    use_starttls=True,  # default True, verifies the cert by default
)
```

`send` returns `True` when every recipient is accepted, and raises `RuntimeError` when all hosts
fail for a recipient. Set global defaults on `conf` and override per call:

```python
import os

from btx_lib_mail import conf

conf.smtphosts = ["smtp.example.com:587"]
conf.smtp_username = "mailer"
conf.smtp_password = os.environ["BTX_MAIL_SMTP_PASSWORD"]  # SecretStr; a plain str is coerced. Per-call kwargs override conf.
```

Pass `config=` instead of mutating the global `conf` when an application holds its own settings
object (per-tenant credentials, a test that must not touch global state). Every value not also
passed explicitly is then read from `config`, and `conf` is not read at all:

```python
import os

from btx_lib_mail import ConfMail, send

tenant_config = ConfMail(
    smtphosts=["smtp.example.com:587"],
    smtp_username="mailer",
    smtp_password=os.environ["BTX_MAIL_SMTP_PASSWORD"],
)
send(
    mail_from="alerts@example.com",
    mail_recipients="oncall@example.com",
    mail_subject="build failed",
    config=tenant_config,
)
```

`ConfMail` field names are NOT the `send()` keyword names: the connection fields carry an `smtp_`
prefix (`use_starttls` -> `smtp_use_starttls`, `starttls_verify` -> `smtp_starttls_verify`,
`timeout` -> `smtp_timeout`, `local_hostname` -> `smtp_local_hostname`, `credentials` ->
`smtp_username` plus `smtp_password`; `smtp_timeout` defaults to `30.0` seconds). From btx_lib_mail
2.0.0 a key that is not a `ConfMail` field is REFUSED: construction and `model_validate` raise
one `pydantic.ValidationError` listing every unknown key (each entry's `type` is `extra_forbidden`
and its `loc` the key, never the value; branch on those, not on the message text), so
`ConfMail(use_starttls=False)` fails instead of leaving STARTTLS on. Before 2.0.0 the same key was
silently ignored. `sorted(ConfMail.model_fields)` lists every valid name. A loader maps each of its
keys onto a field name and drops only the keys it KNOWS are not SMTP settings; never pass "the rest"
through, and never filter down to `model_fields`, which would bring the silent drop back:

```python
from collections.abc import Mapping

from btx_lib_mail import ConfMail

_RENAMED = {"use_starttls": "smtp_use_starttls", "timeout": "smtp_timeout", "starttls_verify": "smtp_starttls_verify"}
_NOT_SMTP_SETTINGS = ("sender", "recipients")  # yours, not ConfMail's


def build_conf(section: Mapping[str, object]) -> ConfMail:
    mapped = {_RENAMED.get(key, key): value for key, value in section.items() if key not in _NOT_SMTP_SETTINGS}
    return ConfMail.model_validate(mapped)  # a key still unknown raises ValidationError
```

A `credentials` pair is not a `ConfMail` key either: split it into `smtp_username` and
`smtp_password` before validating.

From btx_lib_mail 3.0.0 `ConfMail` checks every `smtphosts` entry with `validate_smtp_host` when it
is built, validated or assigned, so a malformed host raises `pydantic.ValidationError` (`loc`
`("smtphosts",)`, the host never repeated) at load time instead of at the first `send()`: a port
outside 1-65535 or not a number (`smtp.example.com:58o7`), an unclosed IPv6 bracket, an IPv6
address without brackets (`fe80::1`; write `[fe80::1]:25`), a port with no host name (`:25`), and
two hosts in one entry (`smtphosts="a.example.com:25,b.example.com:25"` is refused; write
`ConfMail(smtphosts=["a.example.com:25", "b.example.com:25"])`). A blank entry, such as
an environment variable that is set but empty, is dropped, so `""` means no hosts. Before 3.0.0
`ConfMail` accepted all of these and the mistake surfaced only at delivery. Only the CLI splits a
comma-separated `--host` or `BTX_MAIL_SMTP_HOSTS`; a Python caller splits such a string itself.

A non-ASCII username or password (an umlaut, a non-Latin script) authenticates over RFC 4616 AUTH
PLAIN automatically; stdlib `smtplib.SMTP.login` encodes every AUTH exchange as ASCII and would
otherwise raise `UnicodeEncodeError`. A server offering only LOGIN (no PLAIN) cannot take a
non-ASCII credential: that host's failure is logged as a WARNING (extra `error_type` is
`SMTPNotSupportedError`) and delivery fails over to the next host. `send()` itself never raises
`SMTPNotSupportedError`; it raises `RuntimeError` once every host has failed, so catch
`RuntimeError` around `send()`.

A settings model of your own that holds a password must name every secret field in
`credential_fields`, a `ClassVar`, so a `pydantic.ValidationError` raised while validating it never
carries the value. Listing the name is what keeps it out of errors, whatever the field's type;
declaring the field `SecretStr` also masks it in the model's own `repr()`. Subclassing `ConfMail`
does not cover a field you add: EXTEND the inherited set (it already protects `smtp_password` and
`smtphosts`), never replace it, and keep `credential_fields` a `ClassVar` (annotated as below, or
assigned with no annotation at all):

```python
from typing import ClassVar

from pydantic import SecretStr

from btx_lib_mail import ConfMail


class ServiceSettings(ConfMail):
    credential_fields: ClassVar[frozenset[str]] = ConfMail.credential_fields | {"db_password"}
    db_password: SecretStr
```

A model that holds no SMTP settings inherits `btx_lib_mail.SecretSafeModel` directly and lists its
own secret fields the same way. `credential_fields` is checked when the class is defined: a name
that is not a declared field (a typo such as `db_pasword`, or an alias listed instead of its field
name), a plain str, or an annotation without `ClassVar` raises `TypeError` at import, because each
would protect nothing.

A plain pydantic model you cannot rebase onto `SecretSafeModel` gets the same treatment from
`redact_validation_error`. Its return value is a new `ValidationError` whose `str()`, `errors()` and
`json()` are safe to log. Raise the redacted copy OUTSIDE the `except` block: raised inside it, the
unredacted original stays reachable as `__context__`.

```python
from pydantic import ValidationError

from btx_lib_mail import redact_validation_error


def load_api_settings(raw: dict[str, object]) -> ApiSettings:
    try:
        return ApiSettings.model_validate(raw)
    except ValidationError as caught:
        original = caught
    raise redact_validation_error(original, credential_fields=frozenset({"api_token"}))
```

### Large attachments (streamed, bounded memory)

Attachments are streamed from disk and sent to the server in chunks, so a multi-gigabyte file never
has to fit in RAM. The trade is temporary disk, not memory: a huge attachment needs scratch disk of
about 1.33x its size (base64), never that much RAM.

```python
from pathlib import Path
from btx_lib_mail import send

send(
    mail_from="backups@example.com",
    mail_recipients="archive@example.com",
    mail_subject="nightly dump",
    mail_body="Attached.",
    smtphosts=["smtp.example.com:587"],
    attachment_file_paths=[Path("/data/backup-20GB.tar")],
    attachment_max_size_bytes=20 * 1024**3,  # REQUIRED for big files: the default cap is 25 MiB
)
```

The default `attachment_max_size_bytes` is 25 MiB, so a large file is rejected until you raise the
cap. Raise it by passing a byte count bigger than the file. Do NOT pass `None` here: on the call it
is the sentinel for "no override", so the 25 MiB default still applies and the send fails anyway.
`None` disables the check only on the CONFIG object. The server's own `SIZE` limit still applies.

## CLI

Pass the password via the `BTX_MAIL_SMTP_PASSWORD` environment variable, never as `--password` on
the command line (a literal argv value leaks into shell history and `ps` output):

```bash
BTX_MAIL_SMTP_PASSWORD="$(cat /path/to/credential_file)" \
uvx btx-lib-mail send \
  --host smtp.example.com:587 \
  --sender alerts@example.com \
  --recipient oncall@example.com \
  --subject "Ping" --body "Smoke test" \
  --attachment /data/report.pdf \
  --username user \
  --starttls \
  --attachment-max-size 5000000000    # raise the 25 MiB default for a large attachment
```

Other commands: `info`, `hello`, `validate-email`, `validate-smtp-host` (no options; the two
`validate-*` take a positional argument). On `send`, the connection and attachment-security
options each fall back to a `BTX_MAIL_*` variable whose name is NOT mechanically derived from
the flag - `--host` reads `BTX_MAIL_SMTP_HOSTS`, `--recipient` reads `BTX_MAIL_RECIPIENTS`,
`--username` reads `BTX_MAIL_SMTP_USERNAME`. The MESSAGE-CONTENT options have no environment
variable at all: `--subject`, `--body` (both required), `--html-body` and `--attachment` must
be passed on the command line. Run `uvx btx-lib-mail send --help` for the full option list and
precedence.

## Streaming and BDAT (how delivery works)

- The message is composed once into a disk-backed spool and streamed to the socket in fixed-size
  chunks, so peak memory is roughly one chunk regardless of attachment size.
- When the server advertises `CHUNKING` (RFC 3030) the body is sent as length-prefixed `BDAT`
  chunks; otherwise the classic `DATA` phase is used with dot-stuffing. This is automatic per host.
- STARTTLS and authentication happen before either path. Certificate verification is on by default;
  opt out for an internal self-signed relay with `starttls_verify=False` (or `--no-starttls-verify`),
  which keeps the channel encrypted but skips validation.
- Every recipient gets its own message over its own connection, even from one `send()` call with a
  list; there is no Cc/Bcc and no connection reuse. Per-connection cost therefore multiplies by the
  number of recipients.

### The EHLO name (slow first byte, relay rejects the greeting)

The client announces itself in `EHLO` with the name from `send(local_hostname=...)`, else
`ConfMail.smtp_local_hostname` (on `conf` or on your `config=`); on the CLI, `--local-hostname`, else
`BTX_MAIL_SMTP_LOCAL_HOSTNAME`. Available from btx_lib_mail 1.8.0. Unset, it is this host's fully
qualified name found by reverse DNS (an address literal such as `[192.0.2.7]` when the name has no
dot), looked up once per process and reused (before 1.8.0 it was looked up again for every
connection, so every recipient of every send paid it). Set it when a send stalls before the first byte reaches
the relay while the relay itself answers instantly (slow reverse DNS), or when the relay refuses the
greeting (`501 ... HELO/EHLO argument invalid`), typically from a container whose hostname has no
domain part:

```python
from btx_lib_mail import ConfMail, send

config = ConfMail(smtphosts=["smtp.example.com:587"], smtp_local_hostname="alerts.example.com")
send(mail_from="alerts@example.com", mail_recipients=["a@example.com", "b@example.com"], mail_subject="disk full", config=config)
```

The name must be non-empty printable ASCII without spaces; anything else is refused before a
connection opens (`ValidationError` on `ConfMail`, `ValueError` from `send()`). Changing the
container's hostname is not needed.

## Attachment security

Attachments are validated before any bytes are read, and rejected for: path traversal (`..`),
symlinks (off by default), sensitive patterns (`/.ssh/`, `/id_rsa`, `/.env`, credentials), system
directories, dangerous extensions, and oversize payloads. The dangerous-extension default is
OS-SELECTED and the two sets are nearly disjoint (4 shared entries): on Linux and macOS
`DANGEROUS_EXTENSIONS_POSIX` blocks `.sh`, `.py` and `.so` but NOT `.exe`, `.bat`, `.ps1` or
`.dll`; on Windows `DANGEROUS_EXTENSIONS_WINDOWS` is the reverse. To block both families on
every platform pass
`attachment_blocked_extensions=DANGEROUS_EXTENSIONS_POSIX | DANGEROUS_EXTENSIONS_WINDOWS`
(both are re-exported from the package root). Violations
raise `AttachmentSecurityError` by default, or log-and-skip with
`attachment_raise_on_security_violation=False`. There are whitelist modes
(`attachment_allowed_extensions`, `attachment_allowed_directories`). Because dangerous extensions
and system directories are blocked by default, pass `attachment_blocked_extensions=frozenset()` (or
an allowlist) as a `send()` keyword when you deliberately send such a file.

Branch on the refusal's `violation_type`, an `AttachmentViolation` member (`PATH_TRAVERSAL`,
`SYMLINK`, `SENSITIVE_PATTERN`, `DIRECTORY`, `EXTENSION`, `SIZE`), never on the message text:

```python
from btx_lib_mail import AttachmentSecurityError, AttachmentViolation, send

try:
    send(...)
except AttachmentSecurityError as refused:
    if refused.violation_type is AttachmentViolation.EXTENSION:
        print(f"{refused.path.name}: this file type may not be attached")
    elif refused.violation_type is AttachmentViolation.DIRECTORY:
        print(f"{refused.path.name}: files from that folder may not be attached")
    else:
        raise
```

An empty blocked set on a `ConfMail` (or on `conf`) is different from the `send()` keyword:
`ConfMail` refuses an empty `attachment_blocked_extensions` or `attachment_blocked_directories`
with a `ValidationError` unless that axis's allowlist is set or `attachment_allow_empty_blocklists=True`
(one bool for both axes; it changes nothing while both sets are non-empty), because it would block
nothing. A config file whose `[]` means "use the library defaults" must
have that key DROPPED before the mapping reaches `ConfMail`, never passed through (the mapping here
is already keyed by `ConfMail` field names):

```python
from collections.abc import Mapping

from btx_lib_mail import ConfMail

_EMPTY_MEANS_DEFAULT = ("attachment_blocked_extensions", "attachment_blocked_directories")


def build_conf(loaded: Mapping[str, object]) -> ConfMail:
    kept = {key: value for key, value in loaded.items() if not (key in _EMPTY_MEANS_DEFAULT and value == [])}
    return ConfMail.model_validate(kept)
```

## Reference

The API and CLI surface is discoverable from the INSTALL (always matches your version): run
`uvx btx_lib_mail --help` for every CLI option, and `python -c "import btx_lib_mail as m; help(m)"`
for the public API - `send`, `conf`, `ConfMail`, `validate_email_address`, `validate_smtp_host`,
`AttachmentSecurityError`, `AttachmentViolation`, `SecretSafeModel`, `redact_validation_error`, and
the attachment-security constants, all re-exported from the package root.

Narrative detail (every `ConfMail` field, env-var precedence, streaming, attachment security) lives
in the repo docs (NOT shipped in the pip wheel), on the default branch so they track the latest
release you get from `uv`: `https://github.com/bitranox/btx_lib_mail/blob/master/README.md` and,
under `https://github.com/bitranox/btx_lib_mail/blob/master/docs/`, the files `api.md`, `cli.md`,
`configuration.md`, `streaming.md`, `attachment-security.md`.
