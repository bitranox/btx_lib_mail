# btx_lib_mail

<!-- Badges -->
[![CI](https://github.com/bitranox/btx_lib_mail/actions/workflows/default_cicd_public.yml/badge.svg)](https://github.com/bitranox/btx_lib_mail/actions/workflows/default_cicd_public.yml)
[![CodeQL](https://github.com/bitranox/btx_lib_mail/actions/workflows/codeql.yml/badge.svg)](https://github.com/bitranox/btx_lib_mail/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Open in Codespaces](https://img.shields.io/badge/Codespaces-Open-blue?logo=github&logoColor=white&style=flat-square)](https://codespaces.new/bitranox/btx_lib_mail?quickstart=1)
[![PyPI](https://img.shields.io/pypi/v/btx_lib_mail.svg)](https://pypi.org/project/btx_lib_mail/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/btx_lib_mail.svg)](https://pypi.org/project/btx_lib_mail/)
[![Code Style: Ruff](https://img.shields.io/badge/Code%20Style-Ruff-46A3FF?logo=ruff&labelColor=000)](https://docs.astral.sh/ruff/)
[![codecov](https://codecov.io/gh/bitranox/btx_lib_mail/graph/badge.svg?token=UFBaUDIgRk)](https://codecov.io/gh/bitranox/btx_lib_mail)
[![Maintainability](https://qlty.sh/badges/041ba2c1-37d6-40bb-85a0-ec5a8a0aca0c/maintainability.svg)](https://qlty.sh/gh/bitranox/projects/btx_lib_mail)
[![security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)

Send email from Python and from the shell.

Most mail libraries are sold on a feature list, and nobody loses sleep over a feature
list. What keeps you up is the one message that matters failing at the worst possible
time: the 2 GB export that runs your server out of memory, the customer whose name comes
through as garbled bytes, the primary relay that drops mid-send. `btx_lib_mail` is built
for that message, not for the demo.

What you get:

- **Send a 100 GB attachment on a box with almost no free memory.** The message is
  streamed to disk and pushed to the server one chunk at a time, so peak memory stays
  flat whether the file is 100 kB or 100 GB. It never holds the whole payload in RAM,
  because the RAM you do not have is the RAM that kills the job.
- **BDAT when the server supports it, DATA when it does not.** If the far end advertises
  CHUNKING (RFC 3030) the message goes out in length-prefixed chunks; otherwise it falls
  back to a correct, dot-stuffed DATA phase. You do not pick, the library negotiates.
- **Subjects and bodies that encode correctly.** Umlauts, emoji, CJK, a subject that is
  only a full stop: all handled by the standard library's modern email machinery, not by
  a regex someone wrote at 2am. No more `Grüße` arriving as `GrÃ¼ÃŸe` in a customer's name.
- **No more hand-rolling smtplib.** No MIME assembly, no dot-stuffing, no failover loop.
  One function call, or one command.
- **A command-line mailer.** `btx-lib-mail send ...` turns any shell into a mail client,
  with the same streaming and the same checks.
- **Attachments checked before they leave.** Path traversal, symlinks, `/.ssh/`, system
  directories, dangerous extensions and a size cap are refused by default, so you do not
  email your private key by accident.

The part that costs us and earns your trust is the unglamorous part: every wire path is
proven end to end against a real SMTP server, including BDAT, STARTTLS with
authentication, and a memory bound that a 100 GB attachment cannot breach. That
confidence is the actual product. Go and try the daft thing: point it at a spare mailbox
and attach something absurd.

## Quickstart

Install:

```bash
pip install btx_lib_mail
```

Send an email from Python:

```python
from btx_lib_mail import send

send(
    mail_from="alerts@example.com",
    mail_recipients=["oncall@example.com"],
    mail_subject="build failed",
    mail_body="See CI logs for details.",
    smtphosts=["smtp.example.com:587"],
    credentials=("mailer", "s3cr3t"),
)
```

Attach a huge file without running out of memory (streamed, never buffered whole):

```python
from pathlib import Path
from btx_lib_mail import send

send(
    mail_from="backups@example.com",
    mail_recipients=["archive@example.com"],
    mail_subject="nightly dump",
    mail_body="Attached.",
    smtphosts=["smtp.example.com:587"],
    attachment_file_paths=[Path("/data/nightly-dump.tar")],  # gigabytes are fine
)
```

Send from the shell:

```bash
btx-lib-mail send \
  --host smtp.example.com:587 \
  --sender alerts@example.com \
  --recipient oncall@example.com \
  --subject "Ping" \
  --body "Smoke test"
```

Both commands (`btx_lib_mail` and `btx-lib-mail`) and `python -m btx_lib_mail` run the
same CLI.

## Use it from an AI agent (zero install)

btx_lib_mail is built to be driven by LLMs and agents, not only by people. An agent can send mail
with nothing installed, straight from PyPI via `uvx`:

```bash
uvx btx-lib-mail send \
  --host smtp.example.com:587 \
  --sender alerts@example.com --recipient oncall@example.com \
  --subject "Ping" --body "Smoke test"
```

The library also ships a Claude Code skill (`python-send-mail`) that teaches an agent when and how
to use it: install, `uvx`, the library API, the CLI, streaming and BDAT, and attachment security.
Install it into any project:

```bash
/plugin marketplace add bitranox/btx_lib_mail
/plugin install btx_lib_mail
```

It is also available in the central [bitranox-skills](https://github.com/bitranox/bitranox-skills)
marketplace as `coding-python-send-mail`.

## Documentation

- [Installation](docs/installation.md) - pip, pipx, uv, source builds; Python 3.10+ baseline
- [Command-line interface](docs/cli.md) - all CLI commands and `send` options
- [Configuration](docs/configuration.md) - `ConfMail`, precedence, and `BTX_MAIL_*` environment variables
- [Streaming and BDAT](docs/streaming.md) - how bounded-memory delivery and RFC 3030 CHUNKING work
- [Attachment security](docs/attachment-security.md) - the checks applied before an attachment is sent
- [Public API reference](docs/api.md) - `send`, `ConfMail`, functions, and exported constants
- [Module reference](docs/systemdesign/module_reference.md) - internal design and delivery path

### Project docs

- [Install Guide](INSTALL.md)
- [Development Handbook](DEVELOPMENT.md)
- [Contributor Guide](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [AI Transparency](ai-transparency.md)
- [Our Stance on AI](ai-stance.md)
- [License](LICENSE)
