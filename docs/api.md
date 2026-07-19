# Public API reference

All public interfaces are documented in
`docs/systemdesign/module_reference.md#feature-cli-components`. The summary
below mirrors that source so the README can be used as a quick reference.

### Configuration Surface {#public-api-config}

#### `btx_lib_mail.conf: ConfMail` {#public-api-conf}

`conf` is the global configuration instance used whenever a `send` caller does
not supply per-call overrides. Update it directly or replace it wholesale with
`ConfMail.model_validate()`.

#### `ConfMail` fields {#public-api-confmail-fields}

**SMTP Settings:**

| Field                          | Type          | Default | Description                                                                                                                             |
|--------------------------------|---------------|---------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `smtphosts`                    | `list[str]`   | `[]`    | Ordered SMTP hosts (`"host[:port]"`). An empty list requires callers to supply `smtphosts` when sending.                                |
| `raise_on_missing_attachments` | `bool`        | `True`  | When `True`, missing attachments raise `FileNotFoundError`; otherwise a warning is logged and delivery proceeds without the attachment. |
| `raise_on_invalid_recipient`   | `bool`        | `True`  | When `True`, invalid recipient addresses raise `ValueError`; otherwise a warning is logged and the address is skipped.                  |
| `smtp_username`                | `str \| None` | `None`  | Username used for SMTP authentication. Must be paired with `smtp_password`.                                                             |
| `smtp_password`                | `str \| None` | `None`  | Password paired with `smtp_username`. Ignored when either value is missing.                                                             |
| `smtp_use_starttls`            | `bool`        | `True`  | Enables `STARTTLS` negotiation before authentication. Set to `False` for servers that do not support STARTTLS.                          |
| `smtp_starttls_verify`         | `bool`        | `True`  | Verifies the server certificate and hostname during `STARTTLS`. Set to `False` for internal self-signed relays (encrypted, unverified). |
| `smtp_timeout`                 | `float`       | `30.0`  | Socket timeout in seconds applied to SMTP connections.                                                                                  |

**Attachment Security Settings:**

| Field                                    | Type                      | Default               | Description                                                                                                                     |
|------------------------------------------|---------------------------|-----------------------|---------------------------------------------------------------------------------------------------------------------------------|
| `attachment_allowed_extensions`          | `frozenset[str] \| None`  | `None`                | When set, only these extensions are allowed (whitelist mode). `None` uses blacklist mode.                                       |
| `attachment_blocked_extensions`          | `frozenset[str]`          | OS-specific dangers   | Extensions to reject. Ignored when `attachment_allowed_extensions` is set. Defaults to dangerous extensions for the current OS. |
| `attachment_allowed_directories`         | `frozenset[Path] \| None` | `None`                | When set, attachments must reside under one of these directories (whitelist mode).                                              |
| `attachment_blocked_directories`         | `frozenset[Path]`         | OS-specific sensitive | Directories from which attachments cannot be read. Defaults to sensitive system directories.                                    |
| `attachment_max_size_bytes`              | `int \| None`             | `26_214_400` (25 MiB) | Maximum attachment size in bytes. `None` disables size checking.                                                                |
| `attachment_allow_symlinks`              | `bool`                    | `False`               | When `False`, symlinks are rejected; when `True`, symlinks are resolved and validated.                                          |
| `attachment_raise_on_security_violation` | `bool`                    | `True`                | When `True`, security violations raise `AttachmentSecurityError`; when `False`, they log a warning and skip the attachment.     |

Common helpers:

- `ConfMail.model_validate(data: dict[str, Any]) -> ConfMail`  -  validate crude
  configuration (dicts, strings, iterables) into a typed instance.
- `ConfMail.model_update(new_values: dict[str, Any]) -> ConfMail`  -  update an
  existing instance in place.
- `ConfMail.resolved_credentials() -> tuple[str, str] | None`  -  return the
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
raises when every host fails for at least one recipient.

**Core Parameters:**

| Parameter               | Type                             | Default | Notes                                                                                                    |
|-------------------------|----------------------------------|---------|----------------------------------------------------------------------------------------------------------|
| `mail_from`             | `str`                            | -       | Envelope sender address (`local@domain`).                                                                |
| `mail_recipients`       | `str \| Sequence[str]`           | -       | Deduplicated, validated recipient addresses.                                                             |
| `mail_subject`          | `str`                            | -       | UTF-8 subject line.                                                                                      |
| `mail_body`             | `str`                            | `""`    | Optional plain-text body.                                                                                |
| `mail_body_html`        | `str`                            | `""`    | Optional HTML body (UTF-8).                                                                              |
| `smtphosts`             | `Sequence[str] \| None`          | `None`  | Host override. Falls back to `conf.smtphosts`.                                                           |
| `attachment_file_paths` | `Sequence[pathlib.Path] \| None` | `None`  | Iterable of attachment paths. Missing files raise unless `conf.raise_on_missing_attachments` is `False`. |
| `credentials`           | `tuple[str, str] \| None`        | `None`  | `(username, password)` override. Defaults to `conf.resolved_credentials()`.                              |
| `use_starttls`          | `bool \| None`                   | `None`  | When `None`, the helper uses `conf.smtp_use_starttls`.                                                   |
| `starttls_verify`       | `bool \| None`                   | `None`  | When `None`, the helper uses `conf.smtp_starttls_verify`. `False` skips certificate verification.        |
| `timeout`               | `float \| None`                  | `None`  | When `None`, the helper uses `conf.smtp_timeout`.                                                        |

**Attachment Security Parameters (keyword-only):**

| Parameter                                | Type                      | Default                          | Notes                                                                    |
|------------------------------------------|---------------------------|----------------------------------|--------------------------------------------------------------------------|
| `attachment_allowed_extensions`          | `frozenset[str] \| None`  | `None` (blacklist mode)          | Override allowed extensions (whitelist mode). `None` uses blocked list.  |
| `attachment_blocked_extensions`          | `frozenset[str] \| None`  | OS-specific dangerous extensions | Override blocked extensions. `None` uses conf default.                   |
| `attachment_allowed_directories`         | `frozenset[Path] \| None` | `None` (blacklist mode)          | Override allowed directories (whitelist mode). `None` uses blocked list. |
| `attachment_blocked_directories`         | `frozenset[Path] \| None` | OS-specific sensitive dirs       | Override blocked directories. `None` uses conf default.                  |
| `attachment_max_size_bytes`              | `int \| None`             | `26_214_400` (25 MiB)            | Override max attachment size. `None` uses conf default.                  |
| `attachment_allow_symlinks`              | `bool \| None`            | `False`                          | Override symlink policy. `None` uses conf default.                       |
| `attachment_raise_on_security_violation` | `bool \| None`            | `True`                           | Override security violation behaviour. `None` uses conf default.         |

#### Default Blocked Extensions

**POSIX (Linux/macOS):**
```
.sh, .bash, .zsh, .ksh, .csh, .py, .pyw, .pyc, .pyo, .pl, .pm, .rb, .php,
.js, .mjs, .cjs, .so, .dylib, .bin, .run, .appimage, .elf, .out,
.jar, .war, .ear, .deb, .rpm, .apk
```

**Windows:**
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
```
/.ssh/, /id_rsa, /id_ed25519, /id_ecdsa, /authorized_keys, /known_hosts,
/.gnupg/, /private.key, /secret, /.env, /credentials, /password, /token,
/.aws/credentials, /.kube/config
```

**Raises:**

- `ValueError`  -  after validation if no valid recipients remain.
- `FileNotFoundError`  -  when a required attachment is missing and
  `raise_on_missing_attachments` is `True`.
- `AttachmentSecurityError`  -  when an attachment violates security policies and
  `attachment_raise_on_security_violation` is `True`.
- `RuntimeError`  -  when every configured host fails for a recipient (the error
  lists recipients and host roster).

