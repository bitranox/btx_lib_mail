# Feature Documentation: CLI Behavior Scaffold {#feature-cli-behavior-scaffold}

## Status {#feature-cli-status}

Complete

## Links & References {#feature-cli-links}
**Feature Requirements:** Scaffold requirements (ad-hoc)
**Task/Ticket:** None documented
**Pull Requests:** Pending current refactor
**Related Files:**

* src/btx_lib_mail/behaviors.py
* src/btx_lib_mail/cli.py
* src/btx_lib_mail/__main__.py
* src/btx_lib_mail/__init__.py
* src/btx_lib_mail/__init__conf__.py
* tests/test_cli.py
* tests/test_module_entry.py
* tests/test_behaviors.py
* tests/test_scripts.py

---

## Problem Statement {#feature-cli-problem}

The original scaffold concentrated the greeting, failure trigger, and CLI
orchestration inside a single module, making it harder to explain module intent
and to guarantee that the console script and ``python -m`` execution paths stay
behaviourally identical. We needed clearer module boundaries and shared helpers
for traceback preferences without introducing the full domain/application
separation that would be overkill for this minimal template.

## Solution Overview {#feature-cli-solution}

* Extracted the behaviour helpers into ``behaviors.py`` so both CLI and library
  consumers have a single cohesive module documenting the temporary domain.
* Simplified ``cli.py`` to import the behaviour helpers, added explicit
  functions for applying and restoring traceback preferences, and centralised
  the exit-code handling used by both entry points.
* Reduced ``__main__.py`` to a thin wrapper delegating to the CLI helper while
  sharing the same traceback state restoration helpers.
* Re-exported the helpers through ``__init__.py`` so CLI and library imports
  draw from the same source.
* Documented the responsibilities in this module reference so future refactors
  have an authoritative baseline.

---

## Architecture Integration {#feature-cli-architecture}

**App Layer Fit:** This package remains a CLI-first utility; all modules live in
the transport/adapter layer, with ``behaviors.py`` representing the small
stand-in domain.

**Data Flow:**
1. CLI parses options with rich-click.
2. Traceback preferences are applied via ``apply_traceback_preferences``.
3. Commands delegate to behaviour helpers.
4. Exit codes and tracebacks are rendered by ``lib_cli_exit_tools``.

**System Dependencies:**
* ``rich_click`` for CLI UX
* ``lib_cli_exit_tools`` for exit-code normalisation and traceback output
* ``importlib.metadata`` via ``__init__conf__`` to present package metadata

---

## Core Components {#feature-cli-components}

### behaviors.emit_greeting {#behaviors-emit-greeting}

* **Purpose:** Write the canonical greeting used in smoke tests and
  documentation.
* **Input:** Optional text stream (defaults to ``sys.stdout``).
* **Output:** Writes ``"Hello World\n"`` to the stream and flushes if possible.
* **Location:** src/btx_lib_mail/behaviors.py

### behaviors.raise_intentional_failure {#behaviors-raise-intentional-failure}

* **Purpose:** Provide a deterministic failure hook for error-handling tests.
* **Input:** None.
* **Output:** Raises ``RuntimeError('I should fail')``.
* **Location:** src/btx_lib_mail/behaviors.py

### behaviors.noop_main {#behaviors-noop-main}

* **Purpose:** Placeholder entry for transports expecting a ``main`` callable.
* **Input:** None.
* **Output:** Returns ``None``.
* **Location:** src/btx_lib_mail/behaviors.py

### cli.apply_traceback_preferences {#cli-apply-traceback-preferences}

* **Purpose:** Synchronise traceback configuration between the CLI and ``python -m`` paths.
* **Input:** Boolean flag enabling rich tracebacks.
* **Output:** Updates ``lib_cli_exit_tools.config.traceback`` and
  ``traceback_force_color``.
* **Location:** src/btx_lib_mail/cli.py

### cli.main {#cli-main}

* **Purpose:** Execute the click command group with shared exit handling.
* **Input:** Optional argv, restore flag, summary and verbose limits.
* **Output:** Integer exit code (0 on success, mapped error codes otherwise).
* **Location:** src/btx_lib_mail/cli.py

### cli._record_traceback_choice / cli._announce_traceback_choice / cli._traceback_option_requested {#cli-traceback-management}

* **Purpose:** Persist the selected traceback mode in both the Click context and
  ``lib_cli_exit_tools`` while exposing a predicate that tells whether the user
  explicitly provided the option.
* **Input:** Click context plus the boolean flag derived from CLI options.
* **Output:** None (mutates context and ``lib_cli_exit_tools.config``) and a
  boolean value from ``_traceback_option_requested``.
* **Location:** src/btx_lib_mail/cli.py

### cli._invoke_cli / cli._current_traceback_mode / cli._traceback_limit / cli._print_exception / cli._run_cli_via_exit_tools / cli._show_help {#cli-infrastructure}

* **Purpose:** Delegate execution to ``lib_cli_exit_tools`` while deciding how
  to present tracebacks and when to show command help for bare invocations.
* **Input:** Global configuration flags, configured length limits, optional
  argv, and the Click context used for help rendering.
* **Output:** Either a boolean flag, an integer limit, a rendered help screen,
  or the exit code produced by ``lib_cli_exit_tools``.
* **Location:** src/btx_lib_mail/cli.py

### cli.cli_send_mail {#cli-cli-send-mail}

* **Purpose:** Expose the ``send`` CLI surface for :func:`btx_lib_mail.lib_mail.send`,
  enabling engineers to smoke-test SMTP setups without writing bespoke
  scripts.
* **Input:** ``send`` command options ``--host``, ``--recipient``, ``--sender``,
  ``--subject``, ``--body``, ``--html-body``, ``--attachment``,
  ``--starttls``, ``--username``, ``--password``, and ``--timeout``. Falls back to
  ``BTX_MAIL_SMTP_HOSTS``, ``BTX_MAIL_RECIPIENTS``, ``BTX_MAIL_SENDER``,
  ``BTX_MAIL_SMTP_USE_STARTTLS``, ``BTX_MAIL_SMTP_USERNAME``,
  ``BTX_MAIL_SMTP_PASSWORD``, and ``BTX_MAIL_SMTP_TIMEOUT`` environment variables
  (or a local ``.env``) when CLI values are omitted. Precedence: CLI options →
  environment variables → `.env` entries → :data:`btx_lib_mail.lib_mail.conf`.
* **Output:** Delegates to :func:`send` and echoes a summary line upon success;
  exceptions from :func:`send` bubble up to the shared error handlers.
* **Location:** src/btx_lib_mail/cli.py

### cli.cli_validate_email {#cli-cli-validate-email}

* **Purpose:** CLI subcommand that validates a single email address via
  :func:`validate_email_address` and echoes a confirmation on success.
* **Input:** Positional ``ADDRESS`` argument.
* **Output:** Echoes ``"Valid email address: ..."`` on success; raises
  ``ValueError`` on invalid input.
* **Location:** src/btx_lib_mail/cli.py

### cli.cli_validate_smtp_host {#cli-cli-validate-smtp-host}

* **Purpose:** CLI subcommand that validates a single SMTP host string via
  :func:`validate_smtp_host` and echoes a confirmation on success.
* **Input:** Positional ``HOST`` argument.
* **Output:** Echoes ``"Valid SMTP host: ..."`` on success; raises
  ``ValueError`` on invalid input.
* **Location:** src/btx_lib_mail/cli.py

### lib_mail.ConfMail {#lib-mail-confmail}

* **Purpose:** Declarative configuration (via Pydantic) for outbound SMTP
  delivery, consolidating host lists, attachment policies, and security
  options.
* **Input:** Accepts strings, lists, or tuples for ``smtphosts``; optional
  ``smtp_username``/``smtp_password`` credentials; ``smtp_use_starttls`` toggle
  (defaults to ``True``); ``smtp_timeout`` value (defaults to ``30.0`` seconds);
  policy flags for attachment and recipient validation.
* **Output:** Provides normalised configuration through methods such as
  :meth:`resolved_credentials`, enabling the send helper to consume consistent
  data regardless of input form.
* **Location:** src/btx_lib_mail/lib_mail.py

### lib_mail.send

* **Purpose:** Deliver multipart UTF-8 e-mails with optional HTML and
  attachments, iterating over configured SMTP hosts until delivery succeeds or
  all hosts fail.
* **Input:** Sender, recipients, subject/body content, optional HTML body,
  optional attachment paths, and runtime overrides for credentials,
  STARTTLS usage, and socket timeout.
* **Output:** Returns ``True`` after a successful delivery; raises
  ``RuntimeError`` listing undelivered recipients when every host fails.
* **Additional Behaviour:**
  - Uses ``ConfMail`` defaults when per-call overrides are not provided
    (STARTTLS is enabled by default and may be disabled explicitly when needed).
  - Performs STARTTLS when configured and authenticates with supplied
    credentials.
  - Logs failed host attempts at WARNING level and ensures connections are
    closed via context managers.
* **Location:** src/btx_lib_mail/lib_mail.py

### __main__._module_main {#module-main-module-main}

* **Purpose:** Provide ``python -m`` entry point mirroring the console script.
* **Input:** None.
* **Output:** Exit code from ``cli.main`` after restoring traceback state.
* **Location:** src/btx_lib_mail/__main__.py

### __main__._open_cli_session / _command_to_run / _command_name {#module-main-session-helpers}

* **Purpose:** Describe the session wiring and command selection used by the
  module entry point so tests and documentation can reason about the
  composition.
* **Output:** Context manager yielding the command runner, the Click command
  itself, and the shell-facing name.
* **Location:** src/btx_lib_mail/__main__.py

### __init__conf__.print_info {#init-conf-print-info}

* **Purpose:** Render the statically-defined project metadata for the CLI ``info`` command.
* **Input:** None.
* **Output:** Writes the hard-coded metadata block to ``stdout``.
* **Location:** src/btx_lib_mail/__init__conf__.py

### Package Exports {#package-exports-cli}

* ``__init__.py`` re-exports behaviour helpers and ``print_info`` for library
  consumers while hiding adapter wiring.

---

# Feature Documentation: Mail Delivery Helpers {#feature-mail-delivery-helpers}

## Status {#feature-mail-status}

Complete

## Links & References {#feature-mail-links}
**Feature Requirements:** Internal SMTP helper expansion
**Task/Ticket:** None documented
**Pull Requests:** Pending current refactor
**Related Files:**

* src/btx_lib_mail/lib_mail.py
* tests/test_lib_mail.py

---

## Problem Statement {#feature-mail-problem}

The project needed a reusable SMTP helper capable of iterating through multiple
hosts, handling optional STARTTLS and authentication, validating recipients, and
packaging attachments—all without leaking transport details into callers or the
CLI. Earlier iterations relied on list utility helpers and scattered logic.

## Solution Overview {#feature-mail-solution}

* Introduced immutable value objects (:class:`AttachmentPayload`,
  :class:`DeliveryOptions`) to separate preparation from SMTP orchestration.
* Replaced the external list utility dependency with explicit normalisers that
  keep intent obvious.
* Broke the delivery pipeline into small helpers (`_prepare_*`, `_deliver_*`,
  `_compose_message`) so each step reads like prose.
* Ensured validation and logging behave consistently whether invoked via CLI or
  directly from library code.

---

## Architecture Integration {#feature-mail-architecture}

**App Layer Fit:** ``lib_mail`` sits in the adapter layer, translating validated
inputs into SMTP side effects.

**Data Flow:**
1. Callers populate :data:`conf` or pass explicit overrides.
2. :func:`send` prepares recipients, hosts, attachments, and delivery options.
3. Each recipient is attempted across the host list via ``_deliver_to_any_host``.
4. ``_deliver_via_host`` composes the MIME message and sends it over SMTP.

**System Dependencies:**
* ``smtplib`` for SMTP interactions
* ``ssl`` for STARTTLS contexts
* ``pydantic`` for configuration validation

---

## Core Components {#feature-mail-components}

### lib_mail.AttachmentPayload {#lib-mail-attachmentpayload}

* **Purpose:** Preserve attachment filename and bytes together for MIME encoding.
* **Fields:** ``filename`` (``str``), ``content`` (``bytes``).
* **Location:** src/btx_lib_mail/lib_mail.py

### lib_mail.DeliveryOptions {#lib-mail-deliveryoptions}

* **Purpose:** Freeze delivery knobs (credentials, STARTTLS flag, timeout) once.
* **Fields:** ``credentials`` (``tuple[str, str] | None``), ``use_starttls`` (``bool``), ``timeout`` (``float``).
* **Location:** src/btx_lib_mail/lib_mail.py

### lib_mail.conf {#lib-mail-conf}

* **Purpose:** Global configuration instance shared across adapters.
* **Behaviour:** Values may be set directly or populated via CLI precedence
  (CLI args → env vars → `.env` → defaults).
* **Type:** :class:`ConfMail`.
* **Location:** src/btx_lib_mail/lib_mail.py

### lib_mail._resolve_delivery_options {#lib-mail-resolve-delivery-options}

* **Purpose:** Merge per-call overrides with :data:`conf` defaults.
* **Inputs:** Optional credentials, STARTTLS flag, timeout.
* **Output:** :class:`DeliveryOptions`.
* **Location:** src/btx_lib_mail/lib_mail.py

### lib_mail._prepare_recipients {#lib-mail-prepare-recipients}

* **Purpose:** Strip, deduplicate, lower-case, and validate recipient emails.
* **Inputs:** ``str`` or ``Sequence[str]``.
* **Output:** ``tuple[str, ...]``.
* **Location:** src/btx_lib_mail/lib_mail.py

### lib_mail._prepare_hosts {#lib-mail-prepare-hosts}

* **Purpose:** Normalise host strings and remove duplicates/empties.
* **Inputs:** ``tuple[str, ...]``.
* **Output:** ``tuple[str, ...]``.
* **Location:** src/btx_lib_mail/lib_mail.py

### lib_mail._prepare_attachments {#lib-mail-prepare-attachments}

* **Purpose:** Resolve file paths, read bytes, and create attachment payloads.
* **Inputs:** ``tuple[pathlib.Path, ...]``.
* **Output:** ``tuple[AttachmentPayload, ...]``.
* **Location:** src/btx_lib_mail/lib_mail.py

### lib_mail._deliver_to_any_host {#lib-mail-deliver-to-any-host}

* **Purpose:** Iterate over hosts until delivery succeeds.
* **Inputs:** Sender, recipient, content, host tuple, attachments, delivery options.
* **Output:** ``bool`` (success flag).
* **Location:** src/btx_lib_mail/lib_mail.py

### lib_mail._deliver_via_host {#lib-mail-deliver-via-host}

* **Purpose:** Manage SMTP session lifecycle for a single host.
* **Inputs:** Host string, sender/recipient/content, attachments, delivery options.
* **Output:** ``None`` (raises on failure).
* **Location:** src/btx_lib_mail/lib_mail.py

### lib_mail._compose_message {#lib-mail-compose-message}

* **Purpose:** Build a multipart MIME message string with optional HTML and attachments.
* **Inputs:** Sender, recipient, subject, bodies, attachments.
* **Output:** ``str``.
* **Location:** src/btx_lib_mail/lib_mail.py

### lib_mail._render_attachment {#lib-mail-render-attachment}

* **Purpose:** Encode an :class:`AttachmentPayload` as a MIME part.
* **Inputs:** :class:`AttachmentPayload`.
* **Output:** :class:`email.mime.base.MIMEBase`.
* **Location:** src/btx_lib_mail/lib_mail.py

### lib_mail._normalise_email_address {#lib-mail-normalise-email}

* **Purpose:** Trim whitespace/quotes and lower-case email candidates.
* **Inputs:** ``str``.
* **Output:** ``str``.
* **Location:** src/btx_lib_mail/lib_mail.py

### lib_mail._normalise_host {#lib-mail-normalise-host}

* **Purpose:** Strip whitespace/quotes from host entries.
* **Inputs:** ``str``.
* **Output:** ``str``.
* **Location:** src/btx_lib_mail/lib_mail.py

### lib_mail._collect_host_inputs {#lib-mail-collect-host-inputs}

* **Purpose:** Accept ``None``, strings, or iterables and return a host list.
* **Inputs:** ``Any``.
* **Output:** ``list[str]``.
* **Location:** src/btx_lib_mail/lib_mail.py

### lib_mail.validate_email_address {#lib-mail-validate-email-address}

* **Purpose:** Raise ``ValueError`` when the address does not match ``EMAIL_PATTERN``.
* **Inputs:** ``str``.
* **Output:** ``None`` (raises on invalid input).
* **Location:** src/btx_lib_mail/lib_mail.py

### lib_mail.validate_smtp_host {#lib-mail-validate-smtp-host}

* **Purpose:** Raise ``ValueError`` when the host string is not a valid SMTP
  host, including IPv6 bracketed addresses (``[::1]:25``).
* **Inputs:** ``str``.
* **Output:** ``None`` (raises on invalid input).
* **Location:** src/btx_lib_mail/lib_mail.py

### lib_mail._parse_smtp_host {#lib-mail-parse-smtp-host}

* **Purpose:** Validate and split an SMTP host string into hostname and port.
  Strips IPv6 brackets so ``smtplib.SMTP`` receives a bare address.
* **Inputs:** ``str``.
* **Output:** ``tuple[str, int | None]``.
* **Location:** src/btx_lib_mail/lib_mail.py

---
  consumers. No legacy compatibility layer remains; new code should import from
  the canonical module paths.

---

## Implementation Details

**Dependencies:**

* External: ``rich_click``, ``lib_cli_exit_tools``
* Internal: ``behaviors`` module, ``__init__conf__`` static metadata constants

**Key Configuration:**

* No environment variables required.
* Traceback preferences controlled via CLI ``--traceback`` flag.

**Database Changes:**

* None.

**Error Handling Strategy:**

* ``lib_cli_exit_tools`` centralises exception rendering.
* ``apply_traceback_preferences`` ensures colour output for ``--traceback``.
* ``restore_traceback_state`` restores previous preferences after each run.

---

## Testing Approach

**Manual Testing Steps:**

1. ``btx_lib_mail`` → prints CLI help (no default action).
2. ``btx_lib_mail hello`` → prints greeting.
3. ``btx_lib_mail fail`` → prints truncated traceback.
4. ``btx_lib_mail --traceback fail`` → prints full rich traceback.
5. ``python -m btx_lib_mail --traceback fail`` → matches console output.

**Automated Tests:**

* ``tests/test_cli.py`` exercises the help-first behaviour, failure path,
  metadata output, and invalid command handling for the click surface.
* ``tests/test_module_entry.py`` ensures ``python -m`` entry mirrors the console
  script, including traceback behaviour.
* ``tests/test_behaviors.py`` verifies greeting/failure helpers against custom
  streams.
* ``tests/test_scripts.py`` validates the automation entry points via the shared
  scripts CLI.
* ``tests/test_cli.py`` and ``tests/test_module_entry.py`` now introduce
  structured recording helpers (``CapturedRun`` and ``PrintedTraceback``) so the
  assertions read like documented scenarios.
* Doctests embedded in behaviour and CLI helpers provide micro-regression tests
  for argument handling.

**Edge Cases:**

* Running without subcommand delegates to ``noop_main`` (no output).
* Repeated invocations respect previous traceback preference thanks to
  restoration helpers.

**Test Data:**

* No fixtures required; tests rely on built-in `CliRunner` and monkeypatching.

---

## Known Issues & Future Improvements

**Current Limitations:**

* Behaviour module still contains placeholder logic; real logging helpers will
  replace it in future iterations.

**Future Enhancements:**

* Introduce structured logging once the logging stack lands.
* Expand the module reference when new commands or behaviours are added.

---

## Risks & Considerations

**Technical Risks:**

* Traceback behaviour depends on ``lib_cli_exit_tools``; upstream changes may
  require adjustments to the helper functions.

**User Impact:**

* None expected; CLI surface and public imports remain backward compatible.

---

## Documentation & Resources

**Internal References:**

* README.md – usage examples
* INSTALL.md – installation options
* DEVELOPMENT.md – developer workflow

**External References:**

* rich-click documentation
* lib_cli_exit_tools project README

---

**Created:** 2025-09-26 by Codex (automation)
**Last Updated:** 2025-09-26 by Codex
**Review Cycle:** Evaluate during next logging feature milestone

---

## Instructions for Use

1. Trigger this document whenever CLI behaviour helpers change.
2. Keep module descriptions in sync with code during future refactors.
3. Extend with new components when additional commands or behaviours ship.
