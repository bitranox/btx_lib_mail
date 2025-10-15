# Feature Documentation: CLI Behavior Scaffold

## Status

Complete

## Links & References
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

## Problem Statement

The original scaffold concentrated the greeting, failure trigger, and CLI
orchestration inside a single module, making it harder to explain module intent
and to guarantee that the console script and ``python -m`` execution paths stay
behaviourally identical. We needed clearer module boundaries and shared helpers
for traceback preferences without introducing the full domain/application
separation that would be overkill for this minimal template.

## Solution Overview

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

## Architecture Integration

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

## Core Components

### behaviors.emit_greeting

* **Purpose:** Write the canonical greeting used in smoke tests and
  documentation.
* **Input:** Optional text stream (defaults to ``sys.stdout``).
* **Output:** Writes ``"Hello World\n"`` to the stream and flushes if possible.
* **Location:** src/btx_lib_mail/behaviors.py

### behaviors.raise_intentional_failure

* **Purpose:** Provide a deterministic failure hook for error-handling tests.
* **Input:** None.
* **Output:** Raises ``RuntimeError('I should fail')``.
* **Location:** src/btx_lib_mail/behaviors.py

### behaviors.noop_main

* **Purpose:** Placeholder entry for transports expecting a ``main`` callable.
* **Input:** None.
* **Output:** Returns ``None``.
* **Location:** src/btx_lib_mail/behaviors.py

### cli.apply_traceback_preferences

* **Purpose:** Synchronise traceback configuration between the CLI and ``python -m`` paths.
* **Input:** Boolean flag enabling rich tracebacks.
* **Output:** Updates ``lib_cli_exit_tools.config.traceback`` and
  ``traceback_force_color``.
* **Location:** src/btx_lib_mail/cli.py

### cli.main

* **Purpose:** Execute the click command group with shared exit handling.
* **Input:** Optional argv, restore flag, summary and verbose limits.
* **Output:** Integer exit code (0 on success, mapped error codes otherwise).
* **Location:** src/btx_lib_mail/cli.py

### cli._record_traceback_choice / cli._announce_traceback_choice / cli._traceback_option_requested

* **Purpose:** Persist the selected traceback mode in both the Click context and
  ``lib_cli_exit_tools`` while exposing a predicate that tells whether the user
  explicitly provided the option.
* **Input:** Click context plus the boolean flag derived from CLI options.
* **Output:** None (mutates context and ``lib_cli_exit_tools.config``) and a
  boolean value from ``_traceback_option_requested``.
* **Location:** src/btx_lib_mail/cli.py

### cli._invoke_cli / cli._current_traceback_mode / cli._traceback_limit / cli._print_exception / cli._run_cli_via_exit_tools / cli._show_help

* **Purpose:** Delegate execution to ``lib_cli_exit_tools`` while deciding how
  to present tracebacks and when to show command help for bare invocations.
* **Input:** Global configuration flags, configured length limits, optional
  argv, and the Click context used for help rendering.
* **Output:** Either a boolean flag, an integer limit, a rendered help screen,
  or the exit code produced by ``lib_cli_exit_tools``.
* **Location:** src/btx_lib_mail/cli.py

### __main__._module_main

* **Purpose:** Provide ``python -m`` entry point mirroring the console script.
* **Input:** None.
* **Output:** Exit code from ``cli.main`` after restoring traceback state.
* **Location:** src/btx_lib_mail/__main__.py

### __main__._open_cli_session / _command_to_run / _command_name

* **Purpose:** Describe the session wiring and command selection used by the
  module entry point so tests and documentation can reason about the
  composition.
* **Output:** Context manager yielding the command runner, the Click command
  itself, and the shell-facing name.
* **Location:** src/btx_lib_mail/__main__.py

### __init__conf__.print_info

* **Purpose:** Render the statically-defined project metadata for the CLI ``info`` command.
* **Input:** None.
* **Output:** Writes the hard-coded metadata block to ``stdout``.
* **Location:** src/btx_lib_mail/__init__conf__.py

### Package Exports

* ``__init__.py`` re-exports behaviour helpers and ``print_info`` for library
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
