"""## btx_lib_mail.behaviors {#module-btx-lib-mail-behaviors}

**Purpose:** Gather the domain-placeholder helpers that back the CLI scaffold so
each behaviour has a single, well-documented home. Keeping the trio together
lets adapter layers evolve without rewriting domain stubs.

**Contents:**
- `emit_greeting` — success-path helper that emits the canonical message.
- `raise_intentional_failure` — deterministic failure hook for exercising error paths.
- `noop_main` — placeholder entry point for transports expecting a `main`.

**System Role:** Described in
`docs/systemdesign/module_reference.md#feature-cli-behavior-scaffold`; this
module represents the current domain surface for the template while richer
features incubate elsewhere.
"""

from __future__ import annotations

from typing import Final, TextIO

import sys


CANONICAL_GREETING: Final[str] = "Hello World"
"""Canonical greeting line shared across CLI and smoke tests."""


def _target_stream(preferred: TextIO | None) -> TextIO:
    """Return the stream that should hear the greeting."""

    return preferred if preferred is not None else sys.stdout


def _greeting_line() -> str:
    """Return the greeting exactly as it should appear."""

    return f"{CANONICAL_GREETING}\n"


def _flush_if_possible(stream: TextIO) -> None:
    """Flush the stream when the stream knows how to flush."""

    flush = getattr(stream, "flush", None)
    if callable(flush):
        flush()


def emit_greeting(*, stream: TextIO | None = None) -> None:
    """### emit_greeting(stream: TextIO | None = None) {#behaviors-emit-greeting}

    **Purpose:** Offer a deterministic success story that documentation, tests,
    and CLI commands can reuse while the real domain behaviour is still under
    construction.

    **What:** Writes `CANONICAL_GREETING` followed by a newline to the selected
    text stream and flushes the stream when a `flush` method exists.

    **Parameters:**
    - `stream: TextIO | None = None` — Optional destination. When `None`, the
      helper targets `sys.stdout`.

    **Returns:** `None`.

    **Raises:** No new exceptions are raised; any stream failures bubble up.

    **Example:**
    >>> from io import StringIO
    >>> buffer = StringIO()
    >>> emit_greeting(stream=buffer)
    >>> buffer.getvalue()
    'Hello World\\n'
    """

    target = _target_stream(stream)
    target.write(_greeting_line())
    _flush_if_possible(target)


def raise_intentional_failure() -> None:
    """### raise_intentional_failure() {#behaviors-raise-intentional-failure}

    **Purpose:** Provide a guaranteed failure hook so transports and tests can
    assert traceback and exit-code behaviour without introducing ad-hoc errors.

    **What:** Always raises `RuntimeError('I should fail')`.

    **Parameters:** None.

    **Returns:** This helper never returns.

    **Raises:** `RuntimeError` — unconditionally, with the canonical message.

    **Example:**
    >>> try:
    ...     raise_intentional_failure()
    ... except RuntimeError as exc:
    ...     exc.args[0]
    'I should fail'
    """

    raise RuntimeError("I should fail")


def noop_main() -> None:
    """### noop_main() {#behaviors-noop-main}

    **Purpose:** Honour tooling contracts that expect a `main` callable even
    while the real domain implementation is pending.

    **What:** Performs no work and returns immediately so callers can treat the
    placeholder as a benign default.

    **Parameters:** None.

    **Returns:** `None`.

    **Raises:** No exceptions.

    **Example:**
    >>> noop_main() is None
    True
    """

    return None


__all__ = [
    "CANONICAL_GREETING",
    "emit_greeting",
    "raise_intentional_failure",
    "noop_main",
]
