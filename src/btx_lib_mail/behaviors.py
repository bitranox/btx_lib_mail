"""Gather the domain-placeholder helpers that back the CLI scaffold.

Keeping the trio together lets adapter layers evolve without rewriting
domain stubs, and gives each behaviour a single, well-documented home.

Contents:
    - `emit_greeting` - success-path helper that emits the canonical message.
    - `raise_intentional_failure` - deterministic failure hook for exercising error paths.
    - `noop_main` - placeholder entry point for transports expecting a `main`.

Described in `docs/systemdesign/module_reference.md#behaviour-scaffold`; this
module represents the current domain surface for the template while richer
features incubate elsewhere.
"""

from __future__ import annotations

import sys
from typing import Final, TextIO

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
    r"""Write the canonical greeting to a text stream.

    Offers a deterministic success story that documentation, tests, and CLI
    commands can reuse while the real domain behaviour is still under
    construction. Writes `CANONICAL_GREETING` followed by a newline to the
    selected text stream and flushes the stream when a `flush` method
    exists.

    Args:
        stream: Optional destination. When `None`, the helper targets `sys.stdout`.

    Returns:
        None.

    Raises:
        None: no new exceptions are raised; any stream failures bubble up.

    Examples:
        >>> from io import StringIO
        >>> buffer = StringIO()
        >>> emit_greeting(stream=buffer)
        >>> buffer.getvalue()
        'Hello World\n'
    """
    target = _target_stream(stream)
    target.write(_greeting_line())
    _flush_if_possible(target)


def raise_intentional_failure() -> None:
    """Raise a guaranteed failure for exercising error paths.

    Provides a guaranteed failure hook so transports and tests can assert
    traceback and exit-code behaviour without introducing ad-hoc errors.
    Always raises `RuntimeError('I should fail')`; this helper never
    returns.

    Raises:
        RuntimeError: Unconditionally, with the canonical message.

    Examples:
        >>> try:
        ...     raise_intentional_failure()
        ... except RuntimeError as exc:
        ...     exc.args[0]
        'I should fail'
    """
    raise RuntimeError("I should fail")


def noop_main() -> None:
    """Do nothing, honouring tooling contracts that expect a `main` callable.

    Performs no work and returns immediately so callers can treat the
    placeholder as a benign default while the real domain implementation is
    pending.

    Returns:
        None.

    Examples:
        >>> noop_main() is None
        True
    """
    return None


__all__ = [
    "CANONICAL_GREETING",
    "emit_greeting",
    "noop_main",
    "raise_intentional_failure",
]
