"""Public package surface exposing greeting, failure, and metadata hooks."""

from __future__ import annotations

from .behaviors import (
    CANONICAL_GREETING,
    emit_greeting,
    noop_main,
    raise_intentional_failure,
)
from .__init__conf__ import print_info

__all__ = [
    "CANONICAL_GREETING",
    "emit_greeting",
    "noop_main",
    "print_info",
    "raise_intentional_failure",
]
