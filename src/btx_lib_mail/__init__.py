"""Public package surface exposing greeting, failure, and metadata hooks."""

from __future__ import annotations

from .behaviors import (
    CANONICAL_GREETING,
    emit_greeting,
    noop_main,
    raise_intentional_failure,
)
from .lib_mail import ConfMail, conf, logger, send, validate_email_address, validate_smtp_host
from .__init__conf__ import print_info

__all__ = [
    "CANONICAL_GREETING",
    "emit_greeting",
    "noop_main",
    "print_info",
    "raise_intentional_failure",
    "ConfMail",
    "conf",
    "send",
    "logger",
    "validate_email_address",
    "validate_smtp_host",
]
