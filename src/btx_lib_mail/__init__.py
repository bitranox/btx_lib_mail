"""Public package surface exposing greeting, failure, and metadata hooks."""

from __future__ import annotations

from .__init__conf__ import print_info
from .behaviors import (
    CANONICAL_GREETING,
    emit_greeting,
    noop_main,
    raise_intentional_failure,
)
from .lib_mail import (
    DANGEROUS_DIRECTORIES_POSIX,
    DANGEROUS_DIRECTORIES_WINDOWS,
    DANGEROUS_EXTENSIONS_POSIX,
    DANGEROUS_EXTENSIONS_WINDOWS,
    SENSITIVE_PATH_PATTERNS,
    AttachmentSecurityError,
    AttachmentViolation,
    ConfMail,
    conf,
    logger,
    send,
    validate_email_address,
    validate_smtp_host,
)
from .secret_safety import REDACTED_INPUT, SecretSafeModel, redact_validation_error

__all__ = [
    "CANONICAL_GREETING",
    "DANGEROUS_DIRECTORIES_POSIX",
    "DANGEROUS_DIRECTORIES_WINDOWS",
    "DANGEROUS_EXTENSIONS_POSIX",
    "DANGEROUS_EXTENSIONS_WINDOWS",
    "REDACTED_INPUT",
    "SENSITIVE_PATH_PATTERNS",
    "AttachmentSecurityError",
    "AttachmentViolation",
    "ConfMail",
    "SecretSafeModel",
    "conf",
    "emit_greeting",
    "logger",
    "noop_main",
    "print_info",
    "raise_intentional_failure",
    "redact_validation_error",
    "send",
    "validate_email_address",
    "validate_smtp_host",
]
