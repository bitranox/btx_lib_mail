"""Credential-safe validation errors for pydantic models that hold secrets.

A pydantic ``ValidationError`` records the raw input of every failing
validator. For a model that holds a password that input is the password (a
wrongly typed value) or the whole input mapping (a model-level validator), and
``hide_input_in_errors`` hides it only from ``str()``, not from ``errors()`` or
``json()``. ``SecretSafeModel`` wraps its whole validation schema so every error
raised while validating it is rebuilt with those inputs replaced.

Two errors are raised before any hook of the model runs, so they are NOT
covered: malformed JSON handed to ``TypeAdapter(Model).validate_json``, and
malformed JSON handed to ``model_validate_json`` of a plain (non-secret-safe)
model that nests a ``SecretSafeModel``. The JSON parser fails first, and its
``json_invalid`` error carries the whole JSON text as its input.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterator, Mapping
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from enum import Enum
from typing import TYPE_CHECKING, Any, ClassVar, Final, cast, get_args

from pydantic import AliasChoices, AliasPath, BaseModel, ConfigDict, ValidationError
from pydantic_core import InitErrorDetails, PydanticCustomError, core_schema

if TYPE_CHECKING:
    from pydantic import GetCoreSchemaHandler
    from pydantic_core import CoreSchema, ErrorDetails
    from typing_extensions import LiteralString

REDACTED_INPUT: Final[str] = "[redacted]"
"""Stand-in for an error input that could carry a credential."""

# An input is shown only when it is one of these scalars; anything else (a
# mapping, a model, a dataclass, a deque, a dict view, any object) can hold a
# credential somewhere inside it, so it is hidden.
_SHOWN_INPUT_TYPES: Final = (str, bytes, int, float, bool, type(None), Decimal, date, datetime, time, timedelta, Enum)

# An unexpected key is often a misspelled credential name (pasword=...), so the
# value under it is hidden whatever the key is called.
_ALWAYS_HIDDEN_TYPES: Final[frozenset[str]] = frozenset({"extra_forbidden"})

# from_exception_data accepts only pydantic's own error types by name.
_KNOWN_ERROR_TYPES: Final[frozenset[str]] = frozenset(get_args(core_schema.ErrorType))

# A text shorter than this is scrubbed from a message only where it stands
# alone, so a one-letter value does not shred every word holding that letter.
_MIN_FREE_TEXT: Final = 4

# Bounds on the walk over an input when collecting the texts to scrub; an input
# larger than this cannot be proven absent from a message, so the message is hidden.
_MAX_TEXT_DEPTH: Final = 8
_MAX_TEXTS: Final = 1000

_FAILED_TITLE: Final = "ValidationError"
_FAILED_TYPE: Final = "redacted_error"
_FAILED_MESSAGE: Final = "validation failed; the details could not be redacted and were dropped"


class _UnprovableError(Exception):
    """An input too large or too deep to prove absent from a message."""


def _must_hide(error: ErrorDetails, hidden_locations: frozenset[str]) -> bool:
    location = error["loc"]
    if not location or error["type"] in _ALWAYS_HIDDEN_TYPES or str(location[0]) in hidden_locations:
        return True
    return not isinstance(error["input"], _SHOWN_INPUT_TYPES)


def _children(value: object) -> Iterator[object]:
    if isinstance(value, Mapping):
        yield from cast("Mapping[object, object]", value).values()
    elif isinstance(value, Collection):
        yield from cast("Collection[object]", value)
    else:
        yield from vars(value).values() if hasattr(value, "__dict__") else ()


def _own_texts(value: object) -> tuple[str, ...]:
    # A collection's text is made of its members' texts; any other object may
    # render a secret itself (a dataclass repr), so its own text is scrubbed too.
    return () if isinstance(value, Collection) else (str(value),)


def _input_texts(value: object) -> set[str]:
    """Collect the text of *value* and of every scalar reachable inside it."""
    texts: set[str] = set()
    pending: list[tuple[object, int]] = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        if len(texts) > _MAX_TEXTS or depth > _MAX_TEXT_DEPTH:
            raise _UnprovableError
        if isinstance(current, bool) or current is None:
            continue
        if isinstance(current, str):
            texts.add(current)
        elif isinstance(current, Enum):
            texts.add(str(current))
            pending.append((current.value, depth + 1))
        elif isinstance(current, (bytes, bytearray)):
            texts.add(bytes(current).decode("utf-8", "replace"))
        elif isinstance(current, (int, float, Decimal)):
            texts.add(str(current))
        else:
            texts.update(_own_texts(current))
            pending.extend((child, depth + 1) for child in _children(current))
    return texts


def _scrubbed(message: str, error_input: object) -> str:
    """Return *message* with every text of *error_input* replaced by ``REDACTED_INPUT``."""
    patterns = [
        re.escape(text) if len(text) >= _MIN_FREE_TEXT else rf"(?<![^\W_]){re.escape(text)}(?![^\W_])"
        for text in sorted(_input_texts(error_input), key=len, reverse=True)
        if text.strip()
    ]
    if not patterns:
        return message
    return re.sub("|".join(patterns), lambda _match: REDACTED_INPUT, message)


def _renders_as(detail: InitErrorDetails, error_type: str, message: str) -> bool:
    try:
        [probe] = ValidationError.from_exception_data(_FAILED_TITLE, [detail]).errors(include_url=False)
    except (TypeError, ValueError, KeyError):
        # A built-in type name without the ctx it requires, or an unknown name.
        return False
    return probe["type"] == error_type and probe["msg"] == message


def _faithful_detail(error: ErrorDetails, *, hide: bool) -> InitErrorDetails:
    error_type, location = error["type"], error["loc"]
    message = _scrubbed(error["msg"], error["input"]) if hide else error["msg"]
    error_input: Any = REDACTED_INPUT if hide else error["input"]
    # ctx can repeat the input (union_tag_invalid's ctx["tag"]), so a hidden error keeps none.
    context = None if hide else error.get("ctx")
    candidates: list[InitErrorDetails] = []
    if error_type in _KNOWN_ERROR_TYPES:
        # The built-in type keeps pydantic's documentation link; it is used only
        # when it renders exactly the message the original error carried.
        known: InitErrorDetails = {"type": error_type, "loc": location, "input": error_input}
        if context is not None:
            known["ctx"] = context
        candidates.append(known)
    # Type and message come from an error pydantic already built, not from a
    # caller-written template, so they are passed on as they are. Without a ctx
    # the message is used verbatim, so the last candidate always renders.
    literal_type, literal_message = cast("LiteralString", error_type), cast("LiteralString", message)
    if context is not None:
        candidates.append({"type": PydanticCustomError(literal_type, literal_message, context), "loc": location, "input": error_input})
    fallback: InitErrorDetails = {"type": PydanticCustomError(literal_type, literal_message), "loc": location, "input": error_input}
    return next((candidate for candidate in candidates if _renders_as(candidate, error_type, message)), fallback)


def _redacted_detail(error: ErrorDetails, hidden_locations: frozenset[str]) -> InitErrorDetails:
    try:
        return _faithful_detail(error, hide=_must_hide(error, hidden_locations))
    except Exception:
        # Fail closed: keep only the type and location, which pydantic produced.
        return {"type": PydanticCustomError(cast("LiteralString", str(error["type"])), REDACTED_INPUT), "loc": error["loc"], "input": REDACTED_INPUT}


def _failed_redaction() -> ValidationError:
    detail: InitErrorDetails = {"type": PydanticCustomError(_FAILED_TYPE, _FAILED_MESSAGE), "loc": (), "input": REDACTED_INPUT}
    return ValidationError.from_exception_data(_FAILED_TITLE, [detail], hide_input=True)


def redact_validation_error(exc: ValidationError, *, credential_fields: frozenset[str]) -> ValidationError:
    """Return a copy of *exc* whose errors cannot carry a credential.

    The rebuild never raises: an error it cannot rebuild faithfully keeps only
    its type and location, and if even that fails the result is one opaque
    ``redacted_error``.

    Args:
        exc: The error pydantic raised.
        credential_fields: Top-level locations whose input is always hidden:
            field names and every alias pydantic may report in ``loc``.

    Returns:
        A new ``ValidationError`` with the same title, types, locations and
        messages. An error's input is replaced by ``REDACTED_INPUT`` when it is
        model-level, an ``extra_forbidden`` error, at a credential location, or
        not a plain scalar (str, bytes, int, float, bool, None, Decimal, a date
        or time value, an Enum member). Such a hidden error also loses its
        ``ctx`` and has the input's text scrubbed from its message. Other
        errors keep their input and ctx.

    Examples:
        >>> from pydantic import BaseModel
        >>> class M(BaseModel):
        ...     password: str
        >>> try:
        ...     M(password=123)
        ... except ValidationError as caught:
        ...     redact_validation_error(caught, credential_fields=frozenset({"password"})).errors()[0]["input"]
        '[redacted]'
    """
    try:
        details = [_redacted_detail(error, credential_fields) for error in exc.errors(include_url=False)]
        return ValidationError.from_exception_data(exc.title, details, hide_input=True)
    except Exception:
        # Fail closed: nothing of the original survives.
        return _failed_redaction()


def _alias_names(alias: str | AliasPath | AliasChoices | None) -> frozenset[str]:
    if alias is None:
        return frozenset()
    if isinstance(alias, str):
        return frozenset({alias})
    if isinstance(alias, AliasPath):
        return frozenset({str(alias.path[0])})
    names: set[str] = set()
    for choice in alias.choices:
        names |= _alias_names(choice)
    return frozenset(names)


class SecretSafeModel(BaseModel):
    """Base for models holding credentials: their validation errors are redacted.

    Subclasses list their credential fields in ``credential_fields``; aliases of
    those fields are hidden too. The redaction wraps the model's whole core
    schema, so it covers field validation, validated assignment, model-level
    validators (a subclass's own included), ``model_validate``,
    ``model_validate_strings``, this model's own ``model_validate_json`` (also
    for malformed JSON), ``TypeAdapter(Model).validate_python``, and the errors
    raised while validating this model nested in a list or in another model.
    ``strict=`` and ``context=`` pass through unchanged.

    Not covered, because the JSON parser fails before this model is reached and
    its ``json_invalid`` error quotes the whole JSON text: malformed JSON handed
    to ``TypeAdapter(Model).validate_json``, or to ``model_validate_json`` of a
    plain outer model nesting this one.

    A model that NESTS a ``SecretSafeModel`` and has a model-level validator of
    its own must itself inherit this base and list the nested field, because its
    own model-level errors quote its own input.
    """

    model_config = ConfigDict(hide_input_in_errors=True)
    credential_fields: ClassVar[frozenset[str]] = frozenset()

    @classmethod
    def _hidden_locations(cls) -> frozenset[str]:
        hidden = set(cls.credential_fields)
        for name in cls.credential_fields:
            info = cls.model_fields.get(name)
            if info is not None:
                hidden |= _alias_names(info.alias) | _alias_names(info.validation_alias)
        return frozenset(hidden)

    @classmethod
    def __get_pydantic_core_schema__(cls, source: type[BaseModel], handler: GetCoreSchemaHandler) -> CoreSchema:
        schema = handler(source)

        def redact(value: Any, validate: core_schema.ValidatorFunctionWrapHandler) -> Any:
            try:
                return validate(value)
            except ValidationError as exc:
                original = exc
            # Redacted and raised outside the except block, so the unredacted
            # error is never kept as __context__. pydantic also rebuilds an error
            # raised here at its own boundary and drops the chain (measured on
            # 2.13.5); this placement does not rely on that.
            raise redact_validation_error(original, credential_fields=cls._hidden_locations())

        return core_schema.no_info_wrap_validator_function(redact, schema)

    # Two errors are raised outside the schema above, so they are caught here:
    # malformed JSON fails in the parser, and its input is the whole JSON text;
    # assignment to a frozen model or field is refused in BaseModel.__setattr__,
    # and its input is the assigned value. Hidden from type checkers so pyright
    # keeps the inherited signatures.
    if not TYPE_CHECKING:

        def __setattr__(self, name: str, value: Any) -> None:
            try:
                super().__setattr__(name, value)
            except ValidationError as exc:
                original = exc
            else:
                return
            raise redact_validation_error(original, credential_fields=type(self)._hidden_locations())

        @classmethod
        def model_validate_json(cls, *args: Any, **kwargs: Any) -> Any:
            try:
                return super().model_validate_json(*args, **kwargs)
            except ValidationError as exc:
                original = exc
            raise redact_validation_error(original, credential_fields=cls._hidden_locations())


__all__ = ["REDACTED_INPUT", "SecretSafeModel", "redact_validation_error"]
