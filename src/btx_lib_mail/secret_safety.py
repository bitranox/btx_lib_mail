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

The error MESSAGE of a hidden error is scrubbed on a best-effort basis only:
every text reachable in its input is replaced where the message repeats it
verbatim or in its ``repr()``, ``ascii()`` or JSON-escaped form. A value a
developer TRANSFORMS before writing it into a message (``strip()``, a slice,
other formatting, a hash) cannot be recognised and is not covered; keep
credentials out of messages you write.
"""

from __future__ import annotations

import json
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

# An input is shown only when it is one of these scalars, or an Enum member
# whose value is one; anything else (a mapping, a model, a dataclass, a deque, a
# dict view, any object) can hold a credential somewhere inside it, so it is hidden.
_SHOWN_SCALAR_TYPES: Final = (str, bytes, int, float, bool, type(None), Decimal, date, datetime, time, timedelta)

# An unexpected key is often a misspelled credential name (pasword=...), so the
# value under it is hidden whatever the key is called.
_ALWAYS_HIDDEN_TYPES: Final[frozenset[str]] = frozenset({"extra_forbidden"})

# from_exception_data accepts only pydantic's own error types by name.
_KNOWN_ERROR_TYPES: Final[frozenset[str]] = frozenset(get_args(core_schema.ErrorType))

# A text shorter than this is scrubbed from a message only where it stands
# alone, so a one-letter value does not shred every word holding that letter.
_MIN_FREE_TEXT: Final = 4

# Bounds on the walk over an input when collecting the texts to scrub (also on
# the chain of Enum values followed); an input larger than this cannot be proven
# absent from a message, so the message is hidden.
_MAX_TEXT_DEPTH: Final = 8
_MAX_VISITS: Final = 1000

_NO_CHILDREN: Final[tuple[object, ...]] = ()
# Marks an exhausted member iterator; no input can be this object.
_EXHAUSTED: Final = object()

_FAILED_TITLE: Final = "ValidationError"
_FAILED_TYPE: Final = "redacted_error"
_FAILED_MESSAGE: Final = "validation failed; the details could not be redacted and were dropped"


class _UnprovableError(Exception):
    """An input too large or too deep to prove absent from a message."""


def _must_hide(error: ErrorDetails, hidden_locations: frozenset[str]) -> bool:
    location = error["loc"]
    if not location or error["type"] in _ALWAYS_HIDDEN_TYPES or str(location[0]) in hidden_locations:
        return True
    return not _is_shown_scalar(error["input"])


def _is_shown_scalar(value: object) -> bool:
    # An Enum member renders its value (in the errors() repr and in json()), so
    # it is shown only when the value it finally stands for is a shown scalar.
    for _ in range(_MAX_TEXT_DEPTH):
        if not isinstance(value, Enum):
            return isinstance(value, _SHOWN_SCALAR_TYPES)
        value = cast("object", value.value)
    return False


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


def _texts_and_children(value: object) -> tuple[tuple[str, ...], Iterator[object]]:
    """Return the texts *value* renders by itself and a lazy iterator over its members."""
    if isinstance(value, bool) or value is None:
        return (), iter(_NO_CHILDREN)
    if isinstance(value, str):
        return (value,), iter(_NO_CHILDREN)
    if isinstance(value, Enum):
        return (str(value),), iter((cast("object", value.value),))
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        # A message can quote bytes decoded or as their repr (b'...' with escapes).
        return (raw.decode("utf-8", "replace"), repr(raw)[2:-1]), iter(_NO_CHILDREN)
    if isinstance(value, (int, float, Decimal)):
        return (str(value),), iter(_NO_CHILDREN)
    return _own_texts(value), _children(value)


def _input_texts(value: object) -> set[str]:
    """Collect the text of *value* and of every scalar reachable inside it.

    Members are taken one at a time from a stack of iterators, never collected
    up front, so an input with a huge number of them (``range(10**9)``) is
    refused after ``_MAX_VISITS`` members instead of being materialised first.
    """
    texts: set[str] = set()
    pending: list[tuple[Iterator[object], int]] = [(iter((value,)), 0)]
    visits = 0
    while pending:
        members, depth = pending[-1]
        current = next(members, _EXHAUSTED)
        if current is _EXHAUSTED:
            pending.pop()
            continue
        visits += 1
        if visits > _MAX_VISITS or depth > _MAX_TEXT_DEPTH:
            raise _UnprovableError
        own, children = _texts_and_children(current)
        texts.update(own)
        pending.append((children, depth + 1))
    return texts


def _written_forms(text: str) -> set[str]:
    """Return *text* as a message can repeat it: verbatim, or escaped by repr(), ascii() or json.dumps()."""
    return {text, repr(text)[1:-1], ascii(text)[1:-1], json.dumps(text)[1:-1]}


def _scrub_pattern(form: str) -> str:
    escaped = re.escape(form)
    return escaped if len(form) >= _MIN_FREE_TEXT else rf"(?<![^\W_]){escaped}(?![^\W_])"


def _scrubbed(message: str, error_input: object) -> str:
    """Return *message* with every text of *error_input* replaced by ``REDACTED_INPUT``.

    Best effort: a text is found only where the message repeats it verbatim or in
    one of its escaped forms (``_written_forms``). Longer forms are tried first,
    so an escaped form is replaced whole rather than piecewise.
    """
    forms = {form for text in _input_texts(error_input) if text.strip() for form in _written_forms(text)}
    if not forms:
        return message
    patterns = [_scrub_pattern(form) for form in sorted(forms, key=lambda form: (-len(form), form))]
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
    """Return a copy of *exc* whose error inputs and ctx cannot carry a credential.

    The rebuild never raises: an error it cannot rebuild faithfully keeps only
    its type and location, and if even that fails the result is one opaque
    ``redacted_error``.

    Raise the returned error OUTSIDE the ``except`` block that caught *exc*:
    ``raise redact_validation_error(exc, ...)`` inside that block keeps the
    unredacted original as ``__context__`` (``from None`` only hides it from the
    printed traceback; the attribute still holds it). Capture the original in
    the block and redact and raise after it, as the example shows.

    Args:
        exc: The error pydantic raised.
        credential_fields: Top-level locations whose input is always hidden:
            field names and every alias pydantic may report in ``loc``.

    Returns:
        A new ``ValidationError`` with the same title, types, locations and
        messages. An error's input is replaced by ``REDACTED_INPUT`` when it is
        model-level, an ``extra_forbidden`` error, at a credential location, or
        not a plain scalar (str, bytes, int, float, bool, None, Decimal, a date
        or time value, or an Enum member whose value is one of these). Such a
        hidden error also loses its ``ctx``, and its message is scrubbed on a
        best-effort basis: every text of the input is replaced where the message
        repeats it verbatim or in its ``repr()``, ``ascii()`` or JSON-escaped
        form. A value a developer transforms before writing it into a message
        (``strip()``, a slice, other formatting, a hash) is not recognised.
        Other errors keep their input and ctx.

    Examples:
        >>> from pydantic import BaseModel
        >>> class M(BaseModel):
        ...     password: str
        >>> try:
        ...     M(password=123)
        ... except ValidationError as caught:
        ...     original = caught
        >>> redacted = redact_validation_error(original, credential_fields=frozenset({"password"}))
        >>> redacted.errors()[0]["input"]
        '[redacted]'
        >>> try:
        ...     raise redacted
        ... except ValidationError as raised:
        ...     raised.__context__ is None
        True
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

    The rule for each error is that of ``redact_validation_error``: hidden
    inputs and ctx are replaced whole, while the message of a hidden error is
    scrubbed on a best-effort basis only (the input verbatim or in its
    ``repr()``, ``ascii()`` or JSON-escaped form). A credential a validator
    transforms before writing it into its own message is not covered.

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
