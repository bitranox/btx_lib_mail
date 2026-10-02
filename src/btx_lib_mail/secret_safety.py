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

The error MESSAGE of a hidden error is scrubbed on a best-effort basis only.
The scrub WALKS the input: the input itself, every mapping key and value,
every collection member, every attribute of a plain object, and the value of
an Enum member, up to ``_MAX_VISITS`` members and ``_MAX_TEXT_DEPTH`` levels
deep (an input past that bound cannot be proven absent from the message, so
the whole message is replaced instead of being searched). A mapping KEY equal
to a name the schema declares (a field name or alias of the model, or of a
model reachable from its field annotations) is not walked, so a message that
names a field keeps the name; a VALUE equal to such a name is still walked.
The walk collects the ``str()`` of each str, number, Enum member and other
non-collection object it reaches, and each bytes value both decoded as UTF-8
and in its ``repr()`` form; True, False and None give no text, and a
whitespace-only text is skipped. Every collected text is replaced where the
message repeats it verbatim or in its ``repr()``, ``ascii()`` or JSON-escaped
form (``json.dumps`` with ``ensure_ascii`` both true and false); a text
shorter than 4 characters is replaced only where it stands alone, not
directly next to a letter or digit. A value a developer TRANSFORMS before
writing it into a message (``strip()``, a slice, other formatting, a hash)
cannot be recognised and is not covered; keep credentials out of messages you
write.
"""

from __future__ import annotations

import json
import re
from collections.abc import Collection, Iterator, Mapping, Set
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from enum import Enum
from typing import TYPE_CHECKING, Any, ClassVar, Final, cast, get_args, get_origin
from weakref import WeakKeyDictionary

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


def _children(value: object, declared_names: frozenset[str]) -> Iterator[object]:
    if isinstance(value, Mapping):
        mapping = cast("Mapping[object, object]", value)
        for key, item in mapping.items():
            # A message can quote a credential used AS a key (a misspelled
            # scope name, a header name), so a key is walked and counted toward
            # the visit bound like a value. A key the schema declares is a field
            # name, not a secret, and a model-level message naming that field
            # must keep it; the exemption never extends to the VALUE.
            if not (isinstance(key, str) and key in declared_names):
                yield key
            yield item
    elif isinstance(value, Collection):
        yield from cast("Collection[object]", value)
    else:
        yield from vars(value).values() if hasattr(value, "__dict__") else ()


def _own_texts(value: object) -> tuple[str, ...]:
    # A collection's text is made of its members' texts; any other object may
    # render a secret itself (a dataclass repr), so its own text is scrubbed too.
    return () if isinstance(value, Collection) else (str(value),)


def _texts_and_children(value: object, declared_names: frozenset[str]) -> tuple[tuple[str, ...], Iterator[object]]:
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
    return _own_texts(value), _children(value, declared_names)


def _input_texts(value: object, declared_names: frozenset[str]) -> set[str]:
    """Collect the text of *value* and of every scalar reachable inside it.

    Members are taken one at a time from a stack of iterators, never collected
    up front, so an input with a huge number of them (``range(10**9)``) is
    refused after ``_MAX_VISITS`` members instead of being materialised first.
    A mapping key in *declared_names* is not visited; its value is.
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
        own, children = _texts_and_children(current, declared_names)
        texts.update(own)
        pending.append((children, depth + 1))
    return texts


def _written_forms(text: str) -> set[str]:
    """Return *text* as a message can repeat it: verbatim, or escaped by repr(), ascii() or json.dumps().

    ``json.dumps`` is tried with ``ensure_ascii`` both true (the default) and
    false: a non-ASCII character is escaped by the former and left literal by
    the latter, and a message can be built either way.
    """
    return {text, repr(text)[1:-1], ascii(text)[1:-1], json.dumps(text)[1:-1], json.dumps(text, ensure_ascii=False)[1:-1]}


def _scrub_pattern(form: str) -> str:
    escaped = re.escape(form)
    return escaped if len(form) >= _MIN_FREE_TEXT else rf"(?<![^\W_]){escaped}(?![^\W_])"


def _scrubbed(message: str, error_input: object, *, declared_names: frozenset[str]) -> str:
    """Return *message* with every text of *error_input* replaced by ``REDACTED_INPUT``.

    Best effort: a text is found only where the message repeats it verbatim or in
    one of its escaped forms (``_written_forms``). Longer forms are tried first,
    so an escaped form is replaced whole rather than piecewise.
    """
    forms = {form for text in _input_texts(error_input, declared_names) if text.strip() for form in _written_forms(text)}
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


def _faithful_detail(error: ErrorDetails, *, hide: bool, declared_names: frozenset[str]) -> InitErrorDetails:
    error_type, location = error["type"], error["loc"]
    message = _scrubbed(error["msg"], error["input"], declared_names=declared_names) if hide else error["msg"]
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


def _redacted_detail(error: ErrorDetails, *, hidden_locations: frozenset[str], declared_names: frozenset[str]) -> InitErrorDetails:
    try:
        return _faithful_detail(error, hide=_must_hide(error, hidden_locations), declared_names=declared_names)
    except Exception:
        # Fail closed: keep only the type and location, which pydantic produced.
        return {"type": PydanticCustomError(cast("LiteralString", str(error["type"])), REDACTED_INPUT), "loc": error["loc"], "input": REDACTED_INPUT}


def _failed_redaction(error_class: type[ValidationError] = ValidationError) -> ValidationError:
    detail: InitErrorDetails = {"type": PydanticCustomError(_FAILED_TYPE, _FAILED_MESSAGE), "loc": (), "input": REDACTED_INPUT}
    return error_class.from_exception_data(_FAILED_TITLE, [detail], hide_input=True)


def redact_validation_error(
    exc: ValidationError,
    *,
    credential_fields: frozenset[str],
    declared_names: frozenset[str] = frozenset(),
    error_class: type[ValidationError] = ValidationError,
) -> ValidationError:
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
        declared_names: Names the schema declares (field names and aliases),
            which a message may quote as they are. When the scrub walks a
            mapping, a KEY equal to one of these is not walked, so a message
            such as "timeout must be positive" keeps the field name. The
            exemption is for keys only: a VALUE equal to a declared name is
            still walked and scrubbed. Empty by default, so every key is walked.
        error_class: The class of the returned error: ``ValidationError`` or a
            subclass of it, so a caller can give the error a base of its own.

    Returns:
        A new ``ValidationError`` with the same title, types, locations and
        messages. An error's input is replaced by ``REDACTED_INPUT`` when it is
        model-level, an ``extra_forbidden`` error, at a credential location, or
        not a plain scalar (str, bytes, int, float, bool, None, Decimal, a date
        or time value, or an Enum member whose value is one of these). Such a
        hidden error also loses its ``ctx``, and its message is scrubbed on a
        best-effort basis. The scrub walks the input: the input itself, every
        mapping key and value (except a key in *declared_names*), every
        collection member, every attribute of a plain object, and the value of
        an Enum member, up to a bounded number of members and levels deep. It
        collects the ``str()`` of each str, number, Enum member and other
        non-collection object it reaches, and each bytes value both decoded as
        UTF-8 and in its ``repr()`` form; True, False and None give no text,
        and a whitespace-only text is skipped. Each text is replaced
        where the message repeats it verbatim or in its ``repr()``, ``ascii()``
        or JSON-escaped form (``ensure_ascii`` true or false); a text shorter
        than 4 characters only where it stands alone, not directly next to a
        letter or digit. An input past the walk's bound cannot be proven absent
        from the message, so the whole message is replaced instead. A value a
        developer transforms before writing it into a message (``strip()``, a
        slice, other formatting, a hash) is not recognised. Other errors keep
        their input and ctx.

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
        details = [_redacted_detail(error, hidden_locations=credential_fields, declared_names=declared_names) for error in exc.errors(include_url=False)]
        return error_class.from_exception_data(exc.title, details, hide_input=True)
    except Exception:
        # Fail closed: nothing of the original survives.
        return _failed_redaction(error_class)


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


def _alias_keys(alias: str | AliasPath | AliasChoices | None) -> frozenset[str]:
    """Return every mapping key *alias* can name: an ``AliasPath`` names one per string element."""
    if alias is None:
        return frozenset()
    if isinstance(alias, str):
        return frozenset({alias})
    if isinstance(alias, AliasPath):
        return frozenset(element for element in alias.path if isinstance(element, str))
    keys: set[str] = set()
    for choice in alias.choices:
        keys |= _alias_keys(choice)
    return frozenset(keys)


def _annotation_models(annotation: object) -> Iterator[type[BaseModel]]:
    """Yield every model class named in *annotation*, through Optional, Union, list, dict and the like."""
    # get_origin first: on Python 3.10 a parametrised generic such as list[int]
    # passes isinstance(..., type) but is refused by issubclass.
    if get_origin(annotation) is None and isinstance(annotation, type) and issubclass(annotation, BaseModel):
        yield annotation
        return
    for argument in get_args(annotation):
        yield from _annotation_models(argument)


# Collected once per model class; weak keys so a model class that goes away
# (one built inside a function) is not kept alive by the cache.
_DECLARED_NAMES: Final[WeakKeyDictionary[type[BaseModel], frozenset[str]]] = WeakKeyDictionary()


def _declared_names(model: type[BaseModel]) -> frozenset[str]:
    """Return the field names and alias keys of *model* and of every model reachable from its field annotations.

    Nested models, the members of Optional, Union, list and dict annotations,
    and the members of a discriminated union (so their discriminator field) are
    all included. A model that refers back to itself is visited once.
    """
    cached = _DECLARED_NAMES.get(model)
    if cached is not None:
        return cached
    names: set[str] = set()
    seen: set[type[BaseModel]] = set()
    pending = [model]
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        for name, info in current.model_fields.items():
            names |= {name} | _alias_keys(info.alias) | _alias_keys(info.validation_alias)
            pending.extend(_annotation_models(info.annotation))
    declared = frozenset(names)
    _DECLARED_NAMES[model] = declared
    return declared


def _check_credential_fields(model: type[BaseModel], names: object) -> None:
    """Refuse a ``credential_fields`` value that would silently protect nothing.

    Raises:
        TypeError: *names* is a pydantic field instead of a ClassVar, is not a
            set of str (a plain str would be iterated as its characters), or
            names something that is not a declared field of *model* (a typo,
            or an alias listed instead of its field).
    """
    if "credential_fields" in model.model_fields:
        raise TypeError(
            f"{model.__name__}.credential_fields is annotated, so pydantic made it a field and it protects nothing; "
            "assign it without an annotation or declare it ClassVar[frozenset[str]]"
        )
    kind = type(names).__name__
    members: list[object] = list(cast("Set[object]", names)) if isinstance(names, Set) else []
    if not isinstance(names, Set) or not all(isinstance(name, str) for name in members):
        raise TypeError(f"{model.__name__}.credential_fields must be a set of field names, got {kind}")
    unknown = sorted(str(name) for name in members if name not in model.model_fields)
    if unknown:
        raise TypeError(
            f"{model.__name__}.credential_fields lists {', '.join(map(repr, unknown))}, which is not a declared field; "
            "list field names (their aliases are hidden automatically)"
        )


if TYPE_CHECKING:
    _SecretSafeMeta = type(BaseModel)
else:

    class _SecretSafeMeta(type(BaseModel)):
        """Restore ``validation_error_class`` on errors raised by ``Model(...)``.

        A metaclass ``__call__`` and not an ``__init__`` override: pydantic routes
        validation through a model's own ``__init__`` when it defines one, which
        drops ``strict=`` and validates twice. Nested validation builds instances
        without calling the metaclass, and its errors reach the outer model's
        boundary instead. Hidden from type checkers, which would otherwise read
        ``Model(...)`` through this signature rather than the fields.
        """

        def __call__(cls, *args: Any, **kwargs: Any) -> Any:
            try:
                return super().__call__(*args, **kwargs)
            except ValidationError as exc:
                original = exc
            raise cls._as_configured_class(original)


class SecretSafeModel(BaseModel, metaclass=_SecretSafeMeta):
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
    scrubbed on a best-effort basis only -- every text reached by walking the
    input (mapping keys and values, collection members, object attributes,
    Enum values; bytes also in their ``repr()`` form), in its verbatim,
    ``repr()``, ``ascii()`` or JSON-escaped form, up to the walk's visit and
    depth bound; an input past that bound has its whole message replaced
    instead. A whitespace-only text is skipped, and a text under 4 characters
    is replaced only where it stands alone. The model passes its declared
    names (every field name and alias of this model and of every model
    reachable from its field annotations) as ``declared_names``, so a mapping
    KEY equal to one of them is not walked and a message naming a field keeps
    the name; a VALUE equal to such a name is still scrubbed. A credential a
    validator transforms before writing it into its own message is not
    covered.

    Not covered, because the JSON parser fails before this model is reached and
    its ``json_invalid`` error quotes the whole JSON text: malformed JSON handed
    to ``TypeAdapter(Model).validate_json``, or to ``model_validate_json`` of a
    plain outer model nesting this one.

    A model that NESTS a ``SecretSafeModel`` and has a model-level validator of
    its own must itself inherit this base and list the nested field, because its
    own model-level errors quote its own input.

    ``credential_fields`` is checked when the subclass is defined: it must be a
    set of the subclass's declared field names, assigned without an annotation
    (or declared ``ClassVar``). A typo, an alias listed instead of its field, a
    plain str, or an annotated attribute (which pydantic turns into a field)
    raises ``TypeError`` at class definition, because each would otherwise
    protect nothing.

    A validated assignment that fails is rolled back: pydantic applies the new
    value before a model-level ``mode="after"`` validator runs and keeps it when
    that validator raises (whatever it raises), so this model restores the
    previous field values, fields-set and extra values before re-raising. The
    restore is shallow: a validator that mutates a field value in place before
    raising is not undone.

    ``validation_error_class`` (a ClassVar, ``ValidationError`` by default)
    names the class of every error this model raises. Set it to a subclass of
    ``ValidationError`` to give the errors a base of your own; title,
    ``errors()`` and redaction stay as described above.
    """

    model_config = ConfigDict(hide_input_in_errors=True)
    credential_fields: ClassVar[frozenset[str]] = frozenset()
    validation_error_class: ClassVar[type[ValidationError]] = ValidationError

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs: Any) -> None:
        """Check the subclass's credential_fields as soon as it is defined.

        Args:
            **kwargs: Forwarded to pydantic's own subclass hook.
        """
        super().__pydantic_init_subclass__(**kwargs)
        _check_credential_fields(cls, cls.credential_fields)

    @classmethod
    def _hidden_locations(cls) -> frozenset[str]:
        hidden = set(cls.credential_fields)
        for name in cls.credential_fields:
            info = cls.model_fields.get(name)
            if info is not None:
                hidden |= _alias_names(info.alias) | _alias_names(info.validation_alias)
        return frozenset(hidden)

    @classmethod
    def _redacted(cls, original: ValidationError) -> ValidationError:
        # Both calls below can raise (a subclass's model_fields access, a bad
        # alias, a schema walk): guard them here too, not just the rebuild
        # inside redact_validation_error, so a raise from EITHER path fails
        # closed instead of letting pydantic-core catch it at the schema
        # boundary and rebuild a value_error whose input is the raw mapping
        # this method was never given a chance to redact.
        try:
            hidden_locations = cls._hidden_locations()
            declared_names = _declared_names(cls)
        except Exception:
            return _failed_redaction(cls.validation_error_class)
        return redact_validation_error(original, credential_fields=hidden_locations, declared_names=declared_names, error_class=cls.validation_error_class)

    @classmethod
    def __get_pydantic_core_schema__(cls, source: type[BaseModel], handler: GetCoreSchemaHandler) -> CoreSchema:
        """Wrap the model's core schema so every validation error it raises is redacted.

        Args:
            source: The model class pydantic is building a schema for.
            handler: Builds the schema source would otherwise get.

        Returns:
            source's schema wrapped by a validator that redacts a
            ValidationError before re-raising it.
        """
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
            raise cls._redacted(original)

        return core_schema.no_info_wrap_validator_function(redact, schema)

    # Two errors are raised outside the schema above, so they are caught here:
    # malformed JSON fails in the parser, and its input is the whole JSON text;
    # assignment to a frozen model or field is refused in BaseModel.__setattr__,
    # and its input is the assigned value. Hidden from type checkers so pyright
    # keeps the inherited signatures.
    if not TYPE_CHECKING:

        def __setattr__(self, name: str, value: Any) -> None:
            """Assign name, redacting and rolling back on a failed validated assignment.

            Args:
                name: Field (or extra key) being assigned.
                value: New value to validate and assign.

            Raises:
                ValidationError: The assignment failed; the model's prior
                    state is restored first and the error is redacted.
            """
            # pydantic writes the new value before a mode="after" model
            # validator runs and leaves it there when that validator raises
            # (whatever it raises), so the state is saved here and put back on
            # any failure.
            saved = self._assignment_state()
            try:
                super().__setattr__(name, value)
            except ValidationError as exc:
                original = exc
            except BaseException:
                self._restore_assignment_state(saved)
                raise
            else:
                return
            self._restore_assignment_state(saved)
            raise type(self)._redacted(original)

        def _assignment_state(self) -> tuple[dict[str, Any], set[str], dict[str, Any] | None]:
            extra = self.__pydantic_extra__
            return dict(self.__dict__), set(self.__pydantic_fields_set__), None if extra is None else dict(extra)

        def _restore_assignment_state(self, saved: tuple[dict[str, Any], set[str], dict[str, Any] | None]) -> None:
            # One swap per attribute, so a reader on another thread never sees
            # a half-restored __dict__ (the global conf is shared).
            values, fields_set, extra = saved
            object.__setattr__(self, "__dict__", values)
            object.__setattr__(self, "__pydantic_fields_set__", fields_set)
            object.__setattr__(self, "__pydantic_extra__", extra)

        @classmethod
        def model_validate_json(cls, *args: Any, **kwargs: Any) -> Any:
            """Validate JSON into an instance, redacting any validation error.

            Args:
                *args: Forwarded to pydantic's model_validate_json.
                **kwargs: Forwarded to pydantic's model_validate_json.

            Returns:
                The validated model instance.

            Raises:
                ValidationError: Validation failed; the error is redacted.
            """
            try:
                return super().model_validate_json(*args, **kwargs)
            except ValidationError as exc:
                original = exc
            raise cls._redacted(original)

        # pydantic rebuilds an error raised inside the schema as a plain
        # ValidationError at its own boundary, so a validation_error_class other
        # than ValidationError is restored here, outside it (construction is
        # wrapped by the metaclass). The error was already redacted inside the
        # schema; redacting it again is a no-op on its inputs and rebuilds it as
        # the configured class.
        @classmethod
        def model_validate(cls, *args: Any, **kwargs: Any) -> Any:
            """Validate a Python object into an instance, redacting any validation error.

            Args:
                *args: Forwarded to pydantic's model_validate.
                **kwargs: Forwarded to pydantic's model_validate.

            Returns:
                The validated model instance.

            Raises:
                ValidationError: Validation failed; the error is redacted
                    and rebuilt as validation_error_class.
            """
            try:
                return super().model_validate(*args, **kwargs)
            except ValidationError as exc:
                original = exc
            raise cls._as_configured_class(original)

        @classmethod
        def model_validate_strings(cls, *args: Any, **kwargs: Any) -> Any:
            """Validate a mapping of strings into an instance, redacting any validation error.

            Args:
                *args: Forwarded to pydantic's model_validate_strings.
                **kwargs: Forwarded to pydantic's model_validate_strings.

            Returns:
                The validated model instance.

            Raises:
                ValidationError: Validation failed; the error is redacted
                    and rebuilt as validation_error_class.
            """
            try:
                return super().model_validate_strings(*args, **kwargs)
            except ValidationError as exc:
                original = exc
            raise cls._as_configured_class(original)

        @classmethod
        def _as_configured_class(cls, original: ValidationError) -> ValidationError:
            if isinstance(original, cls.validation_error_class):
                return original
            return cls._redacted(original)


__all__ = ["REDACTED_INPUT", "SecretSafeModel", "redact_validation_error"]
