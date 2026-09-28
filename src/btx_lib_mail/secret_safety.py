"""Credential-safe validation errors for pydantic models that hold secrets.

A pydantic ``ValidationError`` records the raw input of every failing
validator. For a model that holds a password that input is the password (a
wrongly typed value) or the whole input mapping (a model-level validator), and
``hide_input_in_errors`` hides it only from ``str()``, not from ``errors()`` or
``json()``. ``SecretSafeModel`` wraps its whole validation schema so every error
it raises is rebuilt with those inputs replaced, whichever entry point ran it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, ClassVar, Final, cast, get_args

from pydantic import AliasChoices, AliasPath, BaseModel, ConfigDict, ValidationError
from pydantic_core import InitErrorDetails, PydanticCustomError, core_schema

if TYPE_CHECKING:
    from pydantic import GetCoreSchemaHandler
    from pydantic_core import CoreSchema, ErrorDetails
    from typing_extensions import LiteralString

REDACTED_INPUT: Final[str] = "[redacted]"
"""Stand-in for an error input that could carry a credential."""

# Inputs of these types can contain a credential somewhere inside them.
_CONTAINER_TYPES: Final = (Mapping, BaseModel, list, tuple, set, frozenset)

# An unexpected key is often a misspelled credential name (pasword=...), so the
# value under it is hidden whatever the key is called.
_ALWAYS_HIDDEN_TYPES: Final[frozenset[str]] = frozenset({"extra_forbidden"})

# from_exception_data accepts only pydantic's own error types by name; anything
# else (a PydanticCustomError from a subclass validator) is rebuilt as custom.
_KNOWN_ERROR_TYPES: Final[frozenset[str]] = frozenset(get_args(core_schema.ErrorType))


def _must_hide(error: ErrorDetails, hidden_locations: frozenset[str]) -> bool:
    location = error["loc"]
    if not location or error["type"] in _ALWAYS_HIDDEN_TYPES or str(location[0]) in hidden_locations:
        return True
    return isinstance(error["input"], _CONTAINER_TYPES)


def _rebuilt(error: ErrorDetails, *, hide: bool) -> InitErrorDetails:
    error_input: Any = REDACTED_INPUT if hide else error["input"]
    if error["type"] not in _KNOWN_ERROR_TYPES:
        # Type and message come from an error pydantic already built, not from a
        # caller-written template, so they are passed on as they are.
        custom = PydanticCustomError(cast("LiteralString", error["type"]), cast("LiteralString", error["msg"]))
        return {"type": custom, "loc": error["loc"], "input": error_input}
    detail: InitErrorDetails = {"type": error["type"], "loc": error["loc"], "input": error_input}
    if "ctx" in error:
        detail["ctx"] = error["ctx"]
    return detail


def redact_validation_error(exc: ValidationError, *, credential_fields: frozenset[str]) -> ValidationError:
    """Return a copy of *exc* whose error inputs cannot carry a credential.

    Args:
        exc: The error pydantic raised.
        credential_fields: Top-level locations whose input is always hidden:
            field names and every alias pydantic may report in ``loc``.

    Returns:
        A new ``ValidationError`` with the same title, types, locations and
        messages. Inputs are replaced by ``REDACTED_INPUT`` for model-level
        errors, ``extra_forbidden`` errors, credential locations and container
        inputs; other inputs stay.

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
    details = [_rebuilt(error, hide=_must_hide(error, credential_fields)) for error in exc.errors(include_url=False)]
    return ValidationError.from_exception_data(exc.title, details, hide_input=True)


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
    validators (a subclass's own included), every ``model_validate*`` entry
    point, ``TypeAdapter`` and a model nested in another model or a list.
    ``strict=`` and ``context=`` pass through unchanged.

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
                redacted = redact_validation_error(exc, credential_fields=cls._hidden_locations())
            # Raised outside the except block, so the unredacted error is not
            # kept as __context__.
            raise redacted

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
                redacted = redact_validation_error(exc, credential_fields=type(self)._hidden_locations())
            else:
                return
            raise redacted

        @classmethod
        def model_validate_json(cls, *args: Any, **kwargs: Any) -> Any:
            try:
                return super().model_validate_json(*args, **kwargs)
            except ValidationError as exc:
                redacted = redact_validation_error(exc, credential_fields=cls._hidden_locations())
            raise redacted


__all__ = ["REDACTED_INPUT", "SecretSafeModel", "redact_validation_error"]
