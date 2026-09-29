"""Guards that keep SMTP credentials out of logs, exception texts and validation errors.

Every secret here is a planted dummy. Every absence assertion is preceded by a
positive control proving the thing searched was actually produced.
"""

from __future__ import annotations

# Tests reach module internals (the failure describer, the transport seam) on purpose.
# pyright: reportPrivateUsage=false
import ast
import json
import logging
import pickle
import smtplib
import sys
import threading
from collections import deque
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import IO, TYPE_CHECKING, ClassVar, Literal, cast

import pytest
from pydantic import (
    AliasChoices,
    AliasPath,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    TypeAdapter,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

import btx_lib_mail
from btx_lib_mail import REDACTED_INPUT, ConfMail, SecretSafeModel, lib_mail, redact_validation_error, secret_safety
from btx_lib_mail.secret_safety import _MAX_VISITS

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from btx_lib_mail.lib_mail import DeliveryOptions

_DUMMY = "DUMMY-pässwörd-PLANTED-7f3a"
_AUTH_STRING = "\x00user\x00" + _DUMMY


class _RaisingTransport:
    """Transport double that fails every delivery with a preset exception."""

    def __init__(self, error: BaseException) -> None:
        self.error = error

    def deliver(self, *, host: str, sender: str, recipient: str, message: IO[bytes], delivery: DeliveryOptions) -> None:
        raise self.error


def _send_through(transport: lib_mail.Transport) -> None:
    lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients="rcpt@example.com",
        mail_subject="s",
        mail_body="b",
        smtphosts=["smtp.example.com"],
        transport=transport,
    )


def _failure_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == "btx_lib_mail" and r.levelno == logging.WARNING and "can not send mail" in r.msg]


@pytest.mark.os_agnostic
def test_a_failed_host_logs_no_traceback_and_no_auth_string(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="btx_lib_mail")
    error = UnicodeEncodeError("ascii", _AUTH_STRING, 6, 7, "ordinal not in range(128)")

    with pytest.raises(RuntimeError):
        _send_through(_RaisingTransport(error))

    records = _failure_records(caplog)
    assert len(records) == 1, "positive control: the per-host failure must reach the capture"
    record = records[0]
    assert "UnicodeEncodeError" in record.getMessage(), "positive control: the failure is still described"
    assert record.exc_info is None
    assert record.stack_info is None
    assert _DUMMY not in repr(vars(record))
    assert _DUMMY not in caplog.text


@pytest.mark.os_agnostic
def test_a_failed_host_logs_the_smtp_code_and_server_text(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="btx_lib_mail")
    error = smtplib.SMTPAuthenticationError(535, b"5.7.8 Authentication credentials invalid")

    with pytest.raises(RuntimeError):
        _send_through(_RaisingTransport(error))

    record = _failure_records(caplog)[0]
    assert "SMTPAuthenticationError 535 5.7.8 Authentication credentials invalid" in record.getMessage()
    assert record.__dict__["error_type"] == "SMTPAuthenticationError"
    assert record.__dict__["smtp_code"] == 535


class _FailingFormatter(logging.Formatter):
    """Formatter that always raises, to trigger the handler's own error path."""

    def format(self, record: logging.LogRecord) -> str:
        raise RuntimeError("formatter exploded PLANTED-FORMATTER-BOOM")


# Held in a name, not inlined at the call site: logging.Handler.handleError's
# "Call stack:" section prints each live frame's CURRENT SOURCE LINE, so an
# inline `ValueError("PLANTED ...")` literal would leak through that
# diagnostic regardless of the fix under test. A name keeps the call site's
# source line free of the plant, isolating the __context__-chaining bug this
# test targets from that unrelated (and much older) stdlib behaviour.
_PLANTED_TRANSPORT_ERROR = ValueError("PLANTED-DELIVERY-6c2e in transport")


@pytest.mark.os_agnostic
def test_a_failing_log_handler_does_not_chain_the_original_delivery_exception(capsys: pytest.CaptureFixture[str]) -> None:
    """logging.Handler.handleError prints via sys.exc_info(); the delivery error must not be chained onto it.

    A per-host WARNING logged INSIDE the ``except`` block that caught the delivery
    failure keeps that failure as ``__context__`` on anything the log call itself
    raises: a broken handler/formatter then has Python's default traceback printer
    walk the chain and print the delivery error too ("During handling of the above
    exception..."), even though nothing asked for a traceback.
    """
    handler = logging.StreamHandler()
    handler.setFormatter(_FailingFormatter())
    logger = logging.getLogger("btx_lib_mail")
    logger.addHandler(handler)
    logger.setLevel(logging.WARNING)
    original = logging.raiseExceptions
    logging.raiseExceptions = True
    try:
        with pytest.raises(RuntimeError):
            _send_through(_RaisingTransport(_PLANTED_TRANSPORT_ERROR))
    finally:
        logger.removeHandler(handler)
        logging.raiseExceptions = original
    captured = capsys.readouterr()
    assert "PLANTED-FORMATTER-BOOM" in captured.err, "positive control: the broken handler's own failure is reported"
    assert "PLANTED-DELIVERY-6c2e" not in captured.err, "the delivery exception must not be chained onto the handler's own failure"


@pytest.mark.os_agnostic
def test_a_network_error_keeps_its_text() -> None:
    assert lib_mail._describe_failure(ConnectionRefusedError(111, "Connection refused")) == "ConnectionRefusedError: [Errno 111] Connection refused"


@pytest.mark.os_agnostic
def test_an_unknown_error_is_named_but_not_quoted() -> None:
    assert lib_mail._describe_failure(ValueError(_DUMMY)) == "ValueError"


@pytest.mark.os_agnostic
def test_a_long_server_reply_is_bounded() -> None:
    described = lib_mail._describe_failure(smtplib.SMTPDataError(554, b"x" * 5000))
    assert described.startswith("SMTPDataError 554 x")
    assert len(described) == lib_mail._FAILURE_TEXT_LIMIT


@pytest.mark.os_agnostic
def test_a_server_reply_cannot_forge_log_lines() -> None:
    reply = b"5.7.8 denied\r\nWARNING forged line\x1b[31m\x00"
    described = lib_mail._describe_failure(smtplib.SMTPAuthenticationError(535, reply))
    assert described.startswith("SMTPAuthenticationError 535 5.7.8 denied"), "positive control: the reply text is kept"
    assert "forged line" in described, "positive control: text after the line break is kept, on the same line"
    assert all(character.isprintable() for character in described)


@pytest.mark.os_agnostic
def test_a_custom_transport_os_error_is_kept_on_one_line() -> None:
    described = lib_mail._describe_failure(ConnectionError("refused\nsecond line"))
    assert described == "ConnectionError: refused second line"


_LOG_METHODS = frozenset({"debug", "info", "warning", "warn", "error", "critical", "exception", "log"})


def _refers_to(node: ast.expr, names: set[str]) -> bool:
    """Return True when *node* is one of *names*, or an f-string interpolating one."""
    if isinstance(node, ast.Name):
        return node.id in names
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(part, ast.FormattedValue) and _refers_to(part.value, names) for part in node.values)
    return False


def _hands_over_the_exception(call: ast.Call, names: set[str]) -> bool:
    """Return True when a logging call passes a caught exception as an argument or an `extra` value."""
    if not (isinstance(call.func, ast.Attribute) and call.func.attr in _LOG_METHODS):
        return False
    extra_values = [value for keyword in call.keywords if keyword.arg == "extra" and isinstance(keyword.value, ast.Dict) for value in keyword.value.values]
    return any(_refers_to(value, names) for value in [*call.args, *extra_values])


def _attaches_a_traceback(call: ast.Call) -> bool:
    if any(keyword.arg in {"exc_info", "stack_info"} for keyword in call.keywords):
        return True
    return isinstance(call.func, ast.Attribute) and call.func.attr == "exception"


def _exception_leaking_log_calls(source: str, filename: str) -> list[str]:
    """Return `file:line` for every log call that hands an exception object to the log record."""
    tree = ast.parse(source)
    lines = {node.lineno for node in ast.walk(tree) if isinstance(node, ast.Call) and _attaches_a_traceback(node)}
    for handler in ast.walk(tree):
        if not (isinstance(handler, ast.ExceptHandler) and handler.name):
            continue
        calls = (node for statement in handler.body for node in ast.walk(statement) if isinstance(node, ast.Call))
        lines |= {call.lineno for call in calls if _hands_over_the_exception(call, {handler.name})}
    return [f"{filename}:{line}" for line in sorted(lines)]


# Lines 3, 4, 8, 9 and 10 hand the exception (or its traceback) to the record;
# lines 11 and 12 only pass values derived from it and must NOT be flagged.
_PLANTED = """\
import logging
log = logging.getLogger("x")
log.warning("m", exc_info=True)
log.exception("m")
try:
    pass
except Exception as error:
    log.warning("m %r", error)
    log.warning("m", extra={"error": error})
    log.warning(f"m {error!r}")
    log.warning("m %s", describe(error))
    log.warning("m %s", type(error).__name__, extra={"code": getattr(error, "code", None)})
"""


@pytest.mark.os_agnostic
def test_the_log_call_detector_flags_every_planted_shape_and_nothing_else() -> None:
    assert _exception_leaking_log_calls(_PLANTED, "planted.py") == ["planted.py:3", "planted.py:4", "planted.py:8", "planted.py:9", "planted.py:10"]


@pytest.mark.os_agnostic
def test_no_log_call_in_the_package_hands_over_an_exception() -> None:
    package_dir = Path(btx_lib_mail.__file__).parent
    sources = sorted(package_dir.rglob("*.py"))
    assert any(path.name == "lib_mail.py" for path in sources), "positive control: the scan reaches lib_mail.py"
    offenders = [hit for path in sources for hit in _exception_leaking_log_calls(path.read_text(encoding="utf-8"), path.name)]
    assert offenders == []


_HOST_DUMMY = "DUMMY-PLANTED-5e8b"


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "host",
    [f"user:{_HOST_DUMMY}@smtp.example.com", f"smtp://user:{_HOST_DUMMY}@smtp.example.com:587", "smtp.example.com/relay"],
)
def test_a_host_with_userinfo_or_a_path_is_refused_without_quoting_it(host: str) -> None:
    with pytest.raises(ValueError, match="must not contain") as caught:
        lib_mail.validate_smtp_host(host)
    assert _HOST_DUMMY not in str(caught.value)


@pytest.mark.os_agnostic
@pytest.mark.parametrize("host", ["smtp.example.com", "smtp.example.com:587", "[::1]:25", "[::1]"])
def test_plain_hosts_still_validate(host: str) -> None:
    lib_mail.validate_smtp_host(host)


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "hosts",
    [
        [f"smtp://user:{_HOST_DUMMY}@smtp.example.com:587"],
        [f"smtp://user:{_HOST_DUMMY}@smtp.example.com:587", "good.example.com"],
        ["good.example.com", f"smtp://user:{_HOST_DUMMY}@smtp.example.com:587"],
    ],
    ids=["alone", "before a good host", "after a good host"],
)
def test_send_refuses_a_userinfo_host_before_any_delivery(hosts: list[str], caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="btx_lib_mail")
    transport = _RaisingTransport(AssertionError("transport must not be reached"))
    with pytest.raises(ValueError, match="must not contain") as caught:
        lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="rcpt@example.com",
            mail_subject="s",
            smtphosts=hosts,
            transport=transport,
        )
    assert _HOST_DUMMY not in str(caught.value)
    assert caplog.records == [], "send() must refuse the userinfo host before logging anything, not merely before logging the dummy"


@pytest.mark.os_agnostic
def test_delivery_options_repr_hides_the_credentials() -> None:
    options = lib_mail.DeliveryOptions(credentials=("user", _HOST_DUMMY), use_starttls=True, starttls_verify=True, timeout=5.0)
    assert "use_starttls=True" in repr(options), "positive control: the repr is still produced"
    assert _HOST_DUMMY not in repr(options)
    assert options.credentials == ("user", _HOST_DUMMY)


def _leaks(exc: BaseException, needle: str) -> list[str]:
    """Name every rendering of *exc*, and of each exception chained to it, that contains *needle*."""
    places: dict[str, str] = {}
    current: BaseException | None = exc
    depth = 0
    while current is not None:
        prefix = "" if depth == 0 else f"chained[{depth}] "
        places[f"{prefix}str"] = str(current)
        places[f"{prefix}repr"] = repr(current)
        if isinstance(current, ValidationError):
            places[f"{prefix}errors()"] = repr(current.errors())
            places[f"{prefix}json()"] = current.json()
        current = current.__cause__ or current.__context__
        depth += 1
    return [name for name, text in places.items() if needle in text]


_MODEL_DUMMY = "DUMMY-PLANTED-9c1e"


class _Creds(SecretSafeModel):
    model_config = ConfigDict(validate_assignment=True)
    credential_fields = frozenset({"password"})
    password: SecretStr | None = None
    timeout: float = 30.0


class _CredsWithRule(_Creds):
    @model_validator(mode="after")
    def _rule(self) -> _CredsWithRule:
        if self.timeout > 100:
            raise ValueError("timeout too large")
        return self


class _CredsWithCustomRule(_Creds):
    @model_validator(mode="after")
    def _rule(self) -> _CredsWithCustomRule:
        raise PydanticCustomError("my_rule", "custom {what} broke", {"what": "thing"})


class _CredsWithValueErrorNamedRule(_Creds):
    # A custom error reusing a built-in type name that REQUIRES a ctx pydantic
    # would otherwise supply ('error'): rebuilding it by name without that ctx fails.
    @model_validator(mode="after")
    def _rule(self) -> _CredsWithValueErrorNamedRule:
        raise PydanticCustomError("value_error", "my message")


class _CredsWithIntParsingNamedRule(_Creds):
    # A custom error reusing a built-in type name whose own message differs:
    # rebuilding it by name replaces the custom message with pydantic's.
    @model_validator(mode="after")
    def _rule(self) -> _CredsWithIntParsingNamedRule:
        raise PydanticCustomError("int_parsing", "my own text")


class _PwAuth(BaseModel):
    kind: Literal["pw"]
    password: str


class _TokenAuth(BaseModel):
    kind: Literal["token"]
    token: str


class _TaggedCreds(SecretSafeModel):
    # union_tag_invalid repeats the input's tag in ctx["tag"] and in msg.
    credential_fields = frozenset({"auth"})
    auth: _PwAuth | _TokenAuth = Field(discriminator="kind")


@dataclass
class _Holder:
    secret: str


class _Unprintable:
    """An input whose text cannot be rendered: its str() and repr() raise."""

    def __str__(self) -> str:
        raise RuntimeError(_MODEL_DUMMY)

    def __repr__(self) -> str:
        raise RuntimeError(_MODEL_DUMMY)


# A backslash is doubled by repr() and by json.dumps(); umlauts are escaped by
# ascii() and by json.dumps(). Either way the message no longer holds the input
# verbatim, so a scrub of the raw text alone finds nothing.
_BACKSLASH_DUMMY = "DUMMY-PLANTED-5b2d\\x"
_UMLAUT_DUMMY = "DUMMY-PLANTED-6c3e-äöü"
# repr() keeps the umlaut and doubles the backslash; ascii() and json.dumps()
# escape the umlaut too, so only the repr() form of the text matches.
_UMLAUT_BACKSLASH_DUMMY = "DUMMY-PLANTED-8e5a-ä\\x"
# Bytes are quoted by their own repr (b'...\xc3\xa4'), which no form of the
# decoded text matches.
_BYTES_DUMMY = "DUMMY-PLANTED-9f6b-ä".encode()
# json.dumps(ensure_ascii=False) keeps the umlaut literal but still escapes the
# quote, so its form differs from repr() (which leaves the quote bare) and from
# json.dumps()'s default ensure_ascii=True form (which escapes the umlaut too).
_NONASCII_QUOTE_DUMMY = 'DUMMY-PLANTED-2d9f-ä"x'
# A credential used AS a mapping key, not a value.
_KEY_DUMMY = "DUMMY-PLANTED-4a7c"


class _QuotedToken(SecretSafeModel):
    credential_fields = frozenset({"token"})
    token: str = ""


class _TokenQuotedByRepr(_QuotedToken):
    @field_validator("token")
    @classmethod
    def _check(cls, value: str) -> str:
        raise ValueError(f"bad token {value!r}")


class _TokenQuotedByAscii(_QuotedToken):
    @field_validator("token")
    @classmethod
    def _check(cls, value: str) -> str:
        raise ValueError(f"bad token {value!a}")


class _TokenQuotedByJson(_QuotedToken):
    @field_validator("token")
    @classmethod
    def _check(cls, value: str) -> str:
        raise ValueError(f"bad token {json.dumps(value)}")


class _TokenQuotedByJsonNonAscii(_QuotedToken):
    @field_validator("token")
    @classmethod
    def _check(cls, value: str) -> str:
        raise ValueError(f"bad token {json.dumps(value, ensure_ascii=False)}")


class _MappingEnum(Enum):
    HELD = MappingProxyType({"password": _MODEL_DUMMY})


class _TokenScopes(SecretSafeModel):
    """Field is a credential dict: the KEY, not only the value, can hold a secret."""

    credential_fields = frozenset({"tokens"})
    tokens: dict[str, str] = Field(default_factory=dict)

    @field_validator("tokens")
    @classmethod
    def _check(cls, value: dict[str, str]) -> dict[str, str]:
        for key, scope in value.items():
            if scope not in {"read", "write"}:
                raise ValueError(f"token {key} has unknown scope {scope}")
        return value


class _BytesTokenQuotedByRepr(SecretSafeModel):
    credential_fields = frozenset({"token"})
    token: bytes = b""

    @field_validator("token")
    @classmethod
    def _check(cls, value: bytes) -> bytes:
        raise ValueError(f"bad token {value!r}")


class _TupleEnum(Enum):
    HELD = ("x", _MODEL_DUMMY)


class _ScalarEnum(Enum):
    SHOWN = "abc"


class _EnumOfEnum(Enum):
    SHOWN = _ScalarEnum.SHOWN


class _Outer(SecretSafeModel):
    credential_fields = frozenset({"mail"})
    mail: _Creds
    retries: int = 1

    @model_validator(mode="after")
    def _rule(self) -> _Outer:
        if self.retries > 5:
            raise ValueError("too many retries")
        return self


class _PlainOuter(BaseModel):
    mail: _CredsWithRule


class _PlaintextToken(SecretSafeModel):
    model_config = ConfigDict(validate_assignment=True)
    credential_fields = frozenset({"token"})
    token: str = ""
    retries: int = 1

    @model_validator(mode="after")
    def _rule(self) -> _PlaintextToken:
        if self.retries > 5:
            raise ValueError("too many retries")
        return self


class _Forbidding(SecretSafeModel):
    model_config = ConfigDict(extra="forbid")
    credential_fields = frozenset({"password"})
    password: SecretStr | None = None


class _Aliased(SecretSafeModel):
    credential_fields = frozenset({"password", "token", "key"})
    password: str = Field(default="", alias="pw")
    token: str = Field(default="", validation_alias="tok")
    key: str = Field(default="", validation_alias=AliasChoices("apikey", "api_key"))


class _FrozenCreds(_Creds):
    model_config = ConfigDict(frozen=True)


def _assign_retries(model: _PlaintextToken) -> None:
    model.retries = 9


def _assign_password(model: _FrozenCreds) -> None:
    model.password = _MODEL_DUMMY  # type: ignore[assignment]


# (label, build, needle): each arm asserts the input IT sent is absent, so an arm
# whose input is not the shared dummy (the alias arms send a number) still has a
# needle that can be found when the redaction is missing.
_LEAK_CASES: list[tuple[str, Callable[[], object], str]] = [
    ("subclass rule via __init__", lambda: _CredsWithRule(password=_MODEL_DUMMY, timeout=500), _MODEL_DUMMY),  # type: ignore[arg-type]
    ("subclass rule via model_validate", lambda: _CredsWithRule.model_validate({"password": _MODEL_DUMMY, "timeout": 500}), _MODEL_DUMMY),
    ("subclass rule via model_validate_json", lambda: _CredsWithRule.model_validate_json(f'{{"password": "{_MODEL_DUMMY}", "timeout": 500}}'), _MODEL_DUMMY),
    ("subclass rule via model_validate_strings", lambda: _CredsWithRule.model_validate_strings({"password": _MODEL_DUMMY, "timeout": "500"}), _MODEL_DUMMY),
    ("malformed JSON", lambda: _Creds.model_validate_json(f'{{"password": "{_MODEL_DUMMY}", "timeout": '), _MODEL_DUMMY),
    ("TypeAdapter", lambda: TypeAdapter(_CredsWithRule).validate_python({"password": _MODEL_DUMMY, "timeout": 500}), _MODEL_DUMMY),
    ("TypeAdapter list", lambda: TypeAdapter(list[_CredsWithRule]).validate_python([{"password": _MODEL_DUMMY, "timeout": 500}]), _MODEL_DUMMY),
    ("nested in a plain model", lambda: _PlainOuter(mail={"password": _MODEL_DUMMY, "timeout": 500}), _MODEL_DUMMY),  # type: ignore[arg-type]
    ("list password", lambda: _Creds(password=["x", _MODEL_DUMMY]), _MODEL_DUMMY),  # type: ignore[arg-type]
    ("scalar password", lambda: _Creds(password=64518273), "64518273"),  # type: ignore[arg-type]
    ("container in a non-credential field", lambda: _Creds(timeout={"password": _MODEL_DUMMY}), _MODEL_DUMMY),  # type: ignore[arg-type]
    ("dataclass in a non-credential field", lambda: _Creds(timeout=_Holder(_MODEL_DUMMY)), _MODEL_DUMMY),  # type: ignore[arg-type]
    ("SimpleNamespace in a non-credential field", lambda: _Creds(timeout=SimpleNamespace(password=_MODEL_DUMMY)), _MODEL_DUMMY),  # type: ignore[arg-type]
    ("deque in a non-credential field", lambda: _Creds(timeout=deque(["x", _MODEL_DUMMY])), _MODEL_DUMMY),  # type: ignore[arg-type]
    ("dict values view in a non-credential field", lambda: _Creds(timeout={"password": _MODEL_DUMMY}.values()), _MODEL_DUMMY),  # type: ignore[arg-type]
    ("mapping-valued Enum in a non-credential field", lambda: _Creds(timeout=_MappingEnum.HELD), _MODEL_DUMMY),  # type: ignore[arg-type]
    ("tuple-valued Enum in a non-credential field", lambda: _Creds(timeout=_TupleEnum.HELD), _MODEL_DUMMY),  # type: ignore[arg-type]
    ("token quoted by repr()", lambda: _TokenQuotedByRepr(token=_BACKSLASH_DUMMY), "PLANTED-5b2d"),
    ("token quoted by ascii()", lambda: _TokenQuotedByAscii(token=_UMLAUT_DUMMY), "PLANTED-6c3e"),
    ("token quoted by json.dumps()", lambda: _TokenQuotedByJson(token=_UMLAUT_DUMMY), "PLANTED-6c3e"),
    ("backslash token quoted by json.dumps()", lambda: _TokenQuotedByJson(token=_BACKSLASH_DUMMY), "PLANTED-5b2d"),
    ("umlaut and backslash token quoted by repr()", lambda: _TokenQuotedByRepr(token=_UMLAUT_BACKSLASH_DUMMY), "PLANTED-8e5a"),
    ("bytes token quoted by repr()", lambda: _BytesTokenQuotedByRepr(token=_BYTES_DUMMY), "PLANTED-9f6b"),
    ("token quoted by json.dumps(ensure_ascii=False)", lambda: _TokenQuotedByJsonNonAscii(token=_NONASCII_QUOTE_DUMMY), "PLANTED-2d9f"),
    ("credential dict key", lambda: _TokenScopes(tokens={_KEY_DUMMY: "admin"}), _KEY_DUMMY),
    ("custom error type", lambda: _CredsWithCustomRule(password=_MODEL_DUMMY), _MODEL_DUMMY),  # type: ignore[arg-type]
    ("custom error reusing value_error", lambda: _CredsWithValueErrorNamedRule(password=_MODEL_DUMMY), _MODEL_DUMMY),  # type: ignore[arg-type]
    ("custom error reusing int_parsing", lambda: _CredsWithIntParsingNamedRule(password=_MODEL_DUMMY), _MODEL_DUMMY),  # type: ignore[arg-type]
    ("union tag at a credential location", lambda: _TaggedCreds(auth={"kind": _MODEL_DUMMY, "password": "x"}), _MODEL_DUMMY),  # type: ignore[arg-type]
    ("input whose text cannot be rendered", lambda: _Creds(password=_Unprintable()), _MODEL_DUMMY),  # type: ignore[arg-type]
    ("outer model rule", lambda: _Outer(mail={"password": _MODEL_DUMMY}, retries=9), _MODEL_DUMMY),  # type: ignore[arg-type]
    ("assignment re-runs a subclass rule", lambda: _assign_retries(_PlaintextToken(token=_MODEL_DUMMY)), _MODEL_DUMMY),
    ("assignment to a frozen model", lambda: _assign_password(_FrozenCreds()), _MODEL_DUMMY),
    ("extra_forbidden", lambda: _Forbidding(pasword=_MODEL_DUMMY), _MODEL_DUMMY),  # type: ignore[call-arg]
    ("alias", lambda: _Aliased(pw=91827364), "91827364"),  # type: ignore[arg-type]
    ("validation_alias", lambda: _Aliased(tok=82736451), "82736451"),  # type: ignore[call-arg]
    ("AliasChoices", lambda: _Aliased(api_key=73645182), "73645182"),  # type: ignore[call-arg]
]


@pytest.mark.os_agnostic
@pytest.mark.parametrize(("label", "build", "needle"), _LEAK_CASES, ids=[case[0] for case in _LEAK_CASES])
def test_a_secret_safe_model_error_never_carries_the_credential(label: str, build: Callable[[], object], needle: str) -> None:
    with pytest.raises(ValidationError) as caught:
        build()
    assert caught.value.error_count() >= 1, f"positive control ({label}): an error was produced"
    assert _leaks(caught.value, needle) == []


@pytest.mark.os_agnostic
def test_the_leak_detector_fires_on_a_plain_model() -> None:
    class _Plain(BaseModel):
        password: SecretStr | None = None

        @model_validator(mode="after")
        def _rule(self) -> _Plain:
            raise ValueError("always")

    with pytest.raises(ValidationError) as caught:
        _Plain(password=_MODEL_DUMMY)  # type: ignore[arg-type]
    assert "errors()" in _leaks(caught.value, _MODEL_DUMMY)


@pytest.mark.os_agnostic
def test_the_leak_detector_walks_the_exception_chain() -> None:
    try:
        try:
            raise ValueError(_MODEL_DUMMY)
        except ValueError:
            raise RuntimeError("outer") from None
    except RuntimeError as outer:
        assert _leaks(outer, _MODEL_DUMMY) == ["chained[1] str", "chained[1] repr"]


@pytest.mark.os_agnostic
def test_a_non_credential_field_keeps_its_input() -> None:
    with pytest.raises(ValidationError) as caught:
        _Creds(password=_MODEL_DUMMY, timeout="abc")  # type: ignore[arg-type]
    errors = caught.value.errors()
    assert [e["loc"] for e in errors] == [("timeout",)]
    assert errors[0]["input"] == "abc"
    assert errors[0]["msg"] == "Input should be a valid number, unable to parse string as a number"
    assert "url" in errors[0], "a visible built-in error is rebuilt as that built-in type, so it keeps its documentation link"


@pytest.mark.os_agnostic
def test_a_redacted_error_keeps_type_location_and_message() -> None:
    with pytest.raises(ValidationError) as caught:
        _CredsWithCustomRule(password=_MODEL_DUMMY)  # type: ignore[arg-type]
    error = caught.value.errors()[0]
    assert error["type"] == "my_rule"
    assert error["msg"] == "custom thing broke"
    assert error["input"] == REDACTED_INPUT


_CUSTOM_ERRORS: list[tuple[type[_Creds], str, str]] = [
    (_CredsWithCustomRule, "my_rule", "custom thing broke"),
    (_CredsWithValueErrorNamedRule, "value_error", "my message"),
    (_CredsWithIntParsingNamedRule, "int_parsing", "my own text"),
]


@pytest.mark.os_agnostic
@pytest.mark.parametrize(("model", "error_type", "message"), _CUSTOM_ERRORS, ids=[case[1] for case in _CUSTOM_ERRORS])
def test_a_custom_error_keeps_its_own_type_and_message(model: type[_Creds], error_type: str, message: str) -> None:
    with pytest.raises(ValidationError) as caught:
        model(password=_MODEL_DUMMY)  # type: ignore[arg-type]
    errors = caught.value.errors()
    assert [(e["type"], e["loc"], e["msg"], e["input"]) for e in errors] == [(error_type, (), message, REDACTED_INPUT)]
    assert "ctx" not in errors[0], "a hidden error keeps no ctx: ctx can repeat the input"


@pytest.mark.os_agnostic
def test_a_hidden_error_drops_ctx_and_scrubs_the_input_from_its_message() -> None:
    with pytest.raises(ValidationError) as caught:
        _TaggedCreds(auth={"kind": _MODEL_DUMMY, "password": "x"})  # type: ignore[arg-type]
    errors = caught.value.errors()
    assert [(e["type"], e["loc"], e["input"]) for e in errors] == [("union_tag_invalid", ("auth",), REDACTED_INPUT)], "positive control"
    assert "ctx" not in errors[0]
    # 'kind' is also a KEY of the hidden input dict, but it is the discriminator
    # field of a model the schema declares, so it is not walked and survives.
    assert errors[0]["msg"] == f"Input tag '{REDACTED_INPUT}' found using 'kind' does not match any of the expected tags: 'pw', 'token'"


class _PositiveTimeout(SecretSafeModel):
    """A model-level rule whose message names a top-level field."""

    credential_fields = frozenset({"password"})
    password: SecretStr | None = None
    timeout: float = 30.0

    @model_validator(mode="after")
    def _rule(self) -> _PositiveTimeout:
        if self.timeout < 0:
            raise ValueError("timeout must be positive")
        return self


class _SubConfig(BaseModel):
    valid: bool = True


class _WithSubConfig(SecretSafeModel):
    """A model-level rule whose message names a field of a NESTED model."""

    credential_fields = frozenset({"password"})
    password: SecretStr | None = None
    sub: _SubConfig | None = None

    @model_validator(mode="after")
    def _rule(self) -> _WithSubConfig:
        if self.sub is not None and not self.sub.valid:
            raise ValueError("sub config is not valid")
        return self


class _AliasedLimit(SecretSafeModel):
    """A model-level rule whose message names every alias a field accepts."""

    credential_fields = frozenset({"password"})
    password: SecretStr | None = None
    limit: int = Field(default=1, validation_alias=AliasChoices("maximum", AliasPath("settings", "ceiling")))

    @model_validator(mode="after")
    def _rule(self) -> _AliasedLimit:
        if self.limit > 5:
            raise ValueError("maximum or settings.ceiling must not exceed 5")
        return self


# (label, build, message): the input of each hidden model-level error holds, as
# a mapping KEY, the name the message quotes.
_DECLARED_NAME_CASES: list[tuple[str, Callable[[], object], str]] = [
    ("top-level field", lambda: _PositiveTimeout(password=_MODEL_DUMMY, timeout=-1), "Value error, timeout must be positive"),  # type: ignore[arg-type]
    (
        "field of a nested model",
        lambda: _WithSubConfig.model_validate({"password": _MODEL_DUMMY, "sub": {"valid": False}}),
        "Value error, sub config is not valid",
    ),
    (
        "alias choice and alias path elements",
        lambda: _AliasedLimit.model_validate({"password": _MODEL_DUMMY, "maximum": 9, "settings": {"ceiling": 1}}),
        "Value error, maximum or settings.ceiling must not exceed 5",
    ),
]


@pytest.mark.os_agnostic
@pytest.mark.parametrize(("label", "build", "message"), _DECLARED_NAME_CASES, ids=[case[0] for case in _DECLARED_NAME_CASES])
def test_a_declared_name_used_as_an_input_key_survives_in_the_message(label: str, build: Callable[[], object], message: str) -> None:
    with pytest.raises(ValidationError) as caught:
        build()
    errors = caught.value.errors()
    assert [(e["type"], e["loc"], e["input"]) for e in errors] == [("value_error", (), REDACTED_INPUT)], f"positive control ({label})"
    assert errors[0]["msg"] == message
    assert _leaks(caught.value, _MODEL_DUMMY) == [], "the credential VALUE is still hidden"


class _ErrorNamedField(SecretSafeModel):
    """A field named like the word in pydantic's own 'Value error,' prefix."""

    credential_fields = frozenset({"password"})
    password: SecretStr | None = None
    error: str = ""

    @model_validator(mode="after")
    def _rule(self) -> _ErrorNamedField:
        if self.error:
            raise ValueError(f"error holds {self.error}")
        return self


@pytest.mark.os_agnostic
def test_a_field_named_error_keeps_the_value_error_prefix_and_its_value_is_scrubbed() -> None:
    with pytest.raises(ValidationError) as caught:
        _ErrorNamedField(error=_MODEL_DUMMY)
    errors = caught.value.errors()
    assert [(e["type"], e["loc"], e["input"]) for e in errors] == [("value_error", (), REDACTED_INPUT)], "positive control"
    assert errors[0]["msg"] == f"Value error, error holds {REDACTED_INPUT}"
    assert _leaks(caught.value, _MODEL_DUMMY) == []


class _TreeNode(SecretSafeModel):
    """A model whose field annotation refers back to the model itself."""

    credential_fields = frozenset({"password"})
    password: SecretStr | None = None
    child: _TreeNode | None = None
    depth: int = 0

    @model_validator(mode="after")
    def _rule(self) -> _TreeNode:
        if self.depth < 0:
            raise ValueError("depth must not be negative")
        return self


@pytest.mark.os_agnostic
def test_a_self_referencing_model_collects_its_declared_names_without_looping() -> None:
    caught: list[ValidationError] = []

    def build() -> None:
        try:
            _TreeNode(password=_MODEL_DUMMY, depth=-1)  # type: ignore[arg-type]
        except ValidationError as error:
            caught.append(error)

    # A daemon thread and a join timeout bound the call from outside the code under
    # test, so a collection that never ends fails this test instead of hanging the suite.
    worker = threading.Thread(target=build, daemon=True)
    worker.start()
    worker.join(timeout=5)
    assert not worker.is_alive(), "collecting the declared names kept following the model's reference to itself"
    assert caught, "positive control: the worker finished by raising, not by returning silently"
    assert [(e["loc"], e["msg"]) for e in caught[0].errors()] == [((), "Value error, depth must not be negative")]


@pytest.mark.os_agnostic
def test_a_value_equal_to_a_declared_name_is_still_scrubbed() -> None:
    # The exemption is for mapping KEYS only: a credential whose value happens
    # to equal a field name is still found and replaced.
    with pytest.raises(ValidationError) as control:
        _PositiveTimeout(password=_MODEL_DUMMY, timeout=-1)  # type: ignore[arg-type]
    assert control.value.errors()[0]["msg"] == "Value error, timeout must be positive", "control: the name alone survives"
    with pytest.raises(ValidationError) as caught:
        _PositiveTimeout(password="timeout", timeout=-1)  # type: ignore[arg-type]
    errors = caught.value.errors()
    assert [(e["type"], e["loc"], e["input"]) for e in errors] == [("value_error", (), REDACTED_INPUT)], "positive control"
    assert errors[0]["msg"] == f"Value error, {REDACTED_INPUT} must be positive"


@pytest.mark.os_agnostic
def test_an_input_whose_text_cannot_be_rendered_fails_closed() -> None:
    with pytest.raises(ValidationError) as caught:
        _Creds(password=_Unprintable())  # type: ignore[arg-type]
    errors = caught.value.errors()
    assert errors, "positive control: the error survived the failed rendering"
    assert [e["loc"][:1] for e in errors] == [("password",)] * len(errors), "each error keeps its own location"
    assert all(e["input"] == REDACTED_INPUT for e in errors)
    assert all(e["msg"] == REDACTED_INPUT for e in errors), "the message could not be checked, so it is hidden whole"


@pytest.mark.os_agnostic
def test_an_input_too_deep_to_check_hides_the_message() -> None:
    shallow: object = _MODEL_DUMMY
    for _ in range(3):
        shallow = [shallow]
    deep: object = _MODEL_DUMMY
    for _ in range(12):
        deep = [deep]
    with pytest.raises(ValidationError) as shallow_caught:
        _Creds(password=shallow)  # type: ignore[arg-type]
    assert all(e["msg"] != REDACTED_INPUT for e in shallow_caught.value.errors()), "control: a checkable input keeps its message"
    with pytest.raises(ValidationError) as deep_caught:
        _Creds(password=deep)  # type: ignore[arg-type]
    errors = deep_caught.value.errors()
    assert errors, "positive control"
    assert all(e["msg"] == REDACTED_INPUT and e["input"] == REDACTED_INPUT for e in errors), "an input too deep to check hides the message whole"


@pytest.mark.os_agnostic
def test_a_failure_computing_the_declared_names_fails_closed_instead_of_leaking_the_raw_input(monkeypatch: pytest.MonkeyPatch) -> None:
    """If collecting the schema's own names raises, the redaction must still hide the raw input.

    ``SecretSafeModel._redacted`` calls the module-level ``_declared_names`` by its
    global name, so patching ``btx_lib_mail.secret_safety._declared_names`` is the real
    seam ``_redacted`` reads at call time (not a copy bound elsewhere).
    """
    with pytest.raises(ValidationError) as control:
        ConfMail(smtp_password=[_DUMMY])  # type: ignore[arg-type]
    control_errors = control.value.errors()
    assert control_errors, "positive control: a broken declared-names collector is not the only way to reach an error here"
    assert _DUMMY not in str(control.value), "positive control: the plant is checked against the working path first"

    def _boom(model: type[BaseModel]) -> frozenset[str]:
        raise ValueError("boom")

    monkeypatch.setattr(secret_safety, "_declared_names", _boom)
    with pytest.raises(ValidationError) as caught:
        ConfMail(smtp_password=[_DUMMY])  # type: ignore[arg-type]
    exc = caught.value
    errors = exc.errors()
    assert errors, "positive control: the patch is reached and still raises"
    assert [(e["type"], e["loc"], e["input"]) for e in errors] == [("redacted_error", (), REDACTED_INPUT)]
    assert errors[0]["msg"] == "validation failed; the details could not be redacted and were dropped"
    assert _DUMMY not in str(exc)
    assert _DUMMY not in repr(exc)
    assert _DUMMY not in json.dumps(errors, default=str)
    assert exc.__context__ is None, "the unredacted original must not survive on the chain"


@pytest.mark.os_agnostic
def test_a_failure_computing_the_hidden_locations_fails_closed_instead_of_leaking_the_raw_input(monkeypatch: pytest.MonkeyPatch) -> None:
    """If collecting the credential locations raises, the redaction must still hide the raw input.

    ``SecretSafeModel._redacted`` calls ``cls._hidden_locations()`` before ``_declared_names``;
    both calls sit inside the same guard, so a raise from either path must fail closed. This is
    the sibling of the test above, which forces ``_declared_names`` instead.
    """
    with pytest.raises(ValidationError) as control:
        ConfMail(smtp_password=[_DUMMY])  # type: ignore[arg-type]
    control_errors = control.value.errors()
    assert control_errors, "positive control: a broken hidden-locations collector is not the only way to reach an error here"
    assert _DUMMY not in str(control.value), "positive control: the plant is checked against the working path first"

    def _boom(cls: type[BaseModel]) -> frozenset[str]:
        raise ValueError("boom")

    monkeypatch.setattr(SecretSafeModel, "_hidden_locations", classmethod(_boom))
    with pytest.raises(ValidationError) as caught:
        ConfMail(smtp_password=[_DUMMY])  # type: ignore[arg-type]
    exc = caught.value
    errors = exc.errors()
    assert errors, "positive control: the patch is reached and still raises"
    assert [(e["type"], e["loc"], e["input"]) for e in errors] == [("redacted_error", (), REDACTED_INPUT)]
    assert errors[0]["msg"] == "validation failed; the details could not be redacted and were dropped"
    assert _DUMMY not in str(exc)
    assert _DUMMY not in repr(exc)
    assert _DUMMY not in json.dumps(errors, default=str)
    assert exc.__context__ is None, "the unredacted original must not survive on the chain"


_ESCAPED_QUOTES: list[tuple[type[_QuotedToken], Callable[[str], str], str, str]] = [
    (_TokenQuotedByRepr, repr, _BACKSLASH_DUMMY, f"Value error, bad token '{REDACTED_INPUT}'"),
    (_TokenQuotedByAscii, ascii, _UMLAUT_DUMMY, f"Value error, bad token '{REDACTED_INPUT}'"),
    (_TokenQuotedByJson, json.dumps, _UMLAUT_DUMMY, f'Value error, bad token "{REDACTED_INPUT}"'),
    (_TokenQuotedByJson, json.dumps, _BACKSLASH_DUMMY, f'Value error, bad token "{REDACTED_INPUT}"'),
    (_TokenQuotedByRepr, repr, _UMLAUT_BACKSLASH_DUMMY, f"Value error, bad token '{REDACTED_INPUT}'"),
    (_TokenQuotedByJsonNonAscii, lambda text: json.dumps(text, ensure_ascii=False), _NONASCII_QUOTE_DUMMY, f'Value error, bad token "{REDACTED_INPUT}"'),
]


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("model", "quote", "token", "message"),
    _ESCAPED_QUOTES,
    ids=["repr backslash", "ascii umlauts", "json umlauts", "json backslash", "repr umlaut and backslash", "json ensure_ascii=False"],
)
def test_an_escaped_copy_of_a_hidden_input_is_scrubbed_from_the_message(
    model: type[_QuotedToken], quote: Callable[[str], str], token: str, message: str
) -> None:
    assert quote(token)[1:-1] != token, "fixture: the quoting changes the text, so a verbatim scrub cannot find it"
    with pytest.raises(ValidationError) as caught:
        model(token=token)
    errors = caught.value.errors()
    assert [(e["type"], e["loc"], e["input"]) for e in errors] == [("value_error", ("token",), REDACTED_INPUT)], "positive control"
    assert errors[0]["msg"] == message


@pytest.mark.os_agnostic
def test_an_enum_is_shown_only_when_its_value_is_a_shown_scalar() -> None:
    for member in (_ScalarEnum.SHOWN, _EnumOfEnum.SHOWN):
        with pytest.raises(ValidationError) as shown:
            _Creds(timeout=member)  # type: ignore[arg-type]
        assert shown.value.errors()[0]["input"] is member, f"control: {member!r} renders a scalar, so it stays visible"
    for member in (_MappingEnum.HELD, _TupleEnum.HELD):
        with pytest.raises(ValidationError) as hidden:
            _Creds(timeout=member)  # type: ignore[arg-type]
        assert [e["loc"] for e in hidden.value.errors()] == [("timeout",)], "positive control"
        assert hidden.value.errors()[0]["input"] == REDACTED_INPUT, f"{member.name} of {type(member).__name__} renders a container"


@pytest.mark.os_agnostic
def test_the_repr_of_hidden_bytes_is_scrubbed_from_the_message() -> None:
    assert repr(_BYTES_DUMMY)[2:-1] != _BYTES_DUMMY.decode(), "fixture: the bytes repr differs from the decoded text"
    with pytest.raises(ValidationError) as caught:
        _BytesTokenQuotedByRepr(token=_BYTES_DUMMY)
    errors = caught.value.errors()
    assert [(e["type"], e["loc"], e["input"]) for e in errors] == [("value_error", ("token",), REDACTED_INPUT)], "positive control"
    assert errors[0]["msg"] == f"Value error, bad token b'{REDACTED_INPUT}'"


@pytest.mark.os_agnostic
def test_a_credential_used_as_a_mapping_key_is_scrubbed_from_the_message() -> None:
    with pytest.raises(ValidationError) as caught:
        _TokenScopes(tokens={_KEY_DUMMY: "admin"})
    errors = caught.value.errors()
    assert [(e["type"], e["loc"], e["input"]) for e in errors] == [("value_error", ("tokens",), REDACTED_INPUT)], "positive control"
    # "admin" (the dict VALUE) was already scrubbed before this fix; the KEY is
    # the new part this test proves.
    assert errors[0]["msg"] == f"Value error, token {REDACTED_INPUT} has unknown scope {REDACTED_INPUT}", "the KEY, not only the value, is scrubbed"


def _enum_member_whose_value_is_itself() -> Enum:
    class _Cyclic(Enum):
        LOOP = 1

    member = _Cyclic.LOOP
    member._value_ = member
    return member


@pytest.mark.os_agnostic
def test_an_enum_whose_value_leads_back_to_itself_is_hidden_without_looping() -> None:
    member = _enum_member_whose_value_is_itself()
    assert member.value is member, "fixture: following the value never reaches a non-Enum"
    caught: list[ValidationError] = []

    def build() -> None:
        try:
            _Creds(timeout=member)  # type: ignore[arg-type]
        except ValidationError as error:
            caught.append(error)

    # A daemon thread and a join timeout bound the call from outside the code under
    # test, so a loop that never ends fails this test instead of hanging the suite.
    worker = threading.Thread(target=build, daemon=True)
    worker.start()
    worker.join(timeout=5)
    assert not worker.is_alive(), "the redaction kept following an Enum value that leads back to itself"
    assert caught, "positive control: the worker finished by raising, not by returning silently"
    assert [(e["loc"], e["input"]) for e in caught[0].errors()] == [(("timeout",), REDACTED_INPUT)]


@pytest.mark.os_agnostic
def test_an_input_with_more_members_than_the_walk_allows_hides_the_message() -> None:
    with pytest.raises(ValidationError) as few:
        _Creds(timeout=[f"member-{index}" for index in range(10)])  # type: ignore[arg-type]
    assert few.value.errors()[0]["msg"] != REDACTED_INPUT, "control: an input small enough to check keeps its message"
    with pytest.raises(ValidationError) as many:
        _Creds(timeout=[f"member-{index}" for index in range(5000)])  # type: ignore[arg-type]
    errors = many.value.errors()
    assert [(e["loc"], e["input"]) for e in errors] == [(("timeout",), REDACTED_INPUT)], "positive control"
    assert errors[0]["msg"] == REDACTED_INPUT, "an input with more members than the walk visits hides the message whole"


class _CountingCollection:
    """A `Collection` that counts how many members were actually pulled from it.

    `__len__` reports the real size (honest, not a lie to look small), but the
    walk under test never calls it; only `__iter__` is pulled from, one member
    at a time, so `pulls` is a deterministic proxy for how much of the input
    the walk actually visited -- no wall clock involved.
    """

    def __init__(self, size: int) -> None:
        self._size = size
        self.pulls = 0

    def __len__(self) -> int:
        return self._size

    def __contains__(self, item: object) -> bool:
        return isinstance(item, int) and 0 <= item < self._size

    def __iter__(self) -> Iterator[int]:
        for index in range(self._size):
            self.pulls += 1
            yield index


@pytest.mark.os_agnostic
def test_an_input_with_a_huge_number_of_members_is_refused_without_walking_it() -> None:
    # The walk takes members one at a time and stops after _MAX_VISITS of them
    # (plus the one that trips the bound), never materialising the rest; a
    # collection ten times that size proves the walk did not just run to
    # completion quickly.
    members = _CountingCollection(10 * _MAX_VISITS)
    with pytest.raises(ValidationError) as caught:
        _Creds(timeout=members)  # type: ignore[arg-type]
    errors = caught.value.errors()
    assert [(e["loc"], e["input"]) for e in errors] == [(("timeout",), REDACTED_INPUT)], "positive control"
    assert errors[0]["msg"] == REDACTED_INPUT, "an input too large to check hides the message whole"
    # The lower bound proves the walk really ran up to the bound: a walk that
    # gave up at once would also hide the message (through the fail-closed path).
    assert members.pulls >= _MAX_VISITS - 1, f"the walk pulled only {members.pulls} members before giving up"
    assert members.pulls <= _MAX_VISITS + 1, f"the walk pulled {members.pulls} members from a bound of {_MAX_VISITS}"


class _BrokenError:
    """Stands in for a ValidationError whose errors cannot even be listed."""

    title = "Broken"

    def errors(self, *, include_url: bool = True) -> list[object]:
        raise RuntimeError(_MODEL_DUMMY)


@pytest.mark.os_agnostic
def test_redaction_that_cannot_run_returns_one_opaque_error() -> None:
    result = redact_validation_error(cast("ValidationError", _BrokenError()), credential_fields=frozenset())
    assert isinstance(result, ValidationError), "positive control: the redaction returned instead of raising"
    assert result.errors(include_url=False) == [
        {"type": "redacted_error", "loc": (), "msg": "validation failed; the details could not be redacted and were dropped", "input": REDACTED_INPUT}
    ]
    assert _leaks(result, _MODEL_DUMMY) == []


@pytest.mark.os_agnostic
def test_assignment_errors_are_redacted_too() -> None:
    model = _Creds()
    with pytest.raises(ValidationError) as caught:
        model.password = ["x", _MODEL_DUMMY]  # type: ignore[assignment]
    assert caught.value.errors()[0]["loc"] == ("password",), "positive control"
    assert _leaks(caught.value, _MODEL_DUMMY) == []


_SEEN_CONTEXTS: list[object] = []


class _ContextProbe(SecretSafeModel):
    credential_fields = frozenset({"password"})
    password: SecretStr | None = None
    timeout: float = 30.0

    @field_validator("timeout")
    @classmethod
    def _record(cls, value: float, info: ValidationInfo) -> float:
        _SEEN_CONTEXTS.append(info.context)
        return value


@pytest.mark.os_agnostic
def test_strict_and_context_reach_the_validators() -> None:
    assert _ContextProbe.model_validate({"timeout": "5"}).timeout == 5.0, "positive control: lax mode coerces '5'"
    with pytest.raises(ValidationError):
        _ContextProbe.model_validate({"timeout": "5"}, strict=True)
    with pytest.raises(ValidationError):
        _ContextProbe.model_validate_json('{"timeout": "5"}', strict=True)
    _SEEN_CONTEXTS.clear()
    _ContextProbe.model_validate({"timeout": 5.0}, context={"caller": 1})
    _ContextProbe.model_validate_json('{"timeout": 5.0}', context={"caller": 2})
    assert _SEEN_CONTEXTS == [{"caller": 1}, {"caller": 2}]


@pytest.mark.os_agnostic
def test_the_redaction_keeps_ordinary_model_behaviour() -> None:
    model = _Creds(password=SecretStr(_MODEL_DUMMY), timeout=5.0)
    model.timeout = 7.0
    assert model.timeout == 7.0
    assert model.model_copy(update={"timeout": 9.0}).timeout == 9.0
    restored = pickle.loads(pickle.dumps(model))  # noqa: S301 - round-trips an object this test built
    assert restored == model
    assert _Creds.model_construct(timeout=1.0).timeout == 1.0
    # The wrap turns the core schema into a function-wrap schema; serialisation and
    # the JSON schema must still come from the model's own schema inside it.
    assert model.model_dump() == {"password": SecretStr(_MODEL_DUMMY), "timeout": 7.0}
    assert model.model_dump_json() == '{"password":"**********","timeout":7.0}'
    schema = _Creds.model_json_schema()
    assert schema["title"] == "_Creds"
    assert set(schema["properties"]) == {"password", "timeout"}
    assert schema["properties"]["timeout"] == {"default": 30.0, "title": "Timeout", "type": "number"}


_CONF_DUMMY = "DUMMY-PLANTED-9c1e"
_CONF_DIGITS = 918273645


@pytest.mark.os_agnostic
def test_an_all_digit_password_from_an_env_layer_is_accepted_as_text() -> None:
    config = ConfMail(smtp_username="user", smtp_password=_CONF_DIGITS)  # type: ignore[arg-type]
    assert config.resolved_credentials() == ("user", str(_CONF_DIGITS))


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("value", "needle"),
    [(["x", _CONF_DUMMY], _CONF_DUMMY), ({"k": _CONF_DUMMY}, _CONF_DUMMY), (True, "True"), (9182.73645, "9182.73645")],
    ids=["list", "dict", "bool", "float"],
)
def test_an_unusable_password_type_is_refused_without_its_value(value: object, needle: str) -> None:
    with pytest.raises(ValidationError) as caught:
        ConfMail(smtp_password=value)  # type: ignore[arg-type]
    error = caught.value.errors()[0]
    assert error["loc"] == ("smtp_password",), "positive control: the refusal is about the password"
    assert f"got {type(value).__name__}" in error["msg"]
    assert error["input"] == REDACTED_INPUT
    assert _leaks(caught.value, needle) == []


@pytest.mark.os_agnostic
def test_assigning_an_unusable_password_to_the_global_conf_is_refused_without_its_value() -> None:
    config = ConfMail()
    with pytest.raises(ValidationError) as caught:
        config.smtp_password = ["x", _CONF_DUMMY]  # type: ignore[assignment]
    assert caught.value.errors()[0]["loc"] == ("smtp_password",), "positive control"
    assert _leaks(caught.value, _CONF_DUMMY) == []


@pytest.mark.os_agnostic
def test_a_confmail_subclass_rule_does_not_quote_the_password() -> None:
    class _Strict(ConfMail):
        @model_validator(mode="after")
        def _rule(self) -> _Strict:
            if self.smtp_timeout > 100:
                raise ValueError("timeout too large")
            return self

    with pytest.raises(ValidationError) as caught:
        _Strict(smtp_password=_CONF_DUMMY, smtp_timeout=500)  # type: ignore[arg-type]
    assert "timeout too large" in str(caught.value), "positive control"
    assert _leaks(caught.value, _CONF_DUMMY) == []


_CREDENTIAL_NAME_HINTS = ("password", "token", "secret")


@pytest.mark.os_agnostic
def test_every_secret_field_of_confmail_is_a_credential_field() -> None:
    secret_fields = {
        name
        for name, info in ConfMail.model_fields.items()
        if any(marker in str(info.annotation) for marker in ("SecretStr", "SecretBytes")) or any(hint in name.lower() for hint in _CREDENTIAL_NAME_HINTS)
    }
    assert "smtp_password" in secret_fields, "positive control: the detector sees the password field"
    assert secret_fields <= ConfMail.credential_fields


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "hosts",
    [f"smtp://user:{_HOST_DUMMY}@smtp.example.com:587", ["relay.example.com", f"user:{_HOST_DUMMY}@smtp.example.com"]],
    ids=["str", "list"],
)
def test_a_confmail_host_with_userinfo_is_refused_without_quoting_it(hosts: object) -> None:
    with pytest.raises(ValidationError) as caught:
        ConfMail(smtphosts=hosts)  # type: ignore[arg-type]
    error = caught.value.errors()[0]
    assert error["loc"] == ("smtphosts",), "positive control: the refusal is about the hosts"
    assert "must not contain" in error["msg"]
    assert _leaks(caught.value, _HOST_DUMMY) == []


@pytest.mark.os_agnostic
def test_assigning_a_userinfo_host_to_the_global_conf_is_refused_without_quoting_it() -> None:
    config = ConfMail()
    with pytest.raises(ValidationError) as caught:
        config.smtphosts = [f"smtp://user:{_HOST_DUMMY}@smtp.example.com"]
    assert "must not contain" in caught.value.errors()[0]["msg"], "positive control"
    assert _leaks(caught.value, _HOST_DUMMY) == []


# A host with an embedded newline or escape sequence can forge extra log lines
# or terminal control sequences in whatever renders the per-host WARNING; a
# host is refused before it ever reaches delivery or the log.
@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "host",
    ["evil\nFORGED line", "ho\x1b[31mst", "evil\thost", "evil host"],
    ids=["newline", "escape", "tab", "interior-space"],
)
def test_a_host_with_whitespace_or_control_characters_is_refused_at_send(host: str) -> None:
    with pytest.raises(ValueError, match="whitespace or control characters") as caught:
        lib_mail.validate_smtp_host(host)
    assert "\n" not in str(caught.value)
    assert "\x1b" not in str(caught.value)


@pytest.mark.os_agnostic
def test_plain_hosts_with_only_outer_whitespace_still_validate() -> None:
    # positive control: _normalise_host trims outer whitespace before the refusal
    # check runs, so an ordinary env-file value with surrounding blanks still works.
    assert lib_mail._prepare_hosts(("  smtp.example.com  ",)) == ("smtp.example.com",)


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "hosts",
    ["evil\nFORGED line", ["good.example.com", "ho\x1b[31mst"]],
    ids=["str", "list"],
)
def test_a_confmail_host_with_whitespace_or_control_characters_is_refused(hosts: object) -> None:
    with pytest.raises(ValidationError) as caught:
        ConfMail(smtphosts=hosts)  # type: ignore[arg-type]
    error = caught.value.errors()[0]
    assert error["loc"] == ("smtphosts",), "positive control: the refusal is about the hosts"
    assert "whitespace or control characters" in error["msg"]
    # Minor 1 fix: pydantic's own `.json()` always escapes U+0000-U+001F, so
    # "\n" / "\x1b" not in .json() can never fail regardless of this
    # module's own cleaning. `_leaks` checks `str()`, `repr()`, `errors()`
    # and `.json()` together and fails if the raw offending text (which
    # ConfMail's redaction already replaces with "[redacted]") ever
    # reappears in any of them.
    assert _leaks(caught.value, "FORGED") == []
    assert _leaks(caught.value, "\x1b") == []


@pytest.mark.os_agnostic
def test_a_confmail_host_with_only_outer_whitespace_still_validates() -> None:
    # positive control: outer whitespace/quotes from an env file are trimmed,
    # not refused, mirroring test_plain_hosts_with_only_outer_whitespace_still_validate.
    config = ConfMail(smtphosts=["  smtp.example.com  "])
    assert config.smtphosts == ["smtp.example.com"]


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "hosts",
    [["evil\nFORGED line"], ["good.example.com", "evil\nFORGED line"]],
    ids=["alone", "after a good host"],
)
def test_send_refuses_a_host_with_a_control_character_before_any_delivery(hosts: list[str], caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="btx_lib_mail")
    transport = _RaisingTransport(AssertionError("transport must not be reached"))
    with pytest.raises(ValueError, match="whitespace or control characters") as caught:
        lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="rcpt@example.com",
            mail_subject="s",
            smtphosts=hosts,
            transport=transport,
        )
    assert "\n" not in str(caught.value)
    assert "FORGED line" not in caplog.text, "no delivery attempt, so no log line at all was produced"


@pytest.mark.os_agnostic
def test_the_per_host_warning_cannot_carry_a_forged_log_line_or_escape_sequence(caplog: pytest.LogCaptureFixture) -> None:
    """Defense in depth: even a host bypassing validation cannot forge the WARNING.

    ``_deliver_to_any_host`` trusts the ``hosts`` tuple it is handed and does not
    re-validate it, so this drives it directly with a value that
    ``_refuse_credentials_in_host`` would refuse, to prove the WARNING itself
    cleans the host (and the recipient) rather than relying solely on the
    upstream refusal.
    """
    caplog.set_level(logging.WARNING, logger="btx_lib_mail")
    delivery = lib_mail.DeliveryOptions(credentials=None, use_starttls=False, starttls_verify=True, timeout=5.0)

    # sender/recipient reach `email.message.EmailMessage["From"/"To"]` inside
    # `_compose_to_spool` before the WARNING is ever logged, and stdlib's
    # policy rejects a header value containing an actual newline outright
    # (ValueError, unrelated to this fix); the ESC sequence alone (no
    # newline) still exercises `isprintable()` cleaning without tripping
    # that stdlib guard. `host` is not used as a header, so it keeps CR/LF.
    ok = lib_mail._deliver_to_any_host(
        sender="sender\x1b[31mFORGED sender@example.com",
        recipient="rcpt@example.com",
        subject="s",
        plain_body="b",
        html_body="",
        hosts=("evil\nFORGED line\x1b[31m",),
        attachments=(),
        delivery=delivery,
        transport=_RaisingTransport(ValueError("boom")),
    )

    assert ok is False
    records = _failure_records(caplog)
    assert len(records) == 1, "positive control: the direct call still reaches the WARNING"
    record = records[0]
    message = record.getMessage()
    assert "evil" in message, "positive control: the host text survives, just cleaned"
    assert all(character.isprintable() for character in message)
    assert all(character.isprintable() for character in str(record.__dict__["host"])), "extras must be cleaned too"
    assert all(character.isprintable() for character in str(record.__dict__["recipient"]))
    assert "FORGED sender" in str(record.__dict__["sender"]), "positive control: sender text survives, just cleaned"
    assert all(character.isprintable() for character in str(record.__dict__["sender"])), "extra['sender'] must be cleaned too"


class _SucceedingTransport:
    """Transport double that accepts every delivery."""

    def deliver(self, *, host: str, sender: str, recipient: str, message: IO[bytes], delivery: DeliveryOptions) -> None:
        return None


_RECIPIENT_DUMMY = "dummy-planted-2f9c"


@pytest.mark.os_agnostic
def test_the_success_path_debug_line_cannot_carry_a_forged_log_line_or_escape_sequence(caplog: pytest.LogCaptureFixture) -> None:
    """Defense in depth: values bypassing send()'s own validation cannot forge the success DEBUG line either."""
    caplog.set_level(logging.DEBUG, logger="btx_lib_mail")
    delivery = lib_mail.DeliveryOptions(credentials=None, use_starttls=False, starttls_verify=True, timeout=5.0)

    # See the ESC-only note above: sender/recipient become email headers
    # inside `_compose_to_spool`, which rejects an actual newline outright;
    # `host` does not, so it keeps CR/LF.
    ok = lib_mail._deliver_to_any_host(
        sender="sender\x1b[31mFORGED sender@example.com",
        recipient="rcpt\x1b[31mFORGED recipient@example.com",
        subject="s",
        plain_body="b",
        html_body="",
        hosts=("evil\nFORGED host\x1b[31m",),
        attachments=(),
        delivery=delivery,
        transport=_SucceedingTransport(),
    )

    assert ok is True
    records = [r for r in caplog.records if r.name == "btx_lib_mail" and r.levelno == logging.DEBUG and "mail sent to" in r.msg]
    assert len(records) == 1, "positive control: the success path still logs the DEBUG line"
    record = records[0]
    message = record.getMessage()
    assert "FORGED recipient" in message, "positive control: the recipient text survives, just cleaned"
    assert "FORGED host" in message, "positive control: the host text survives, just cleaned"
    assert all(character.isprintable() for character in message)
    for key in ("sender", "recipient", "host"):
        assert all(character.isprintable() for character in str(record.__dict__[key])), f"extra[{key!r}] must be cleaned too"
    assert "FORGED sender" in str(record.__dict__["sender"]), "positive control: sender text survives, just cleaned"


@pytest.mark.os_agnostic
def test_an_invalid_recipient_warning_cannot_carry_a_forged_log_line_or_escape_sequence(caplog: pytest.LogCaptureFixture) -> None:
    """A recipient that fails validation is still logged in tolerant mode; it must not forge a log line."""
    caplog.set_level(logging.WARNING, logger="btx_lib_mail")
    forged = f"x\nwarning {_RECIPIENT_DUMMY} forged admin login ok\x1b[31m"

    ok = lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients=["good@example.com", forged],
        mail_subject="s",
        smtphosts=["smtp.example.com"],
        raise_on_invalid_recipient=False,
        transport=_SucceedingTransport(),
    )

    assert ok is True
    records = [r for r in caplog.records if r.name == "btx_lib_mail" and r.levelno == logging.WARNING and "invalid recipient" in r.msg]
    assert len(records) == 1, "positive control: the tolerant path still logs the invalid recipient"
    record = records[0]
    message = record.getMessage()
    assert _RECIPIENT_DUMMY in message, "positive control: the recipient text survives, just cleaned"
    assert all(character.isprintable() for character in message)
    assert all(character.isprintable() for character in str(record.__dict__["recipient"])), "extras must be cleaned too"


@pytest.mark.os_agnostic
def test_an_invalid_recipient_raises_a_valueerror_free_of_control_characters() -> None:
    forged = f"x\nwarning {_RECIPIENT_DUMMY} forged admin login ok\x1b[31m"

    with pytest.raises(ValueError, match="invalid recipient") as caught:
        lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients=[forged],
            mail_subject="s",
            smtphosts=["smtp.example.com"],
            raise_on_invalid_recipient=True,
            transport=_SucceedingTransport(),
        )

    text = str(caught.value)
    assert _RECIPIENT_DUMMY in text, "positive control: the recipient text survives, just cleaned"
    assert all(character.isprintable() for character in text)


_WINDOWS_FILENAME_NEWLINE_SKIP_REASON = "POSIX filenames can contain a literal newline; Windows forbids it entirely, so this file could never be created there"


@pytest.mark.os_agnostic
@pytest.mark.skipif(sys.platform.startswith("win"), reason=_WINDOWS_FILENAME_NEWLINE_SKIP_REASON)
def test_an_attachment_path_warning_cannot_carry_a_forged_log_line(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="btx_lib_mail")
    forged_name = f"evil\nFORGED {_RECIPIENT_DUMMY}.sh"
    forged_path = tmp_path / forged_name
    forged_path.write_bytes(b"not actually a script")

    ok = lib_mail.send(
        mail_from="sender@example.com",
        mail_recipients="rcpt@example.com",
        mail_subject="s",
        smtphosts=["smtp.example.com"],
        attachment_file_paths=[forged_path],
        attachment_raise_on_security_violation=False,
        transport=_SucceedingTransport(),
    )

    assert ok is True
    records = [r for r in caplog.records if r.name == "btx_lib_mail" and r.levelno == logging.WARNING and "Attachment security violation" in r.msg]
    assert len(records) == 1, "positive control: the tolerant path still logs the security violation"
    record = records[0]
    message = record.getMessage()
    assert _RECIPIENT_DUMMY in message, "positive control: the path text survives, just cleaned"
    assert all(character.isprintable() for character in message)
    assert all(character.isprintable() for character in str(record.__dict__["attachment_path"])), "extras must be cleaned too"


@pytest.mark.os_agnostic
@pytest.mark.skipif(sys.platform.startswith("win"), reason=_WINDOWS_FILENAME_NEWLINE_SKIP_REASON)
def test_an_attachment_security_error_raised_to_the_caller_cannot_carry_a_forged_line(tmp_path: Path) -> None:
    """AttachmentSecurityError propagates to the caller in strict mode (the default); str()/repr() must not forge a line either."""
    forged_name = f"evil\nFORGED {_RECIPIENT_DUMMY}.sh"
    forged_path = tmp_path / forged_name
    forged_path.write_bytes(b"not actually a script")

    with pytest.raises(lib_mail.AttachmentSecurityError) as caught:
        lib_mail.send(
            mail_from="sender@example.com",
            mail_recipients="rcpt@example.com",
            mail_subject="s",
            smtphosts=["smtp.example.com"],
            attachment_file_paths=[forged_path],
            transport=_SucceedingTransport(),
        )

    exc = caught.value
    assert _RECIPIENT_DUMMY in str(exc), "positive control: the path text survives, just cleaned"
    assert all(character.isprintable() for character in str(exc))
    assert all(character.isprintable() for character in repr(exc))
    assert all(character.isprintable() for character in exc.reason)


def _model_listing(names: object) -> type[SecretSafeModel]:
    """Define a SecretSafeModel subclass whose credential_fields is *names*."""

    class _Listing(SecretSafeModel):
        credential_fields = names  # pyright: ignore[reportAssignmentType] - the refused shapes are the point
        password: str = Field(default="", alias="pw")
        timeout: float = 30.0

    return _Listing


@pytest.mark.os_agnostic
@pytest.mark.parametrize("names", [frozenset({"password"}), {"password"}, frozenset[str]()])
def test_credential_fields_naming_declared_fields_is_accepted(names: object) -> None:
    model = _model_listing(names)

    assert model.model_validate({"pw": "x"}).model_dump()["password"] == "x"


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("names", "needle"),
    [
        pytest.param(frozenset({"pasword"}), "'pasword'", id="typo"),
        pytest.param(frozenset({"pw"}), "'pw'", id="alias-instead-of-field"),
        pytest.param(frozenset({"password", "tokn"}), "'tokn'", id="one-good-one-typo"),
    ],
)
def test_credential_fields_naming_an_undeclared_field_is_refused(names: frozenset[str], needle: str) -> None:
    with pytest.raises(TypeError, match="not a declared field") as caught:
        _model_listing(names)

    assert needle in str(caught.value)


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "names",
    [
        pytest.param("password", id="plain-str"),
        pytest.param(["password"], id="list"),
        pytest.param(frozenset({1}), id="non-str-member"),
        pytest.param(None, id="none"),
    ],
)
def test_credential_fields_that_is_not_a_set_of_names_is_refused(names: object) -> None:
    with pytest.raises(TypeError, match="set of field names"):
        _model_listing(names)


@pytest.mark.os_agnostic
def test_credential_fields_annotated_as_a_field_is_refused() -> None:
    with pytest.warns(UserWarning, match="shadows an attribute"), pytest.raises(TypeError, match="ClassVar"):

        class _Annotated(SecretSafeModel):  # pyright: ignore[reportUnusedClass]
            credential_fields: frozenset[str] = frozenset({"password"})  # pyright: ignore[reportIncompatibleVariableOverride]
            password: str = ""


class _ClassVarAnnotated(SecretSafeModel):
    credential_fields: ClassVar[frozenset[str]] = frozenset({"password"})
    password: str = ""


@pytest.mark.os_agnostic
def test_credential_fields_declared_as_an_annotated_classvar_is_accepted() -> None:
    assert "credential_fields" not in _ClassVarAnnotated.model_fields
    with pytest.raises(ValidationError) as caught:
        _ClassVarAnnotated(password=["x", _MODEL_DUMMY])  # type: ignore[arg-type]
    assert caught.value.errors()[0]["input"] == REDACTED_INPUT


@pytest.mark.os_agnostic
def test_a_subclass_inherits_and_extends_the_checked_credential_fields() -> None:
    class _Child(ConfMail):
        credential_fields = ConfMail.credential_fields | {"api_key"}
        api_key: str = ""

    class _Grandchild(_Child):
        region: str = ""

    assert _Grandchild.credential_fields == ConfMail.credential_fields | {"api_key"}
    with pytest.raises(TypeError, match="'api_kye'"):

        class _Broken(_Child):  # pyright: ignore[reportUnusedClass]
            credential_fields = _Child.credential_fields | {"api_kye"}


class _AfterChecked(SecretSafeModel):
    model_config = ConfigDict(validate_assignment=True)
    credential_fields = frozenset({"password"})
    password: str = ""
    low: int = 0
    high: int = 10

    @model_validator(mode="after")
    def _ordered(self) -> _AfterChecked:
        if self.low > self.high:
            raise ValueError("low must not exceed high")
        return self


@pytest.mark.os_agnostic
def test_an_assignment_a_model_validator_refuses_is_rolled_back() -> None:
    model = _AfterChecked(low=1)
    model.low = 5
    assert model.low == 5, "positive control: a valid assignment sticks"

    with pytest.raises(ValidationError, match="low must not exceed high"):
        model.low = 50

    assert (model.low, model.high) == (5, 10)
    assert model.model_fields_set == {"low"}


class _AfterRaisesTypeError(SecretSafeModel):
    model_config = ConfigDict(validate_assignment=True, extra="allow")
    low: int = 0
    high: int = 10

    @model_validator(mode="after")
    def _ordered(self) -> _AfterRaisesTypeError:
        if self.low > self.high:
            raise TypeError("low must not exceed high")
        return self


@pytest.mark.os_agnostic
def test_an_assignment_refused_with_a_non_validation_exception_is_rolled_back() -> None:
    model = _AfterRaisesTypeError()

    with pytest.raises(TypeError, match="low must not exceed high"):
        model.low = 50

    assert (model.low, model.high) == (0, 10)
    assert model.model_fields_set == set()


@pytest.mark.os_agnostic
def test_a_rolled_back_assignment_restores_a_field_that_was_never_set() -> None:
    model = _AfterChecked()

    with pytest.raises(ValidationError):
        model.low = 50

    assert model.low == 0
    assert model.model_fields_set == set()


class _ExtraChecked(SecretSafeModel):
    model_config = ConfigDict(validate_assignment=True, extra="allow")

    @model_validator(mode="after")
    def _no_bad_flag(self) -> _ExtraChecked:
        if (self.model_extra or {}).get("flag") == "bad":
            raise ValueError("flag must not be bad")
        return self


@pytest.mark.os_agnostic
def test_a_refused_extra_value_is_rolled_back_and_earlier_extras_are_kept() -> None:
    model = _ExtraChecked()
    model.note = "kept"  # pyright: ignore[reportAttributeAccessIssue] - extra="allow"

    with pytest.raises(ValidationError, match="flag must not be bad"):
        model.flag = "bad"  # pyright: ignore[reportAttributeAccessIssue] - extra="allow"

    assert model.model_extra == {"note": "kept"}
