"""Guards that keep SMTP credentials out of logs, exception texts and validation errors.

Every secret here is a planted dummy. Every absence assertion is preceded by a
positive control proving the thing searched was actually produced.
"""

from __future__ import annotations

# Tests reach module internals (the failure describer, the transport seam) on purpose.
# pyright: reportPrivateUsage=false
import ast
import logging
import pickle
import smtplib
from pathlib import Path
from typing import IO, TYPE_CHECKING

import pytest
from pydantic import (
    AliasChoices,
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
from btx_lib_mail import REDACTED_INPUT, SecretSafeModel, lib_mail

if TYPE_CHECKING:
    from collections.abc import Callable

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
    [[f"smtp://user:{_HOST_DUMMY}@smtp.example.com:587"], [f"smtp://user:{_HOST_DUMMY}@smtp.example.com:587", "good.example.com"]],
    ids=["alone", "before a good host"],
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
    assert _HOST_DUMMY not in caplog.text


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
    ("custom error type", lambda: _CredsWithCustomRule(password=_MODEL_DUMMY), _MODEL_DUMMY),  # type: ignore[arg-type]
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


@pytest.mark.os_agnostic
def test_a_redacted_error_keeps_type_location_and_message() -> None:
    with pytest.raises(ValidationError) as caught:
        _CredsWithCustomRule(password=_MODEL_DUMMY)  # type: ignore[arg-type]
    error = caught.value.errors()[0]
    assert error["type"] == "my_rule"
    assert error["msg"] == "custom thing broke"
    assert error["input"] == REDACTED_INPUT


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
