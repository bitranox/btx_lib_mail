"""Inline (CID) images: the MIME tree they build, the Content-ID round trip, and every refusal.

Messages are captured through the `RecordingTransport` double (or a real in-process SMTP server
for the wire round trip) and parsed back with the email package; nothing inside the package is
patched.
"""

from __future__ import annotations

# The growth case needs the open and compose steps on their own, since send() leaves no window
# between them for a test to act in.
# pyright: reportPrivateUsage=false
import os
import re
from email import message_from_bytes
from email import policy as email_policy
from typing import TYPE_CHECKING, Any, cast

import pytest
from smtp_test_server import BdatController, ChunkingHandler, CollectingHandler, run_server
from transport_doubles import RecordingTransport

from btx_lib_mail import (
    INLINE_IMAGE_TYPES,
    AttachmentNotFoundError,
    AttachmentSecurityError,
    AttachmentViolation,
    ConfMail,
    InvalidInputError,
    _attachments,
    _compose,
    _inline_images,
    send,
)
from btx_lib_mail import cli as cli_mod
from btx_lib_mail.cli import CliContext

if TYPE_CHECKING:
    from email.message import EmailMessage, Message
    from pathlib import Path

    from click.testing import CliRunner

# Every byte value, over more than one 57 KiB read, so a chunk seam or a text conversion shows.
_IMAGE_BYTES = bytes(range(256)) * 800
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_BOX_DRAWING = re.compile("[\u2500-\u257f]")
_HTML = '<p>Hello <img src="cid:logo"> and <img src="cid:chart@example.com"></p>'


def _image(directory: Path, name: str, data: bytes = _IMAGE_BYTES) -> Path:
    path = directory / name
    path.write_bytes(data)
    return path


def _send(transport: RecordingTransport, **kwargs: Any) -> None:
    arguments: dict[str, Any] = {
        "mail_from": "sender@example.com",
        "mail_recipients": "rcpt@example.com",
        "mail_subject": "Inline",
        "smtphosts": ["smtp.example.com"],
        # The POSIX default blocks /var, which holds the temp dir on macOS.
        "attachment_blocked_directories": frozenset(),
        "transport": transport,
    }
    arguments.update(kwargs)
    send(**arguments)


def _parsed(raw: bytes) -> EmailMessage:
    return message_from_bytes(raw, policy=email_policy.default)


def _outline(part: Message) -> object:
    """Return the MIME tree as nested ``(content_type, [children])``; a leaf is its content type."""
    if part.is_multipart():
        children = cast("list[Message]", part.get_payload())
        return (part.get_content_type(), [_outline(child) for child in children])
    return part.get_content_type()


def _image_parts(message: EmailMessage) -> list[EmailMessage]:
    return [part for part in message.walk() if part.get_content_maintype() == "image"]


def _sent_with(**kwargs: Any) -> EmailMessage:
    transport = RecordingTransport()
    _send(transport, **kwargs)
    return _parsed(transport.only.raw)


# ---------------------------------------------------------------------------
# The MIME tree
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_html_with_inline_images_is_a_related_tree(tmp_path: Path) -> None:
    message = _sent_with(
        mail_body_html=_HTML,
        inline_images={"logo": _image(tmp_path, "logo.png"), "chart@example.com": _image(tmp_path, "chart.gif")},
    )

    assert _outline(message) == ("multipart/related", ["text/html", "image/png", "image/gif"])
    assert message.get_param("type") == "text/html"
    assert message["MIME-Version"] == "1.0"


@pytest.mark.os_agnostic
def test_plain_html_and_inline_images_nest_related_inside_alternative(tmp_path: Path) -> None:
    message = _sent_with(mail_body="plain text", mail_body_html=_HTML, inline_images={"logo": _image(tmp_path, "logo.png")})

    assert _outline(message) == ("multipart/alternative", ["text/plain", ("multipart/related", ["text/html", "image/png"])])
    [related] = [part for part in message.walk() if part.get_content_type() == "multipart/related"]
    assert related.get_param("type") == "text/html"
    assert message["MIME-Version"] == "1.0"


@pytest.mark.os_agnostic
def test_html_inline_images_and_attachments_wrap_related_in_mixed(tmp_path: Path) -> None:
    message = _sent_with(
        mail_body_html=_HTML,
        inline_images={"logo": _image(tmp_path, "logo.png")},
        attachment_file_paths=[_image(tmp_path, "report.pdf", b"%PDF-1.4")],
    )

    assert _outline(message) == ("multipart/mixed", [("multipart/related", ["text/html", "image/png"]), "application/pdf"])


@pytest.mark.os_agnostic
def test_plain_html_inline_images_and_attachments_build_the_full_tree(tmp_path: Path) -> None:
    message = _sent_with(
        mail_body="plain text",
        mail_body_html=_HTML,
        inline_images={"logo": _image(tmp_path, "logo.png"), "chart@example.com": _image(tmp_path, "chart.jpg")},
        attachment_file_paths=[_image(tmp_path, "report.pdf", b"%PDF-1.4"), _image(tmp_path, "notes.txt", b"notes")],
    )

    assert _outline(message) == (
        "multipart/mixed",
        [
            ("multipart/alternative", ["text/plain", ("multipart/related", ["text/html", "image/png", "image/jpeg"])]),
            "application/pdf",
            "text/plain",
        ],
    )
    [plain] = [part for part in message.walk() if part.get_content_type() == "text/plain" and part.get_filename() is None]
    assert plain.get_content().strip() == "plain text"


@pytest.mark.os_agnostic
def test_an_empty_mapping_sends_what_none_sends(tmp_path: Path) -> None:
    with_none = _sent_with(mail_body="plain", mail_body_html=_HTML)
    with_empty = _sent_with(mail_body="plain", mail_body_html=_HTML, inline_images={})

    assert _outline(with_empty) == _outline(with_none) == ("multipart/alternative", ["text/plain", "text/html"])


@pytest.mark.os_agnostic
def test_an_empty_mapping_needs_no_html_body(tmp_path: Path) -> None:
    message = _sent_with(mail_body="plain", inline_images={})

    assert _outline(message) == "text/plain"


# ---------------------------------------------------------------------------
# Content-ID, bytes, content types, disposition
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_each_image_carries_its_key_as_content_id_and_the_html_is_unchanged(tmp_path: Path) -> None:
    message = _sent_with(
        mail_body_html=_HTML,
        inline_images={"logo": _image(tmp_path, "logo.png"), "chart@example.com": _image(tmp_path, "chart.gif")},
    )

    assert [part["Content-ID"] for part in _image_parts(message)] == ["<logo>", "<chart@example.com>"]
    [html] = [part for part in message.walk() if part.get_content_type() == "text/html"]
    # The wire carries CRLF line ends, which the parser keeps.
    assert html.get_content().rstrip("\r\n") == _HTML


@pytest.mark.os_agnostic
def test_a_long_content_id_is_written_raw_never_as_an_encoded_word(tmp_path: Path) -> None:
    # The email package encodes an over-long unstructured header as RFC 2047 encoded-words,
    # which no client would match against cid: in the HTML.
    key = "k" * 238 + "@example.com"
    assert len(key) == 250
    transport = RecordingTransport()

    _send(transport, mail_body_html=f'<img src="cid:{key}">', inline_images={key: _image(tmp_path, "logo.png")})

    assert b"Content-ID: <" + key.encode("ascii") + b">\r\n" in transport.only.raw
    [image] = _image_parts(_parsed(transport.only.raw))
    assert image["Content-ID"] == f"<{key}>"


@pytest.mark.os_agnostic
def test_every_printable_ascii_character_but_the_refused_ones_is_a_valid_content_id(tmp_path: Path) -> None:
    key = "".join(chr(code) for code in range(0x21, 0x7F) if chr(code) not in '<>"')
    transport = RecordingTransport()

    _send(transport, mail_body_html="<p>x</p>", inline_images={key: _image(tmp_path, "logo.png")})

    assert b"Content-ID: <" + key.encode("ascii") + b">\r\n" in transport.only.raw


@pytest.mark.os_agnostic
def test_the_image_bytes_round_trip_exactly(tmp_path: Path) -> None:
    message = _sent_with(mail_body_html=_HTML, inline_images={"logo": _image(tmp_path, "logo.png")})

    [image] = _image_parts(message)
    assert image["Content-Transfer-Encoding"] == "base64"
    assert image.get_content() == _IMAGE_BYTES


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("name", "content_type"),
    [
        ("a.png", "image/png"),
        ("a.PNG", "image/png"),
        ("a.jpg", "image/jpeg"),
        ("a.JPEG", "image/jpeg"),
        ("a.gif", "image/gif"),
        ("a.webp", "image/webp"),
    ],
)
def test_the_content_type_follows_the_extension_in_any_case(tmp_path: Path, name: str, content_type: str) -> None:
    message = _sent_with(mail_body_html=_HTML, inline_images={"logo": _image(tmp_path, name)})

    [image] = _image_parts(message)
    assert image.get_content_type() == content_type


@pytest.mark.os_agnostic
def test_the_accepted_types_are_published() -> None:
    assert dict(INLINE_IMAGE_TYPES) == {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".webp": "image/webp",
    }


@pytest.mark.os_agnostic
def test_an_image_is_disposed_inline_with_its_file_name(tmp_path: Path) -> None:
    message = _sent_with(mail_body_html=_HTML, inline_images={"logo": _image(tmp_path, "logo.png")})

    [image] = _image_parts(message)
    assert image.get_content_disposition() == "inline"
    assert image.get_filename() == "logo.png"


@pytest.mark.os_agnostic
def test_a_non_ascii_file_name_is_encoded_as_attachments_encode_it(tmp_path: Path) -> None:
    transport = RecordingTransport()

    _send(transport, mail_body_html=_HTML, inline_images={"logo": _image(tmp_path, "Bild März.png")})

    assert b"Content-Disposition: inline; filename*=utf-8''Bild%20M%C3%A4rz.png" in transport.only.raw
    [image] = _image_parts(_parsed(transport.only.raw))
    assert image.get_filename() == "Bild März.png"


@pytest.mark.os_agnostic
def test_a_str_path_is_accepted(tmp_path: Path) -> None:
    message = _sent_with(mail_body_html=_HTML, inline_images={"logo": str(_image(tmp_path, "logo.png"))})

    [image] = _image_parts(message)
    assert image.get_content() == _IMAGE_BYTES


@pytest.mark.os_agnostic
def test_inline_images_do_not_count_toward_attachment_max_count(tmp_path: Path) -> None:
    transport = RecordingTransport()

    _send(
        transport,
        mail_body_html=_HTML,
        inline_images={"logo": _image(tmp_path, "logo.png"), "chart@example.com": _image(tmp_path, "chart.png")},
        attachment_file_paths=[_image(tmp_path, "report.pdf", b"%PDF")],
        config=ConfMail(smtphosts=["smtp.example.com"], attachment_max_count=1),
    )

    assert len(_image_parts(_parsed(transport.only.raw))) == 2


# ---------------------------------------------------------------------------
# Refusals, each before anything is delivered
# ---------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "key",
    [
        "",
        "has space",
        "tab\there",
        "<angle>",
        "angle>",
        'quo"te',
        "ctrl\x01",
        "del\x7f",
        "nul\x00",
        "müller",
        "k" * 251,
    ],
)
def test_a_malformed_content_id_is_refused(tmp_path: Path, key: str) -> None:
    transport = RecordingTransport()

    with pytest.raises(InvalidInputError, match="Content-ID"):
        _send(transport, mail_body_html=_HTML, inline_images={key: _image(tmp_path, "logo.png")})

    assert transport.deliveries == []


@pytest.mark.os_agnostic
def test_a_malformed_content_id_is_not_echoed_raw(tmp_path: Path) -> None:
    transport = RecordingTransport()

    with pytest.raises(InvalidInputError) as caught:
        _send(transport, mail_body_html=_HTML, inline_images={"bad\r\nInjected: yes": _image(tmp_path, "logo.png")})

    assert "\r" not in str(caught.value)
    assert "\n" not in str(caught.value)


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "inline_images",
    [
        ["logo.png"],
        "logo=logo.png",
        {1: "logo.png"},
        {"logo": 42},
        {"logo": b"logo.png"},
    ],
)
def test_a_value_of_the_wrong_shape_is_refused(inline_images: object) -> None:
    transport = RecordingTransport()

    with pytest.raises(InvalidInputError, match="inline_images"):
        _send(transport, mail_body_html=_HTML, inline_images=inline_images)

    assert transport.deliveries == []


@pytest.mark.os_agnostic
def test_inline_images_need_an_html_body(tmp_path: Path) -> None:
    transport = RecordingTransport()

    with pytest.raises(InvalidInputError, match="mail_body_html"):
        _send(transport, mail_body="plain only", inline_images={"logo": _image(tmp_path, "logo.png")})

    assert transport.deliveries == []


@pytest.mark.os_agnostic
@pytest.mark.parametrize("name", ["logo.txt", "logo.svg", "logo.exe", "logo", "logo.png.sh", "logo.bmp"])
def test_a_file_that_is_not_an_accepted_image_type_is_refused_as_extension(tmp_path: Path, name: str) -> None:
    transport = RecordingTransport()

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(transport, mail_body_html=_HTML, inline_images={"logo": _image(tmp_path, name)})

    assert caught.value.violation_type is AttachmentViolation.EXTENSION
    assert transport.deliveries == []


@pytest.mark.os_agnostic
def test_the_attachment_allowlist_narrows_the_image_types(tmp_path: Path) -> None:
    transport = RecordingTransport()

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(
            transport,
            mail_body_html=_HTML,
            inline_images={"logo": _image(tmp_path, "logo.png")},
            attachment_allowed_extensions=frozenset({".pdf", ".gif"}),
        )

    assert caught.value.violation_type is AttachmentViolation.EXTENSION


@pytest.mark.os_agnostic
def test_the_attachment_blocklist_narrows_the_image_types(tmp_path: Path) -> None:
    transport = RecordingTransport()

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(
            transport,
            mail_body_html=_HTML,
            inline_images={"logo": _image(tmp_path, "logo.webp")},
            attachment_blocked_extensions=frozenset({".webp"}),
        )

    assert caught.value.violation_type is AttachmentViolation.EXTENSION


@pytest.mark.os_agnostic
@pytest.mark.parametrize("raise_on_missing", [True, False])
def test_a_missing_image_is_always_an_error(tmp_path: Path, raise_on_missing: bool) -> None:
    transport = RecordingTransport()

    with pytest.raises(AttachmentNotFoundError):
        _send(
            transport,
            mail_body_html=_HTML,
            inline_images={"logo": tmp_path / "absent.png"},
            raise_on_missing_attachments=raise_on_missing,
        )

    assert transport.deliveries == []


@pytest.mark.os_posix
def test_a_symlinked_image_is_refused(tmp_path: Path) -> None:
    link = tmp_path / "link.png"
    link.symlink_to(_image(tmp_path, "target.png"))
    transport = RecordingTransport()

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(transport, mail_body_html=_HTML, inline_images={"logo": link})

    assert caught.value.violation_type is AttachmentViolation.SYMLINK
    assert transport.deliveries == []


@pytest.mark.os_agnostic
def test_an_image_on_a_sensitive_path_is_refused(tmp_path: Path) -> None:
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    transport = RecordingTransport()

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(transport, mail_body_html=_HTML, inline_images={"logo": _image(ssh, "logo.png")})

    assert caught.value.violation_type is AttachmentViolation.SENSITIVE_PATTERN


@pytest.mark.os_agnostic
def test_an_image_in_a_blocked_directory_is_refused(tmp_path: Path) -> None:
    transport = RecordingTransport()

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(
            transport,
            mail_body_html=_HTML,
            inline_images={"logo": _image(tmp_path, "logo.png")},
            attachment_blocked_directories=frozenset({tmp_path}),
        )

    assert caught.value.violation_type is AttachmentViolation.DIRECTORY


@pytest.mark.os_agnostic
def test_a_path_with_a_traversal_component_is_refused(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    _image(tmp_path, "logo.png")
    transport = RecordingTransport()

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(transport, mail_body_html=_HTML, inline_images={"logo": tmp_path / "sub" / ".." / "logo.png"})

    assert caught.value.violation_type is AttachmentViolation.PATH_TRAVERSAL


@pytest.mark.os_posix
def test_a_file_name_with_a_control_character_is_refused(tmp_path: Path) -> None:
    transport = RecordingTransport()

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(transport, mail_body_html=_HTML, inline_images={"logo": _image(tmp_path, "lo\x1bgo.png")})

    assert caught.value.violation_type is AttachmentViolation.FILENAME


@pytest.mark.os_agnostic
def test_an_oversized_image_is_refused(tmp_path: Path) -> None:
    transport = RecordingTransport()

    with pytest.raises(AttachmentSecurityError) as caught:
        _send(transport, mail_body_html=_HTML, inline_images={"logo": _image(tmp_path, "logo.png")}, attachment_max_size_bytes=100)

    assert caught.value.violation_type is AttachmentViolation.SIZE
    assert transport.deliveries == []


@pytest.mark.os_agnostic
def test_warn_mode_does_not_drop_an_image_the_html_references(tmp_path: Path) -> None:
    transport = RecordingTransport()

    with pytest.raises(AttachmentSecurityError):
        _send(
            transport,
            mail_body_html=_HTML,
            inline_images={"logo": _image(tmp_path, "logo.png")},
            attachment_max_size_bytes=100,
            attachment_raise_on_security_violation=False,
        )

    assert transport.deliveries == []


@pytest.mark.os_agnostic
def test_a_refused_image_closes_the_attachments_already_opened(tmp_path: Path) -> None:
    attachment = _image(tmp_path, "report.pdf", b"%PDF")
    transport = RecordingTransport()

    with pytest.raises(AttachmentNotFoundError):
        _send(transport, mail_body_html=_HTML, attachment_file_paths=[attachment], inline_images={"logo": tmp_path / "absent.png"})

    # Windows refuses to delete a file that is still open.
    attachment.unlink()


@pytest.mark.os_agnostic
def test_an_image_that_grows_past_the_limit_while_read_is_refused_in_warn_mode(tmp_path: Path) -> None:
    grown = _image(tmp_path, "grown.png", b"x" * 10)
    security = _attachments.AttachmentSecurityOptions(
        allowed_extensions=None,
        blocked_extensions=frozenset(),
        allowed_directories=None,
        blocked_directories=frozenset(),
        max_size_bytes=10,
        allow_symlinks=False,
        raise_on_violation=False,
        max_count=None,
    )
    images = _inline_images.prepare_inline_images((("logo", grown),), security)
    try:
        with grown.open("ab") as grow:
            grow.write(b"y" * 200_000)
        content = _compose.MessageContent(plain_body="", html_body=_HTML, attachments=(), inline_images=images)
        with pytest.raises(AttachmentSecurityError) as caught:
            _compose.compose_body_once(content, raise_on_violation=False)
    finally:
        _inline_images.close_inline_images(images)

    assert caught.value.violation_type is AttachmentViolation.SIZE


# ---------------------------------------------------------------------------
# Over the wire: DATA and BDAT
# ---------------------------------------------------------------------------


def _deliver_through(controller: Any, tmp_path: Path) -> None:
    send(
        mail_from="sender@example.com",
        mail_recipients="rcpt@example.com",
        mail_subject="Inline over the wire",
        mail_body="plain\n.leading dot\n",
        mail_body_html=_HTML,
        smtphosts=[f"127.0.0.1:{controller.port}"],
        use_starttls=False,
        inline_images={"logo": _image(tmp_path, "logo.png"), "chart@example.com": _image(tmp_path, "chart.webp", b".\r\n.\r\n" * 1000)},
        attachment_file_paths=[_image(tmp_path, "report.pdf", b"%PDF")],
        attachment_blocked_directories=frozenset(),
    )


def _assert_round_trip(raw: bytes) -> None:
    message = _parsed(raw)
    assert _outline(message) == (
        "multipart/mixed",
        [("multipart/alternative", ["text/plain", ("multipart/related", ["text/html", "image/png", "image/webp"])]), "application/pdf"],
    )
    logo, chart = _image_parts(message)
    assert (logo["Content-ID"], logo.get_content()) == ("<logo>", _IMAGE_BYTES)
    assert (chart["Content-ID"], chart.get_content()) == ("<chart@example.com>", b".\r\n.\r\n" * 1000)


@pytest.mark.os_agnostic
def test_inline_images_round_trip_over_data(tmp_path: Path) -> None:
    handler = CollectingHandler()
    controller = run_server(handler)
    try:
        _deliver_through(controller, tmp_path)
    finally:
        controller.stop()

    [raw] = handler.messages
    _assert_round_trip(raw)


@pytest.mark.os_agnostic
def test_inline_images_round_trip_over_bdat(tmp_path: Path) -> None:
    handler = ChunkingHandler()
    controller = run_server(handler, controller_cls=BdatController)
    try:
        _deliver_through(controller, tmp_path)
    finally:
        controller.stop()

    assert handler.bdat_command_count >= 1
    [raw] = handler.messages
    _assert_round_trip(raw)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _flat(output: str) -> str:
    """Return CLI output as one line: no colour codes, no box borders, whitespace collapsed."""
    return " ".join(_BOX_DRAWING.sub(" ", _ANSI_ESCAPE.sub("", output)).split())


def _invoke(cli_runner: CliRunner, tmp_path: Path, extra: list[str]) -> tuple[Any, RecordingTransport]:
    transport = RecordingTransport()
    args = [
        "send",
        "--host",
        "smtp.example.com",
        "--recipient",
        "rcpt@example.com",
        "--subject",
        "S",
        "--body",
        "B",
        # The POSIX default blocks /var, which holds the temp dir on macOS.
        "--attachment-blocked-dir",
        str(tmp_path / "nothing-blocked-here"),
        *extra,
    ]
    result = cli_runner.invoke(cli_mod.cli, args, obj=CliContext(transport=transport))
    return result, transport


@pytest.fixture(autouse=True)
def _no_ambient_mail_settings(monkeypatch: pytest.MonkeyPatch) -> None:  # pyright: ignore[reportUnusedFunction]
    """A developer's own BTX_MAIL_* settings must not reach these tests."""
    for key in list(os.environ):
        if key.startswith("BTX_MAIL_"):
            monkeypatch.delenv(key)


@pytest.mark.os_agnostic
def test_the_cli_sends_inline_images(cli_runner: CliRunner, tmp_path: Path) -> None:
    logo = _image(tmp_path, "logo.png")
    # The value is split at the FIRST '=', so a path may hold one.
    chart = _image(tmp_path, "chart=v2.gif")

    result, transport = _invoke(
        cli_runner,
        tmp_path,
        ["--html-body", _HTML, "--inline-image", f"logo={logo}", "--inline-image", f"chart@example.com={chart}"],
    )

    assert result.exit_code == 0, result.output
    message = _parsed(transport.only.raw)
    assert _outline(message) == ("multipart/alternative", ["text/plain", ("multipart/related", ["text/html", "image/png", "image/gif"])])
    assert [(part["Content-ID"], part.get_filename()) for part in _image_parts(message)] == [("<logo>", "logo.png"), ("<chart@example.com>", "chart=v2.gif")]


@pytest.mark.os_agnostic
@pytest.mark.parametrize("value", ["no-equals-sign", "=logo.png", "logo="])
def test_a_malformed_inline_image_option_is_a_usage_error(cli_runner: CliRunner, tmp_path: Path, value: str) -> None:
    result, transport = _invoke(cli_runner, tmp_path, ["--html-body", _HTML, "--inline-image", value])

    assert result.exit_code == 2, result.output
    # The message, not only the code: an unknown option also exits 2 and names the flag.
    assert "expected CID=PATH" in _flat(result.output)
    assert transport.deliveries == []


@pytest.mark.os_agnostic
def test_a_repeated_content_id_is_a_usage_error(cli_runner: CliRunner, tmp_path: Path) -> None:
    logo = _image(tmp_path, "logo.png")

    result, transport = _invoke(cli_runner, tmp_path, ["--html-body", _HTML, "--inline-image", f"logo={logo}", "--inline-image", f"logo={logo}"])

    assert result.exit_code == 2, result.output
    assert "Content-ID 'logo' given more than once" in _flat(result.output)
    assert transport.deliveries == []


@pytest.mark.os_agnostic
def test_an_invalid_content_id_from_the_cli_is_refused_by_send(cli_runner: CliRunner, tmp_path: Path) -> None:
    logo = _image(tmp_path, "logo.png")

    result, transport = _invoke(cli_runner, tmp_path, ["--html-body", _HTML, "--inline-image", f"lo go={logo}"])

    # An InvalidInputError is a ValueError, which lib_cli_exit_tools maps to exit code 22.
    assert type(result.exception) is InvalidInputError
    assert transport.deliveries == []
