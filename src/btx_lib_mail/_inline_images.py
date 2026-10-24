"""Inline (CID) images: the image types accepted, the Content-ID checks, and opening each image through the attachment checks.

An inline image is a file the HTML body shows in place, referenced as
``cid:<Content-ID>``. Each one is checked and opened exactly like an attachment
(:func:`~btx_lib_mail._attachments.prepare_attachments`), with three
differences, since the HTML refers to it:

- a violation always raises, warn mode included, and a missing or unreadable
  image is always an ``AttachmentNotFoundError``: leaving it out would leave a
  broken image in the message;
- only the types in :data:`INLINE_IMAGE_TYPES` pass, narrowed further by the
  attachment extension allowlist or blocklist in force;
- they do not count toward ``attachment_max_count``; the size limit applies to
  each one.

Private to btx_lib_mail: import the public names from `btx_lib_mail` or `btx_lib_mail.lib_mail`.
"""

from __future__ import annotations

import pathlib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Final, cast

from ._attachments import AttachmentPayload, AttachmentSecurityOptions, close_attachments, extension_as_sent, prepare_attachments
from ._common import printable
from .errors import InvalidInputError

INLINE_IMAGE_TYPES: Final[Mapping[str, str]] = MappingProxyType(
    {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".webp": "image/webp",
    }
)
"""The file extensions an inline image may have, each with the Content-Type it is sent as."""

# A Content-ID is written raw as "Content-ID: <key>"; this keeps that line far below the
# 998-octet line limit of RFC 5322.
CONTENT_ID_MAX_LENGTH: Final[int] = 250

# Printable ASCII without the space; the angle brackets enclose the Content-ID on the wire and
# the double quote would end an HTML attribute holding "cid:<key>".
_CONTENT_ID_CHARACTERS: Final[frozenset[str]] = frozenset(chr(code) for code in range(0x21, 0x7F)) - frozenset('<>"')


@dataclass(frozen=True)
class InlineImageRequest:
    """An inline image the caller asked for: its Content-ID checked, its file not opened yet.

    Attributes:
        content_id: The key the HTML references as ``cid:<content_id>``.
        path: The image file, checked and opened by :func:`prepare_inline_images`.
    """

    content_id: str
    path: pathlib.Path


@dataclass(frozen=True)
class InlineImagePayload:
    """A checked inline image, open, with the Content-ID and Content-Type it is sent under.

    Attributes:
        content_id: The key the HTML references as ``cid:<content_id>``.
        content_type: The image's MIME type, from :data:`INLINE_IMAGE_TYPES`.
        attachment: The checked file, opened once; closed by :func:`close_inline_images`.
    """

    content_id: str
    content_type: str
    attachment: AttachmentPayload


def check_content_id(content_id: object) -> str:
    """Return content_id when it can be sent as ``Content-ID: <content_id>``, refuse it otherwise.

    Args:
        content_id: A key of the caller's ``inline_images`` mapping.

    Returns:
        The Content-ID, unchanged.

    Raises:
        InvalidInputError: If content_id is not a string, is empty, is longer
            than ``CONTENT_ID_MAX_LENGTH`` characters, or holds anything but
            printable ASCII other than ``<``, ``>`` and ``"`` (whitespace and
            control characters included). The key is quoted cleaned of control
            characters, so the message cannot forge a log line.

    Examples:
        >>> check_content_id("logo@example.com")
        'logo@example.com'
        >>> check_content_id("my logo")
        Traceback (most recent call last):
            ...
        btx_lib_mail.errors.InvalidInputError: inline_images: Content-ID 'my logo' may hold only printable ASCII other than space, '<', '>' and '"'
    """
    if not isinstance(content_id, str):
        raise InvalidInputError(f"inline_images: a Content-ID must be a string, got {type(content_id).__name__}")
    if not content_id:
        raise InvalidInputError("inline_images: a Content-ID must not be empty")
    if len(content_id) > CONTENT_ID_MAX_LENGTH:
        raise InvalidInputError(f"inline_images: a Content-ID has {len(content_id)} characters, more than the {CONTENT_ID_MAX_LENGTH} allowed")
    if not _CONTENT_ID_CHARACTERS.issuperset(content_id):
        raise InvalidInputError(f"inline_images: Content-ID {printable(content_id)!r} may hold only printable ASCII other than space, '<', '>' and '\"'")
    return content_id


def coerce_inline_images(entries: object, *, html_body: object) -> tuple[InlineImageRequest, ...]:
    """Return the caller's inline images as requests, each Content-ID checked.

    Args:
        entries: The ``inline_images`` keyword, typed loosely because the
            annotation on ``send()`` is not enforced at run time. ``None`` or an
            empty mapping means no inline images.
        html_body: The ``mail_body_html`` keyword; inline images need one, since
            only HTML can reference them.

    Returns:
        The requests in the mapping's order; empty when there are none.

    Raises:
        InvalidInputError: If entries is neither ``None`` nor a mapping, a key is
            refused by :func:`check_content_id`, a value is neither a ``str`` nor
            a ``pathlib`` path, or there are images but html_body is empty.

    Examples:
        >>> [(image.content_id, image.path.name) for image in coerce_inline_images({"logo": "/srv/logo.png"}, html_body="<img src='cid:logo'>")]
        [('logo', 'logo.png')]
        >>> coerce_inline_images(None, html_body="")
        ()
    """
    if entries is None:
        return ()
    if not isinstance(entries, Mapping):
        raise InvalidInputError(f"inline_images must be a mapping of Content-ID to path, got {type(entries).__name__}")
    images = tuple(
        InlineImageRequest(content_id=check_content_id(key), path=_image_path(value)) for key, value in cast("Mapping[object, object]", entries).items()
    )
    if images and not html_body:
        raise InvalidInputError("inline_images need an HTML body that references them: mail_body_html is empty")
    return images


def _image_path(value: object) -> pathlib.Path:
    if not isinstance(value, (str, pathlib.PurePath)):
        raise InvalidInputError(f"inline_images values must be paths, got {type(value).__name__}")
    return pathlib.Path(value)


def image_security(security: AttachmentSecurityOptions) -> AttachmentSecurityOptions:
    """Return the attachment security options an inline image is checked with.

    The path, symlink, directory, name and size checks are those of the
    attachments. The extension must be an image type that the attachment
    extension policy also lets through (its allowlist when one is set, else its
    blocklist). A violation always raises, and the images do not count toward
    ``attachment_max_count``.

    Args:
        security: The attachment security options of the call.

    Returns:
        The options for the inline images.
    """
    images = frozenset(INLINE_IMAGE_TYPES)
    allowed = images & security.allowed_extensions if security.allowed_extensions is not None else images - security.blocked_extensions
    return replace(security, allowed_extensions=allowed, raise_on_violation=True, max_count=None)


def prepare_inline_images(images: tuple[InlineImageRequest, ...], security: AttachmentSecurityOptions) -> tuple[InlineImagePayload, ...]:
    """Check and open each inline image once, through the attachment checks.

    Args:
        images: The requests from :func:`coerce_inline_images`.
        security: The attachment security options of the call; narrowed by
            :func:`image_security`.

    Returns:
        One payload per image, in order, each holding its open file; the caller
        closes them (:func:`close_inline_images`). On any failure, those already
        opened are closed before the error propagates.

    Raises:
        AttachmentSecurityError: If an image breaks a security rule (warn mode
            included), its type is not an accepted image type, or the
            attachment extension policy refuses it (``EXTENSION``).
        AttachmentNotFoundError: If an image is missing or cannot be read,
            whatever ``raise_on_missing_attachments`` says.
        InvalidInputError: If a directory rule cannot be resolved.
    """
    if not images:
        return ()
    # Strict and raise_on_missing: every path yields a payload or raises, so the zip below pairs them.
    payloads = prepare_attachments(tuple(image.path for image in images), image_security(security), raise_on_missing=True)
    return tuple(
        InlineImagePayload(content_id=image.content_id, content_type=INLINE_IMAGE_TYPES[extension_as_sent(payload.filename)], attachment=payload)
        for image, payload in zip(images, payloads, strict=True)
    )


def close_inline_images(images: tuple[InlineImagePayload, ...]) -> None:
    """Close the file of every inline image."""
    close_attachments(tuple(image.attachment for image in images))


__all__ = [
    "CONTENT_ID_MAX_LENGTH",
    "INLINE_IMAGE_TYPES",
    "InlineImagePayload",
    "InlineImageRequest",
    "check_content_id",
    "close_inline_images",
    "coerce_inline_images",
    "image_security",
    "prepare_inline_images",
]
