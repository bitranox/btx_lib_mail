"""What each command reports in JSON mode: one model per command, dumped once by `emit`.

The field order of each model is the key order on the wire (`docs/cli.md`), so a field is
never reordered without a release note.

Private to btx_lib_mail.cli: the JSON shape, not these classes, is the contract.
"""

from __future__ import annotations

from typing import Literal, TypeAlias

from pydantic import BaseModel

__all__ = ["CommandPayload", "EmailCheck", "Greeting", "HostCheck", "PackageInfo", "SendResult"]


class _Payload(BaseModel, frozen=True, extra="forbid"):
    """Shared configuration: a payload is built once, complete, and never changed."""


class PackageInfo(_Payload, frozen=True, extra="forbid"):
    """`info`: the package metadata.

    Attributes:
        name: Distribution name.
        title: One-line description.
        version: Installed version.
        homepage: Project URL.
        author: Author name.
        author_email: Author address.
        shell_command: The console script name.
    """

    name: str
    title: str
    version: str
    homepage: str
    author: str
    author_email: str
    shell_command: str


class Greeting(_Payload, frozen=True, extra="forbid"):
    """`hello`: the canonical greeting.

    Attributes:
        greeting: The greeting text.
    """

    greeting: str


class EmailCheck(_Payload, frozen=True, extra="forbid"):
    """`validate-email`: the address that passed (a refused one is an error, not a payload).

    Attributes:
        address: The address as given.
        valid: Always ``True``; present so a caller need not infer it from the envelope.
    """

    address: str
    valid: Literal[True] = True


class HostCheck(_Payload, frozen=True, extra="forbid"):
    """`validate-smtp-host`: the host that passed (a refused one is an error, not a payload).

    Attributes:
        host: The host string as given.
        valid: Always ``True``; present so a caller need not infer it from the envelope.
    """

    host: str
    valid: Literal[True] = True


class SendResult(_Payload, frozen=True, extra="forbid"):
    """`send`: who the message went to, and through which hosts.

    Attributes:
        sender: Envelope sender.
        recipients: The recipients delivered to, in the order given (skipped ones left out).
        hosts: The configured SMTP hosts, in failover order.
    """

    sender: str
    recipients: tuple[str, ...]
    hosts: tuple[str, ...]


CommandPayload: TypeAlias = PackageInfo | Greeting | EmailCheck | HostCheck | SendResult
