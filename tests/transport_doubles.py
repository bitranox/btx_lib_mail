"""Transport doubles shared by the test modules, checked against the `Transport` protocol.

Each test module once declared its own double; a change to the protocol could leave one of
them accepting a call the real transport no longer receives. These are declared once, and the
assignments under ``TYPE_CHECKING`` make pyright refuse them if they stop matching.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import IO, TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from btx_lib_mail import DeliveryOptions, Transport


@dataclass(frozen=True)
class Delivery:
    """One message a transport double received."""

    host: str
    sender: str
    recipient: str
    raw: bytes
    options: DeliveryOptions


class RecordingTransport:
    """Accept every message and record it; run *on_first_delivery* once, after the first one.

    The message is read from where ``send()`` left it, without a rewind of its own, so a
    message handed over part-read shows up truncated here.
    """

    def __init__(self, on_first_delivery: Callable[[], None] | None = None) -> None:
        self.deliveries: list[Delivery] = []
        self._on_first_delivery = on_first_delivery

    def deliver(self, *, host: str, sender: str, recipient: str, message: IO[bytes], delivery: DeliveryOptions) -> None:
        self.deliveries.append(Delivery(host=host, sender=sender, recipient=recipient, raw=message.read(), options=delivery))
        if self._on_first_delivery is not None:
            hook, self._on_first_delivery = self._on_first_delivery, None
            hook()

    @property
    def recipients(self) -> list[str]:
        """Return the recipient of each delivery, in order."""
        return [delivery.recipient for delivery in self.deliveries]

    @property
    def messages(self) -> dict[str, bytes]:
        """Return the raw message each recipient received."""
        return {delivery.recipient: delivery.raw for delivery in self.deliveries}

    @property
    def only(self) -> Delivery:
        """Return the single delivery, failing when there was not exactly one."""
        assert len(self.deliveries) == 1, f"expected one delivery, got {len(self.deliveries)}"
        return self.deliveries[0]


class RefusingTransport:
    """Fail every delivery with *error* (a refused connection by default), so every host fails."""

    def __init__(self, error: BaseException | None = None) -> None:
        self.error = error if error is not None else ConnectionRefusedError("refused")

    def deliver(self, *, host: str, sender: str, recipient: str, message: IO[bytes], delivery: DeliveryOptions) -> None:
        raise self.error


class PerHostTransport:
    """Fail a delivery with the error *failures* names for its (host, recipient), accept it otherwise.

    Every attempt is recorded as ``(host, recipient)`` in the order it was made, so a test sees
    which host was tried first for each recipient. A key of ``(host, None)`` fails every
    recipient on that host.
    """

    def __init__(self, failures: dict[tuple[str, str | None], BaseException]) -> None:
        self.failures = failures
        self.attempts: list[tuple[str, str]] = []

    def deliver(self, *, host: str, sender: str, recipient: str, message: IO[bytes], delivery: DeliveryOptions) -> None:
        self.attempts.append((host, recipient))
        error = self.failures.get((host, recipient), self.failures.get((host, None)))
        if error is not None:
            raise error


if TYPE_CHECKING:
    _RECORDING_IS_A_TRANSPORT: Transport = RecordingTransport()
    _REFUSING_IS_A_TRANSPORT: Transport = RefusingTransport()
    _PER_HOST_IS_A_TRANSPORT: Transport = PerHostTransport({})
