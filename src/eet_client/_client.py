"""The client: builds messages, sends them and reads the replies."""

import http.client
import re
from datetime import UTC, datetime

from eet_client import _message, _transport
from eet_client._certificate import Certificate
from eet_client._endpoint import Endpoint
from eet_client._errors import InvalidReply, Unavailable
from eet_client._message import Message
from eet_client._reply import (
    Confirmation,
    Verification,
    read_confirmation,
    read_verification,
)
from eet_client._sale import Sale

_HEADERS = {
    "Content-Type": "text/xml; charset=utf-8",
    "SOAPAction": '"http://fs.gov.cz/eet/OdeslaniTrzby"',
    "User-Agent": "eet-client",
}

# The form that the interface description gives the transaction id.
_TRANSACTION_ID = re.compile(r"[!-~]{1,64}")


class Client:
    """Reports sales to one environment of the service with one certificate.

    A client keeps nothing between calls and can be shared between threads.
    Every call that sends makes one attempt over a new connection; nothing
    is repeated behind the caller's back.

    ``timeout`` is the number of seconds that an exchange with the service
    may take in all: resolving the name, connecting, sending and reading the
    reply. It cannot be less than 2 seconds, the shortest response limit
    that the law lets a taxpayer set, or more than 600.
    """

    def __init__(
        self, certificate: Certificate, endpoint: Endpoint, *, timeout: float = 5.0
    ) -> None:
        if not isinstance(certificate, Certificate):
            raise TypeError("certificate must be a Certificate")
        if not isinstance(endpoint, Endpoint):
            raise TypeError("endpoint must be an Endpoint, such as PLAYGROUND")
        if isinstance(timeout, bool) or not isinstance(timeout, int | float):
            raise TypeError("timeout must be a number of seconds")
        if not 2 <= timeout <= 600:
            raise ValueError("timeout must be between 2 and 600 seconds")
        self._certificate = certificate
        self._endpoint = endpoint
        self._timeout = timeout

    def build(self, sale: Sale, *, repeat: bool = False) -> Message:
        """Build and sign the message for one attempt to report the sale.

        Nothing is sent. Record the attempt, then pass the message to
        ``send`` right away. Pass ``repeat=True`` for every attempt after the
        first one for the same sale, whether or not the first one was sent.
        """
        return _message.build(
            sale, self._certificate, repeat=repeat, verification=False, sent_at=_now()
        )

    def send(self, message: Message) -> Confirmation:
        """Send the message and return the confirmation of the service.

        Raises ``Unavailable`` if no confirmation that can be trusted came
        back: report the sale again later, with a new message built with
        ``repeat=True``. Raises ``Rejected`` if the service refused the
        message: do not report the sale again until the cause is removed.
        Error 4 can mean the certificate, not the sale.
        """
        if not isinstance(message, Message):
            raise TypeError("message must be a Message made by build()")
        status, transaction_id, body = self._exchange(message.xml)
        try:
            _check_length(body, transaction_id)
            return read_confirmation(
                body,
                message_uuid=message.uuid,
                endpoint=self._endpoint,
                now=datetime.now(UTC),
                transaction_id=transaction_id,
            )
        except InvalidReply as error:
            if status == http.client.OK:
                raise
            raise _unreadable(error, status) from error

    def verify(self, sale: Sale) -> Verification:
        """Have the service check a message for the sale without registering it.

        The message goes out in verification mode. The service checks it the
        way it checks a real one and registers nothing. Its answer is not
        signed, so it rests on the TLS connection alone. Raises the same
        exceptions as ``send``.
        """
        message = _message.build(
            sale, self._certificate, repeat=False, verification=True, sent_at=_now()
        )
        status, transaction_id, body = self._exchange(message.xml)
        try:
            _check_length(body, transaction_id)
            return read_verification(
                body, message_uuid=message.uuid, transaction_id=transaction_id
            )
        except InvalidReply as error:
            if status == http.client.OK:
                raise
            raise _unreadable(error, status) from error

    def _exchange(self, xml: bytes) -> tuple[int, str | None, bytes]:
        """Post the message. Return the status, transaction id and body of the reply."""
        try:
            status, headers, body = _transport.post(
                self._endpoint.url, xml, _HEADERS, timeout=self._timeout
            )
        except TimeoutError as error:
            raise Unavailable(
                f"the service did not answer within {self._timeout:g} seconds: {error}"
            ) from error
        except (OSError, http.client.HTTPException) as error:
            # http.client quotes a status line that is not HTTP in full
            reason = "".join(c if c.isprintable() else " " for c in str(error)[:200])
            raise Unavailable(
                "the exchange with the service failed: "
                f"{type(error).__name__}: {reason.strip()}"
            ) from error
        transaction_id = headers.get("X-Global-Transaction-ID")
        if transaction_id is not None and not _TRANSACTION_ID.fullmatch(transaction_id):
            transaction_id = None
        return status, transaction_id, body


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _check_length(body: bytes, transaction_id: str | None) -> None:
    if len(body) > _transport.MAX_REPLY:
        raise InvalidReply(
            f"the reply is longer than {_transport.MAX_REPLY} bytes",
            transaction_id=transaction_id,
        )


def _unreadable(error: InvalidReply, status: int) -> Unavailable:
    """Name the HTTP status when a reply that is not a success cannot be read."""
    return Unavailable(
        f"the service answered with HTTP status {status}",
        transaction_id=error.transaction_id,
    )
