"""What reporting a sale can fail with."""

from enum import IntEnum


class ErrorCode(IntEnum):
    """The documented error codes that an exception can carry.

    The signature check behind ``INVALID_SIGNATURE`` also covers the
    certificate: its issuer, its validity and its revocation.
    """

    TEMPORARY_FAILURE = -1
    INVALID_ENCODING = 2
    SCHEMA_VIOLATION = 3
    INVALID_SIGNATURE = 4
    INVALID_EIC = 6
    TOO_LARGE = 7
    NOT_PROCESSED = 8


class EETError(Exception):
    """Reporting the sale failed. Every failure is one of the two subclasses."""

    def __init__(self, message: str, *, transaction_id: str | None = None) -> None:
        super().__init__(message)
        self.transaction_id = transaction_id
        """Value of the ``X-Global-Transaction-Id`` header of the reply, if the
        service answered. The interface description recommends logging it."""


class Unavailable(EETError):
    """The sale was not confirmed this time. Report it again later, as a repeat.

    The service could not be reached, did not answer in time, answered with
    a SOAP fault or an HTTP error, or answered with error -1 or 8, for which
    the official advice is to send again later. The other negative codes are
    reserved and are treated the same. The sale may or may not have been
    registered, and reporting it again does no harm. If the same sale keeps
    failing this way, the message may be at fault.

    After a verification nothing was reported: run the verification again.
    """

    def __init__(
        self,
        message: str,
        *,
        code: int | None = None,
        transaction_id: str | None = None,
    ) -> None:
        super().__init__(message, transaction_id=transaction_id)
        self.code = code
        """Error code of the service, if this is an error that it reported."""


class InvalidReply(Unavailable):
    """A reply came, but it cannot be read or its signature cannot be trusted.

    Treat it like any ``Unavailable``. If it keeps happening, waiting will
    not help: the service has changed, something sits between it and you,
    or your clock is wrong.
    """


class Rejected(EETError):
    """The service refused the message. Sent again unchanged, it would be refused again.

    The service does not sign its error replies, so a refusal is only as
    trustworthy as the TLS connection it came over.
    """

    def __init__(
        self, code: int, text: str, *, transaction_id: str | None = None
    ) -> None:
        Exception.__init__(self, code, text)
        self.transaction_id = transaction_id
        self.code = code
        """Error code of the service, see ``ErrorCode``."""
        self.text = text
        """Description of the error, as the service worded it."""

    def __str__(self) -> str:
        return f"error {self.code}: {self.text}"
