"""Reading the reply of the service."""

import re
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum

from cryptography import x509
from cryptography.exceptions import (
    InternalError,
    InvalidSignature,
    UnsupportedAlgorithm,
)
from cryptography.x509.oid import NameOID
from lxml import etree

from eet_client._endpoint import Endpoint, _authorities
from eet_client._errors import EETError, ErrorCode, InvalidReply, Rejected, Unavailable
from eet_client._sale import _DATETIME
from eet_client._signature import verify
from eet_client._xml import EET, SOAP, MessageError, only, parse

# The tax administration, as its certificates name it.
_ORGANIZATION = "NTRCZ-72080043"

# The masks of EETXMLSchema.xsd, version 4.1.
_UUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}"
)
_POK = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}"
    r"-[0-9a-fA-F]{2}"
)
# The masks of the interface description, 3.5.2.3 and 3.4.2.5. The schema
# only bounds the range of the two codes.
_ERROR_CODE = re.compile(r"-?[0-9]{1,3}")
_WARNING_CODE = re.compile(r"[1-9][0-9]{0,2}")

_HEADER = f"{{{EET}}}Hlavicka"
_CONFIRMATION = f"{{{EET}}}Potvrzeni"
_ERROR = f"{{{EET}}}Chyba"
_WARNING = f"{{{EET}}}Varovani"


class WarningCode(IntEnum):
    """The warning codes of the service that have a documented meaning."""

    EIC_NOT_IN_CERTIFICATE = 1
    INVALID_AUTHORIZING_EIC = 2
    SOLD_AT_IN_FUTURE = 4
    SOLD_AT_TOO_OLD = 5
    INVALID_UNIT_ID = 6
    AUTHORIZING_EIC_IS_EIC = 7


@dataclass(frozen=True, slots=True)
class ServiceWarning:
    """Something in an accepted message that the service found wrong."""

    code: int
    """Code of the warning, see ``WarningCode``."""

    text: str
    """Description of the warning, as the service worded it."""


@dataclass(frozen=True, slots=True)
class Confirmation:
    """The service confirmed the message. In production that means the sale
    is registered."""

    pok: str
    """Confirmation code of the registered message (``pok``)."""

    received_at: datetime
    """When the service received the message (``dat_prij``)."""

    message_uuid: str
    """Identifier of the message that was confirmed."""

    test: bool
    """Whether a test environment issued the confirmation. A test environment
    registers nothing and its confirmation code is not valid."""

    warnings: tuple[ServiceWarning, ...]
    """What the service found wrong with the message it accepted."""

    transaction_id: str | None
    """Value of the ``X-Global-Transaction-Id`` header of the reply."""


@dataclass(frozen=True, slots=True)
class Verification:
    """The service checked a message in verification mode and found no error.

    Nothing was registered and there is no confirmation code. The service
    does not sign this reply, so it is only as trustworthy as the TLS
    connection it came over.
    """

    message_uuid: str
    """Identifier of the message that was checked."""

    test: bool
    """Whether a test environment checked the message."""

    warnings: tuple[ServiceWarning, ...]
    """What the service would warn about."""

    transaction_id: str | None
    """Value of the ``X-Global-Transaction-Id`` header of the reply."""


def read_confirmation(
    data: bytes,
    *,
    message_uuid: str,
    endpoint: Endpoint,
    now: datetime,
    transaction_id: str | None,
) -> Confirmation:
    """Read the reply to a message that reports a sale.

    Returns the confirmation if its signature holds and its signer is the
    one the endpoint names. Raises ``Rejected`` or ``Unavailable`` for an
    error that the service reports, ``InvalidReply`` for anything else.
    """
    try:
        root, reply = _open(data, transaction_id)
        header = only(reply, _HEADER)
        outcome = _outcome(reply)
        if outcome.tag == _ERROR:
            _check_uuid(header, message_uuid, required=False)
            code, text = _error(outcome)
            if code == 0:
                raise MessageError("the answer belongs to the verification mode")
            raise _failure(code, text, transaction_id)

        # Nothing in the reply is believed before its signature and signer hold.
        _check_signer(verify(root), endpoint, now)
        _check_uuid(header, message_uuid, required=True)
        pok = outcome.get("pok", "")
        if not _POK.fullmatch(pok):
            raise MessageError(
                "the confirmation code does not have the prescribed form"
            )
        test = _boolean(outcome.get("test"))
        if test != endpoint.test:
            kind = "a test" if test else "a production"
            raise MessageError(f"the confirmation comes from {kind} environment")
        return Confirmation(
            pok=pok,
            received_at=_datetime(header.get("dat_prij")),
            message_uuid=message_uuid,
            test=test,
            warnings=_warnings(reply),
            transaction_id=transaction_id,
        )
    except MessageError as error:
        raise InvalidReply(
            f"the reply cannot be accepted: {error}", transaction_id=transaction_id
        ) from error


def read_verification(
    data: bytes, *, message_uuid: str, transaction_id: str | None
) -> Verification:
    """Read the reply to a message sent in verification mode."""
    try:
        _, reply = _open(data, transaction_id)
        header = only(reply, _HEADER)
        outcome = _outcome(reply)
        if outcome.tag == _CONFIRMATION:
            raise MessageError("a confirmation came in answer to a verification")
        _check_uuid(header, message_uuid, required=False)
        code, text = _error(outcome)
        if code != 0:
            raise _failure(code, text, transaction_id)
        return Verification(
            message_uuid=message_uuid,
            test=_boolean(outcome.get("test")),
            warnings=_warnings(reply),
            transaction_id=transaction_id,
        )
    except MessageError as error:
        raise InvalidReply(
            f"the reply cannot be accepted: {error}", transaction_id=transaction_id
        ) from error


def _open(
    data: bytes, transaction_id: str | None
) -> tuple[etree._Element, etree._Element]:
    """The envelope and the ``Odpoved`` element in its Body."""
    root = parse(data)
    if root.tag != f"{{{SOAP}}}Envelope":
        raise MessageError("not a SOAP envelope")
    body = only(root, f"{{{SOAP}}}Body")
    fault = body.find(f"{{{SOAP}}}Fault")
    if fault is not None:
        text = _text(fault.find("faultstring"))
        raise Unavailable(
            f"the service answered with a SOAP fault: {text}",
            transaction_id=transaction_id,
        )
    return root, only(body, f"{{{EET}}}Odpoved")


def _outcome(reply: etree._Element) -> etree._Element:
    """The one ``Potvrzeni`` or ``Chyba`` element of the reply."""
    outcomes = reply.findall(_CONFIRMATION) + reply.findall(_ERROR)
    if len(outcomes) != 1:
        raise MessageError(
            f"expected one Potvrzeni or Chyba element, found {len(outcomes)}"
        )
    return outcomes[0]


def _check_uuid(header: etree._Element, message_uuid: str, *, required: bool) -> None:
    value = header.get("uuid_zpravy")
    if value is None and not required:
        return
    if value is None or not _UUID.fullmatch(value):
        raise MessageError("the reply does not name the message it answers")
    if value.lower() != message_uuid.lower():
        raise MessageError("the reply answers another message")


def _error(element: etree._Element) -> tuple[int, str]:
    code = element.get("kod", "")
    if not _ERROR_CODE.fullmatch(code):
        raise MessageError("the error code is not a number of at most three digits")
    return int(code), _text(element)


def _failure(code: int, text: str, transaction_id: str | None) -> EETError:
    # -1 is the temporary failure; the other negative codes are reserved and
    # are treated the same. For code 8 the only official advice is to send
    # again later, the same as for -1.
    if code < 0 or code == ErrorCode.NOT_PROCESSED:
        return Unavailable(
            f"the service answered with error {code}: {text}",
            code=code,
            transaction_id=transaction_id,
        )
    return Rejected(code, text, transaction_id=transaction_id)


def _warnings(reply: etree._Element) -> tuple[ServiceWarning, ...]:
    warnings = []
    for element in reply.findall(_WARNING):
        code = element.get("kod_varov", "")
        if not _WARNING_CODE.fullmatch(code):
            raise MessageError("a warning code is not a number from 1 to 999")
        warnings.append(ServiceWarning(code=int(code), text=_text(element)))
    return tuple(warnings)


def _text(element: etree._Element | None) -> str:
    """The text of an element, with whitespace collapsed."""
    if element is None:
        return ""
    return " ".join((element.text or "").split())


def _boolean(value: str | None) -> bool:
    """An optional xs:boolean attribute that means false when it is absent."""
    if value is None:
        return False
    value = value.strip()
    if value in ("true", "1"):
        return True
    if value in ("false", "0"):
        return False
    raise MessageError("the test flag is not a boolean")


def _datetime(value: str | None) -> datetime:
    if value is None or not _DATETIME.fullmatch(value):
        raise MessageError(
            "the time of receipt is missing or does not have the prescribed form"
        )
    try:
        return datetime.fromisoformat(value)
    except ValueError as error:
        raise MessageError(
            "the time of receipt is not a valid date and time"
        ) from error


def _check_signer(signer: x509.Certificate, endpoint: Endpoint, now: datetime) -> None:
    """Accept the certificate only as the one that signs for this endpoint."""
    try:
        valid = signer.not_valid_before_utc <= now <= signer.not_valid_after_utc
    except ValueError:  # a date that a datetime cannot hold
        valid = False
    if not valid:
        raise MessageError("the signer's certificate is not valid at this time")
    if not any(
        _issued_by(signer, authority, now) for authority in _authorities(endpoint)
    ):
        raise MessageError(
            "the signer's certificate was not issued by an accepted authority"
        )
    if _subject(signer, NameOID.ORGANIZATION_IDENTIFIER) != [_ORGANIZATION]:
        raise MessageError(
            "the signer's certificate does not belong to the tax administration"
        )
    names = _subject(signer, NameOID.COMMON_NAME)
    if names != [endpoint.signer]:
        raise MessageError(
            "the signer's certificate is not the one this endpoint signs with, "
            f"its common name is {names}"
        )


def _issued_by(
    signer: x509.Certificate, authority: x509.Certificate, now: datetime
) -> bool:
    if not authority.not_valid_before_utc <= now <= authority.not_valid_after_utc:
        return False
    try:
        signer.verify_directly_issued_by(authority)
    except (
        ValueError,
        TypeError,
        InvalidSignature,
        UnsupportedAlgorithm,
        InternalError,
    ):
        return False
    return True


def _subject(
    certificate: x509.Certificate, oid: x509.ObjectIdentifier
) -> list[str | bytes]:
    return [
        attribute.value for attribute in certificate.subject.get_attributes_for_oid(oid)
    ]
