"""Building and signing the message that reports a sale."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime

from lxml import etree

from eet_client import _signature
from eet_client._certificate import Certificate
from eet_client._sale import Sale, _data_attributes, _timestamp
from eet_client._xml import EET, SOAP, WSU, parse


@dataclass(frozen=True, slots=True)
class Message:
    """One signed attempt to report a sale, ready to be sent.

    Every attempt needs a message of its own, with a new identifier, time of
    sending and signature. A message is meant to be sent right after it is
    built.
    """

    uuid: str
    """Identifier of this attempt (``uuid_zpravy``)."""

    sent_at: datetime
    """Time of sending that the message states (``dat_odesl``)."""

    sale: Sale
    """The sale that the message reports."""

    repeat: bool
    """False for the first attempt to report the sale, true for every later
    one (the opposite of ``prvni_zaslani``)."""

    xml: bytes = field(repr=False)
    """The signed SOAP envelope."""


def build(
    sale: Sale,
    certificate: Certificate,
    *,
    repeat: bool,
    verification: bool,
    sent_at: datetime,
) -> Message:
    """Build and sign one message for ``sale``.

    With ``verification`` the service only checks the message and registers
    nothing.
    """
    if not isinstance(sale, Sale):
        raise TypeError("sale must be a Sale")
    if not isinstance(certificate, Certificate):
        raise TypeError("certificate must be a Certificate")
    if not isinstance(repeat, bool):
        raise TypeError("repeat must be a bool")
    if not isinstance(verification, bool):
        raise TypeError("verification must be a bool")
    message_uuid = str(uuid.uuid4())

    envelope = etree.Element(f"{{{SOAP}}}Envelope", nsmap={"soapenv": SOAP, "eet": EET})
    etree.SubElement(envelope, f"{{{SOAP}}}Header")
    body = etree.SubElement(envelope, f"{{{SOAP}}}Body", nsmap={"wsu": WSU})
    trzba = etree.SubElement(body, f"{{{EET}}}Trzba")
    header = etree.SubElement(trzba, f"{{{EET}}}Hlavicka")
    header.set("uuid_zpravy", message_uuid)
    header.set("dat_odesl", _timestamp("sent_at", sent_at))
    header.set("prvni_zaslani", "false" if repeat else "true")
    if verification:
        header.set("overeni", "true")
    data = etree.SubElement(trzba, f"{{{EET}}}Data")
    for name, value in _data_attributes(sale).items():
        data.set(name, value)

    _signature.sign(envelope, certificate)
    xml = etree.tostring(envelope, xml_declaration=True, encoding="UTF-8")
    # What goes out must pass the check that replies have to pass.
    _signature.verify(parse(xml))
    return Message(
        uuid=message_uuid, sent_at=sent_at, sale=sale, repeat=repeat, xml=xml
    )
