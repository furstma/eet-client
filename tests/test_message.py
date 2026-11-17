import dataclasses
import re
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import pytest
from cryptography import x509
from lxml import etree

from eet_client import Certificate, Message, Sale, _signature
from eet_client._message import build
from eet_client._xml import DS, EET, SOAP, WSSE, WSU, MessageError, parse

CET = timezone(timedelta(hours=1))
SENT_AT = datetime(2027, 1, 9, 4, 25, 30, tzinfo=CET)
NS = {"soapenv": SOAP, "eet": EET, "wsse": WSSE, "ds": DS}

# uuid_zpravy as the schema defines it, with the version narrowed to 4
UUID4 = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}"
)


def make(sale: Sale, certificate: Certificate, **options: Any) -> Message:
    arguments: dict[str, Any] = {
        "repeat": False,
        "verification": False,
        "sent_at": SENT_AT,
    }
    arguments.update(options)
    return build(sale, certificate, **arguments)


def header(message: Message) -> dict[str, str]:
    [element] = parse(message.xml).iterfind("soapenv:Body/eet:Trzba/eet:Hlavicka", NS)
    return {str(name): str(value) for name, value in element.attrib.items()}


def test_message_carries_the_sale(sale: Sale, certificate: Certificate) -> None:
    message = make(sale, certificate)
    assert message.sale is sale
    assert message.sent_at == SENT_AT
    assert message.repeat is False
    assert UUID4.fullmatch(message.uuid)
    assert message.xml.startswith(b"<?xml version='1.0' encoding='UTF-8'?>")
    assert "xml=" not in repr(message)
    with pytest.raises(dataclasses.FrozenInstanceError):
        message.uuid = "another"  # type: ignore[misc]

    root = parse(message.xml)
    assert root.tag == f"{{{SOAP}}}Envelope"
    assert [etree.QName(child).localname for child in root] == ["Header", "Body"]
    [trzba] = root[1]
    assert trzba.tag == f"{{{EET}}}Trzba"
    assert [child.tag for child in trzba] == [f"{{{EET}}}Hlavicka", f"{{{EET}}}Data"]
    assert dict(trzba[0].attrib) == {
        "uuid_zpravy": message.uuid,
        "dat_odesl": "2027-01-09T04:25:30+01:00",
        "prvni_zaslani": "true",
    }
    assert dict(trzba[1].attrib) == {
        "eic_popl": "CZ00000019",
        "id_jednotky": "11",
        "id_pokl": "POS-1",
        "porad_cis": "2027/0001",
        "dat_trzby": "2027-01-09T04:25:28+01:00",
        "celk_trzba": "1500.00",
    }


def test_repeat(sale: Sale, certificate: Certificate) -> None:
    message = make(sale, certificate, repeat=True)
    assert message.repeat is True
    assert header(message)["prvni_zaslani"] == "false"
    assert "overeni" not in header(message)


def test_verification(sale: Sale, certificate: Certificate) -> None:
    message = make(sale, certificate, verification=True)
    assert header(message)["overeni"] == "true"
    assert header(message)["prvni_zaslani"] == "true"


def test_every_message_has_its_own_uuid(sale: Sale, certificate: Certificate) -> None:
    assert len({make(sale, certificate).uuid for _ in range(20)}) == 20


def test_sent_at_is_reported_in_czech_local_time(
    sale: Sale, certificate: Certificate
) -> None:
    message = make(
        sale, certificate, sent_at=datetime(2027, 6, 9, 3, 25, 28, tzinfo=UTC)
    )
    assert header(message)["dat_odesl"] == "2027-06-09T05:25:28+02:00"


@pytest.mark.parametrize(
    "sent_at",
    [
        datetime(2027, 1, 9, 4, 25, 30),  # noqa: DTZ001
        datetime(2027, 1, 9, 4, 25, 30, 5, tzinfo=CET),
    ],
)
def test_sent_at_is_validated(
    sale: Sale, certificate: Certificate, sent_at: datetime
) -> None:
    with pytest.raises(ValueError, match="sent_at"):
        make(sale, certificate, sent_at=sent_at)


def test_argument_types(sale: Sale, certificate: Certificate) -> None:
    with pytest.raises(TypeError, match="sale must be a Sale"):
        make({"eic": "CZ00000019"}, certificate)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="certificate must be a Certificate"):
        make(sale, None)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="repeat must be a bool"):
        make(sale, certificate, repeat=1)
    with pytest.raises(TypeError, match="verification must be a bool"):
        make(sale, certificate, verification="false")
    with pytest.raises(TypeError, match="sent_at"):
        make(sale, certificate, sent_at="2027-01-09T04:25:30+01:00")


def test_message_is_signed_by_the_certificate(
    sale: Sale, certificate: Certificate, x509_certificate: x509.Certificate
) -> None:
    assert _signature.verify(parse(make(sale, certificate).xml)) == x509_certificate


def test_signature_has_the_prescribed_shape(
    sale: Sale, certificate: Certificate
) -> None:
    root = parse(make(sale, certificate).xml)
    [soap_header, body] = root
    # nothing but the Security header: no Timestamp, no WS-Addressing
    [security] = soap_header
    assert security.tag == f"{{{WSSE}}}Security"
    [token, signature] = security
    assert token.tag == f"{{{WSSE}}}BinarySecurityToken"
    x509_v3 = (
        "http://docs.oasis-open.org/wss/2004/01/"
        "oasis-200401-wss-x509-token-profile-1.0#X509v3"
    )
    assert token.get("ValueType") == x509_v3
    assert token.get("EncodingType") == (
        "http://docs.oasis-open.org/wss/2004/01/"
        "oasis-200401-wss-soap-message-security-1.0#Base64Binary"
    )
    assert [etree.QName(child).localname for child in signature] == [
        "SignedInfo",
        "SignatureValue",
        "KeyInfo",
    ]

    def algorithm(path: str) -> str | None:
        [element] = signature.iterfind(path, NS)
        return element.get("Algorithm")

    assert algorithm("ds:SignedInfo/ds:CanonicalizationMethod") == _signature.EXC_C14N
    assert algorithm("ds:SignedInfo/ds:SignatureMethod") == _signature.RSA_SHA256
    assert algorithm("ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform") == (
        _signature.EXC_C14N
    )
    assert algorithm("ds:SignedInfo/ds:Reference/ds:DigestMethod") == _signature.SHA256
    [reference] = signature.iterfind("ds:SignedInfo/ds:Reference", NS)
    assert reference.get("URI") == "#" + str(body.get(f"{{{WSU}}}Id"))
    [key_reference] = signature.iterfind(
        "ds:KeyInfo/wsse:SecurityTokenReference/wsse:Reference", NS
    )
    assert key_reference.get("URI") == "#" + str(token.get(f"{{{WSU}}}Id"))
    assert key_reference.get("ValueType") == x509_v3


def test_build_checks_its_own_signature(
    sale: Sale, key: Any, x509_certificate: x509.Certificate
) -> None:
    class Broken(Certificate):
        def sign(self, data: bytes) -> bytes:
            return super().sign(data + b"x")

    with pytest.raises(MessageError, match="signature is not valid"):
        make(sale, Broken(key, x509_certificate))


def test_longest_message_is_far_below_the_size_limit(certificate: Certificate) -> None:
    longest = Sale(
        eic="CZ8551015704",
        authorizing_eic="CZ00000019",
        multiple_taxpayers=True,
        unit_id=999_999_999,
        device_id="x" * 20,
        sequence="x" * 25,
        sold_at=SENT_AT,
        total=Decimal("-99999999.99"),
        to_be_drawn=Decimal("-99999999.99"),
        drawn=Decimal("-99999999.99"),
    )
    # the service refuses messages over 12 kB
    assert len(make(longest, certificate, repeat=True, verification=True).xml) < 6000


def test_changed_message_does_not_verify(sale: Sale, certificate: Certificate) -> None:
    xml = make(sale, certificate).xml
    changed = xml.replace(b'celk_trzba="1500.00"', b'celk_trzba="1.00"')
    assert changed != xml
    with pytest.raises(MessageError, match="digest"):
        _signature.verify(parse(changed))
