import base64
import hashlib
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID
from lxml import etree

from eet_client import Certificate, Endpoint, Sale

PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
Issue = Callable[..., x509.Certificate]


def _issue(
    common_name: str | None,
    key: PrivateKey,
    *,
    issuer: x509.Certificate | None = None,
    issuer_key: PrivateKey | None = None,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    organization_identifier: str | None = None,
    rsa_padding: padding.PSS | None = None,
    subject: x509.Name | None = None,
) -> x509.Certificate:
    """A certificate for ``key``, self-signed unless an issuer is given.

    ``subject``, if given, replaces the name made of the other arguments.
    """
    attributes = []
    if common_name is not None:
        attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    if organization_identifier is not None:
        attributes.append(
            x509.NameAttribute(NameOID.ORGANIZATION_IDENTIFIER, organization_identifier)
        )
    if not attributes:
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, "CZ"))
    if subject is None:
        subject = x509.Name(attributes)
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - timedelta(days=1))
        .not_valid_after(not_after or now + timedelta(days=365))
        .sign(issuer_key or key, hashes.SHA256(), rsa_padding=rsa_padding)
    )


@pytest.fixture(scope="session")
def issue() -> Issue:
    return _issue


@pytest.fixture(scope="session")
def key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def other_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def x509_certificate(key: rsa.RSAPrivateKey) -> x509.Certificate:
    return _issue("CZ00000019", key)


@pytest.fixture(scope="session")
def certificate(
    key: rsa.RSAPrivateKey, x509_certificate: x509.Certificate
) -> Certificate:
    """A self-signed stand-in for a taxpayer's certificate."""
    return Certificate(key, x509_certificate)


@pytest.fixture
def sale() -> Sale:
    return Sale(
        eic="CZ00000019",
        unit_id=11,
        device_id="POS-1",
        sequence="2027/0001",
        sold_at=datetime(2027, 1, 9, 4, 25, 28, tzinfo=timezone(timedelta(hours=1))),
        total=Decimal("1500.00"),
    )


# A confirmation as the service sends it: the Signature in the default
# namespace, SignedInfo spread over lines, no prefix lists.
_CONFIRMATION = """\
<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:eet="http://fs.gov.cz/eet/schema/v4" \
xmlns:ds="http://www.w3.org/2000/09/xmldsig#" \
xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" \
xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" \
xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" \
xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" \
xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header>\
<wsse:Security soapenv:mustUnderstand="1"><wsse:BinarySecurityToken wsu:Id="SecurityToken-1" \
EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0\
#Base64Binary" \
ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3">\
</wsse:BinarySecurityToken><Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
<SignedInfo>
  <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
  <Reference URI="#Body-1">
    <Transforms>
      <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    </Transforms>
    <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <DigestValue></DigestValue>
  </Reference>
</SignedInfo>
    <SignatureValue></SignatureValue><KeyInfo><wsse:SecurityTokenReference xmlns="">\
<wsse:Reference URI="#SecurityToken-1" \
ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>\
</wsse:SecurityTokenReference></KeyInfo></Signature></wsse:Security></soapenv:Header>\
<soapenv:Body wsu:Id="Body-1">BODY</soapenv:Body></soapenv:Envelope>"""

_ERROR = """\
<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:eet="http://fs.gov.cz/eet/schema/v4" \
xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header/>\
<soapenv:Body>BODY</soapenv:Body></soapenv:Envelope>"""

_DS = "{http://www.w3.org/2000/09/xmldsig#}"


class Service:
    """Makes replies the way the service does, signed with a key made for the tests."""

    pok = "e6e9e626-3c24-4ec3-9a52-986a62bc7247-ff"

    def __init__(
        self, key: rsa.RSAPrivateKey, certificate: x509.Certificate, endpoint: Endpoint
    ) -> None:
        self.key = key
        self.certificate = certificate
        self.endpoint = endpoint

    def confirmation(
        self,
        message_uuid: str | None,
        *,
        header: str | None = None,
        outcome: str | None = None,
        warnings: Sequence[tuple[str, str]] = (),
        key: rsa.RSAPrivateKey | None = None,
        certificate: x509.Certificate | None = None,
    ) -> bytes:
        """A signed confirmation. ``header`` and ``outcome`` replace the usual elements."""
        if header is None:
            header = (
                f'<eet:Hlavicka uuid_zpravy="{message_uuid}" '
                'dat_prij="2027-01-09T04:25:31+01:00"/>'
            )
        if outcome is None:
            outcome = f'<eet:Potvrzeni pok="{self.pok}" test="true"/>'
        body = f"<eet:Odpoved>{header}{outcome}{_warnings(warnings)}</eet:Odpoved>"
        return self.sign(_CONFIRMATION.replace("BODY", body).encode(), key, certificate)

    def sign(
        self,
        data: bytes,
        key: rsa.RSAPrivateKey | None = None,
        certificate: x509.Certificate | None = None,
    ) -> bytes:
        """Fill in the certificate, the digest and the signature of an envelope."""
        root = etree.fromstring(data)
        token = root[0][0][0]
        signature = root[0][0][1]
        signed_info = signature[0]
        token.text = base64.b64encode(
            (certificate or self.certificate).public_bytes(serialization.Encoding.DER)
        ).decode()
        digest = hashlib.sha256(_canonical(root[1])).digest()
        [digest_value] = signed_info.iter(f"{_DS}DigestValue")
        digest_value.text = base64.b64encode(digest).decode()
        signature[1].text = base64.b64encode(
            (key or self.key).sign(
                _canonical(signed_info), padding.PKCS1v15(), hashes.SHA256()
            )
        ).decode()
        return etree.tostring(root, xml_declaration=True, encoding="UTF-8")

    def error(
        self,
        code: object,
        text: str = "",
        *,
        message_uuid: str | None = None,
        test: str | None = "true",
        warnings: Sequence[tuple[str, str]] = (),
    ) -> bytes:
        """An error reply. The service does not sign those."""
        uuid = f' uuid_zpravy="{message_uuid}"' if message_uuid else ""
        flag = f' test="{test}"' if test is not None else ""
        body = (
            f'<eet:Odpoved><eet:Hlavicka{uuid} dat_odmit="2027-01-09T04:25:31+01:00"/>'
            f'<eet:Chyba kod="{code}"{flag}>{text}</eet:Chyba>{_warnings(warnings)}</eet:Odpoved>'
        )
        return _ERROR.replace("BODY", body).encode()


def _warnings(warnings: Sequence[tuple[str, str]]) -> str:
    return "".join(
        f'<eet:Varovani kod_varov="{code}">{text}</eet:Varovani>'
        for code, text in warnings
    )


def _canonical(element: etree._Element) -> bytes:
    return etree.tostring(element, method="c14n", exclusive=True, with_comments=False)


@pytest.fixture(scope="session")
def authority_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def authority(authority_key: rsa.RSAPrivateKey) -> x509.Certificate:
    return _issue("Test authority", authority_key)


@pytest.fixture(scope="session")
def service(
    other_key: rsa.RSAPrivateKey,
    authority_key: rsa.RSAPrivateKey,
    authority: x509.Certificate,
) -> Service:
    """A stand-in for the service, with an endpoint that trusts its signature."""
    certificate = _issue(
        "Test signer",
        other_key,
        issuer=authority,
        issuer_key=authority_key,
        organization_identifier="NTRCZ-72080043",
    )
    endpoint = Endpoint(
        url="https://eet.example/eet/services/EETServiceSOAP/v4",
        test=True,
        signer="Test signer",
        authorities=authority.public_bytes(serialization.Encoding.PEM).decode(),
    )
    return Service(other_key, certificate, endpoint)
