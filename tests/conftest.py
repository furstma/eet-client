from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from eet_client import Certificate, Sale

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
) -> x509.Certificate:
    """A certificate for ``key``, self-signed unless an issuer is given."""
    attributes = []
    if common_name is not None:
        attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    if organization_identifier is not None:
        attributes.append(
            x509.NameAttribute(NameOID.ORGANIZATION_IDENTIFIER, organization_identifier)
        )
    if not attributes:
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, "CZ"))
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
        .sign(issuer_key or key, hashes.SHA256())
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
