import base64
import dataclasses
import hashlib
from datetime import UTC, datetime
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from eet_client import PLAYGROUND, PRODUCTION, Endpoint


def test_playground() -> None:
    assert PLAYGROUND.url == "https://pg.trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4"
    assert PLAYGROUND.test is True
    assert PLAYGROUND.signer == "NEOSTRE - playground prostredi EET"


def test_production() -> None:
    assert PRODUCTION.url == "https://trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4"
    assert PRODUCTION.test is False
    assert PRODUCTION.signer == "Spolecne technicke zarizeni spravce dane EET"


@pytest.mark.parametrize("endpoint", [PLAYGROUND, PRODUCTION])
def test_shipped_authority(endpoint: Endpoint) -> None:
    [authority] = x509.load_pem_x509_certificates(endpoint.authorities.encode())
    der = authority.public_bytes(serialization.Encoding.DER)
    assert hashlib.sha256(der).hexdigest() == (
        "df5baf6d7e1a7d14e9911c5b8c676ec6ebcad9354a74f4ac7314e133e07a94de"
    )
    [name] = authority.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert name.value == "I.CA Public CA/RSA 06/2022"
    assert authority.not_valid_after_utc == datetime(2032, 6, 17, 12, 0, 22, tzinfo=UTC)


def test_repr_leaves_the_certificates_out() -> None:
    assert repr(PLAYGROUND) == (
        "Endpoint(url='https://pg.trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4', "
        "test=True, signer='NEOSTRE - playground prostredi EET')"
    )


def test_endpoint_is_immutable_and_can_be_copied_with_changes() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        PRODUCTION.signer = "Somebody else"  # type: ignore[misc]
    changed = dataclasses.replace(PRODUCTION, signer="Somebody else")
    assert changed.signer == "Somebody else"
    assert changed.url == PRODUCTION.url
    assert PRODUCTION.signer != "Somebody else"


def make(**changes: Any) -> Endpoint:
    return dataclasses.replace(PLAYGROUND, **changes)


@pytest.mark.parametrize(
    "url",
    [
        "http://pg.trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4",
        "pg.trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4",
        "https:///eet/services/EETServiceSOAP/v4",
        "HTTP://pg.trzbyeet.gov.cz/",
        "ftp://pg.trzbyeet.gov.cz/",
        "",
        "https://pg.trzbyeet.gov.cz:0/",
        "https://pg.trzbyeet.gov.cz:99999/",
        "https://pg.trzbyeet.gov.cz:https/",
        "https://[::1/",
        "https://pg..trzbyeet.gov.cz/",
        f"https://{'x' * 64}.cz/",
        "https://user@pg.trzbyeet.gov.cz/",
        "https://user:password@pg.trzbyeet.gov.cz/",
        "https://@pg.trzbyeet.gov.cz/",
        "https://pg.trzbyeet.gov.cz/eet#v4",
        "https://pg.trzbyeet.gov.cz/eet services",
        "https://pg.trzbyeet.gov.cz/eet\n",
        " https://pg.trzbyeet.gov.cz/",
        "https://pg.trzbyeet.gov.cz/slu\u017eba",
        "https://p\u0261.trzbyeet.gov.cz/",
    ],
)
def test_url_must_be_a_usable_https_address(url: str) -> None:
    with pytest.raises(ValueError, match="not a usable https address"):
        make(url=url)


@pytest.mark.parametrize(
    "url",
    [
        "https://pg.trzbyeet.gov.cz",
        "https://pg.trzbyeet.gov.cz:8443/eet/services/EETServiceSOAP/v4?a=1",
        "HTTPS://PG.TRZBYEET.GOV.CZ/",
        "https://127.0.0.1:8443/",
        "https://[::1]:8443/eet",
    ],
)
def test_usable_urls(url: str) -> None:
    assert make(url=url).url == url


def test_authority_of_an_unknown_version(authority: x509.Certificate) -> None:
    der = authority.public_bytes(serialization.Encoding.DER)
    version_3, version_4 = bytes.fromhex("a003020102"), bytes.fromhex("a003020103")
    assert der.count(version_3) == 1
    pem = (
        "-----BEGIN CERTIFICATE-----\n"
        + base64.encodebytes(der.replace(version_3, version_4)).decode()
        + "-----END CERTIFICATE-----\n"
    )
    with pytest.raises(ValueError, match="no readable certificate"):
        make(authorities=pem)


def test_signer_must_not_be_empty() -> None:
    with pytest.raises(ValueError, match="signer must not be empty"):
        make(signer="")


@pytest.mark.parametrize(
    "authorities",
    [
        "",
        "not a certificate",
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    ],
)
def test_authorities_must_hold_a_certificate(authorities: str) -> None:
    with pytest.raises(ValueError, match="no readable certificate"):
        make(authorities=authorities)


def test_several_authorities(authority: x509.Certificate) -> None:
    pem = authority.public_bytes(serialization.Encoding.PEM).decode()
    make(authorities=PLAYGROUND.authorities + pem)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("url", b"https://pg.trzbyeet.gov.cz/"),
        ("url", None),
        ("test", "true"),
        ("test", 1),
        ("signer", None),
        ("authorities", None),
        ("authorities", PLAYGROUND.authorities.encode()),
    ],
)
def test_argument_types(field: str, value: object) -> None:
    with pytest.raises(TypeError, match=field):
        make(**{field: value})
