from collections.abc import Callable

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from eet_client import Certificate

Issue = Callable[..., x509.Certificate]

PASSWORD = "příliš žluťoučký"  # noqa: S105


def p12(
    key: pkcs12.PKCS12PrivateKeyTypes | None,
    certificate: x509.Certificate,
    *,
    legacy: bool = False,
) -> bytes:
    encryption: serialization.KeySerializationEncryption
    if legacy:
        # What the certification authority's files use for the key. Their
        # certificates are under 40-bit RC2, which cryptography cannot write,
        # so only the live test loads a whole file.
        encryption = (
            serialization.PrivateFormat.PKCS12.encryption_builder()
            .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
            .hmac_hash(hashes.SHA1())  # noqa: S303
            .build(PASSWORD.encode())
        )
    else:
        encryption = serialization.BestAvailableEncryption(PASSWORD.encode())
    return pkcs12.serialize_key_and_certificates(
        b"taxpayer", key, certificate, None, encryption
    )


@pytest.mark.parametrize("legacy", [False, True])
def test_from_pkcs12(
    key: rsa.RSAPrivateKey, x509_certificate: x509.Certificate, legacy: bool
) -> None:
    certificate = Certificate.from_pkcs12(
        p12(key, x509_certificate, legacy=legacy), PASSWORD
    )
    assert certificate.common_name == "CZ00000019"
    assert certificate.valid_from == x509_certificate.not_valid_before_utc
    assert certificate.valid_until == x509_certificate.not_valid_after_utc
    assert certificate.der == x509_certificate.public_bytes(serialization.Encoding.DER)


def test_from_pkcs12_ignores_the_certificates_of_the_authority(
    key: rsa.RSAPrivateKey, other_key: rsa.RSAPrivateKey, issue: Issue
) -> None:
    authority = issue("Authority", other_key)
    issued = issue("CZ00000019", key, issuer=authority, issuer_key=other_key)
    data = pkcs12.serialize_key_and_certificates(
        None,
        key,
        issued,
        [authority],
        serialization.BestAvailableEncryption(PASSWORD.encode()),
    )
    assert Certificate.from_pkcs12(data, PASSWORD).der == issued.public_bytes(
        serialization.Encoding.DER
    )


@pytest.mark.parametrize("password", ["wrong", "", PASSWORD + " "])
def test_from_pkcs12_wrong_password(
    key: rsa.RSAPrivateKey, x509_certificate: x509.Certificate, password: str
) -> None:
    with pytest.raises(ValueError, match="password is wrong"):
        Certificate.from_pkcs12(p12(key, x509_certificate), password)


@pytest.mark.parametrize(
    ("password", "message"),
    [
        ("\x00", "must not contain a NUL character"),
        (PASSWORD + "\x00", "must not contain a NUL character"),
        ("a\x00b", "must not contain a NUL character"),
        ("secret\ud800", "cannot be encoded as UTF-8"),
    ],
)
def test_from_pkcs12_password_that_cannot_be_used(
    key: rsa.RSAPrivateKey,
    x509_certificate: x509.Certificate,
    password: str,
    message: str,
    capfd: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(ValueError, match=message) as caught:
        Certificate.from_pkcs12(p12(key, x509_certificate), password)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "secret" not in str(caught.value)
    # cryptography's own refusal of a NUL prints the password on stderr
    assert capfd.readouterr().err == ""


@pytest.mark.parametrize("data", [b"", b"not a PKCS#12 file", b"\x30\x03\x02\x01\x03"])
def test_from_pkcs12_damaged_data(data: bytes) -> None:
    with pytest.raises(ValueError, match="cannot read the PKCS#12 data"):
        Certificate.from_pkcs12(data, PASSWORD)


def test_from_pkcs12_without_a_key(
    key: rsa.RSAPrivateKey, x509_certificate: x509.Certificate
) -> None:
    with pytest.raises(ValueError, match="does not hold a private key"):
        Certificate.from_pkcs12(p12(None, x509_certificate), PASSWORD)
    without_certificate = pkcs12.serialize_key_and_certificates(
        b"taxpayer",
        key,
        None,
        None,
        serialization.BestAvailableEncryption(PASSWORD.encode()),
    )
    with pytest.raises(ValueError, match="does not hold a private key"):
        Certificate.from_pkcs12(without_certificate, PASSWORD)


def test_from_pkcs12_with_another_kind_of_key(issue: Issue) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(ValueError, match="not an RSA key"):
        Certificate.from_pkcs12(p12(key, issue("CZ00000019", key)), PASSWORD)


def test_from_pkcs12_argument_types(
    key: rsa.RSAPrivateKey, x509_certificate: x509.Certificate
) -> None:
    data = p12(key, x509_certificate)
    load: Callable[..., Certificate] = Certificate.from_pkcs12
    with pytest.raises(TypeError, match="data must be bytes"):
        load("taxpayer.p12", PASSWORD)
    with pytest.raises(TypeError, match="password must be a str"):
        load(data, PASSWORD.encode())
    with pytest.raises(TypeError, match="password must be a str"):
        load(data, None)


def test_key_must_belong_to_the_certificate(
    other_key: rsa.RSAPrivateKey, x509_certificate: x509.Certificate
) -> None:
    with pytest.raises(ValueError, match="does not belong"):
        Certificate(other_key, x509_certificate)


def test_constructor_argument_types(
    key: rsa.RSAPrivateKey, x509_certificate: x509.Certificate, issue: Issue
) -> None:
    create: Callable[..., Certificate] = Certificate
    with pytest.raises(TypeError, match="private_key"):
        create(key.public_key(), x509_certificate)
    with pytest.raises(TypeError, match="private_key"):
        elliptic = ec.generate_private_key(ec.SECP256R1())
        create(elliptic, issue("CZ00000019", elliptic))
    with pytest.raises(TypeError, match="certificate"):
        create(key, x509_certificate.public_bytes(serialization.Encoding.DER))


def test_certificate_whose_key_cannot_be_read(
    key: rsa.RSAPrivateKey, x509_certificate: x509.Certificate
) -> None:
    der = x509_certificate.public_bytes(serialization.Encoding.DER)
    rsa_encryption = bytes.fromhex("2a864886f70d010101")
    assert der.count(rsa_encryption) == 1
    unknown = x509.load_der_x509_certificate(
        der.replace(rsa_encryption, rsa_encryption[:-1] + b"\x63")
    )
    with pytest.raises(ValueError, match="public key cannot be read"):
        Certificate(key, unknown)


def test_sign(certificate: Certificate, key: rsa.RSAPrivateKey) -> None:
    signature = certificate.sign(b"data")
    key.public_key().verify(signature, b"data", padding.PKCS1v15(), hashes.SHA256())
    assert certificate.sign(b"data") == signature


def test_common_name_may_be_missing(key: rsa.RSAPrivateKey, issue: Issue) -> None:
    assert Certificate(key, issue(None, key)).common_name is None


def test_repr_names_the_certificate_and_nothing_secret(
    certificate: Certificate,
) -> None:
    assert repr(certificate) == (
        f"<Certificate CZ00000019, valid until {certificate.valid_until:%Y-%m-%d}>"
    )
