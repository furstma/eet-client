"""The taxpayer's certificate and its private key."""

from datetime import datetime
from typing import Self

from cryptography import x509
from cryptography.exceptions import InternalError, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


class Certificate:
    """A certificate for sales registration together with its private key."""

    def __init__(
        self, private_key: rsa.RSAPrivateKey, certificate: x509.Certificate
    ) -> None:
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TypeError("private_key must be an RSA private key")
        if not isinstance(certificate, x509.Certificate):
            raise TypeError("certificate must be a cryptography.x509.Certificate")
        try:
            public_key = certificate.public_key()
        except (ValueError, UnsupportedAlgorithm, InternalError) as error:
            raise ValueError("the certificate's public key cannot be read") from error
        if private_key.public_key() != public_key:
            raise ValueError("the private key does not belong to the certificate")
        self._private_key = private_key
        self._certificate = certificate

    @classmethod
    def from_pkcs12(cls, data: bytes, password: str) -> Self:
        """Load the ``.p12`` file issued by the certification authority.

        ``data`` is the content of the file. Certificates of the authority
        that the file may also hold are ignored.
        """
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes, the content of the .p12 file")
        if not isinstance(password, str):
            raise TypeError("password must be a str")
        # No exception may carry the password: an encoding error holds the
        # whole text, so it is not left as the context of the one raised here.
        if "\x00" in password:
            raise ValueError("the password must not contain a NUL character")
        secret = None
        try:
            secret = password.encode()
        except UnicodeEncodeError:
            pass
        if secret is None:
            raise ValueError("the password cannot be encoded as UTF-8")
        try:
            private_key, certificate, _ = pkcs12.load_key_and_certificates(data, secret)
        except ValueError as error:
            raise ValueError(
                "cannot read the PKCS#12 data: the password is wrong, the data is damaged, "
                "or OpenSSL runs without its legacy provider"
            ) from error
        if private_key is None or certificate is None:
            raise ValueError(
                "the PKCS#12 data does not hold a private key with its certificate"
            )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            # the content of the data is at fault, not the type of an argument
            raise ValueError("the private key in the PKCS#12 data is not an RSA key")  # noqa: TRY004
        return cls(private_key, certificate)

    @property
    def common_name(self) -> str | None:
        """Common name of the subject. The certification authority puts the
        taxpayer's identifier here."""
        names = self._certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return str(names[0].value) if names else None

    @property
    def valid_from(self) -> datetime:
        """Start of the certificate's validity, in UTC."""
        return self._certificate.not_valid_before_utc

    @property
    def valid_until(self) -> datetime:
        """End of the certificate's validity, in UTC. The library does not
        check it; the service does."""
        return self._certificate.not_valid_after_utc

    @property
    def der(self) -> bytes:
        """The certificate, without the key, in DER encoding."""
        return self._certificate.public_bytes(serialization.Encoding.DER)

    def sign(self, data: bytes) -> bytes:
        """RSA signature of ``data`` with SHA-256 and PKCS #1 v1.5 padding."""
        return self._private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    def __repr__(self) -> str:
        return (
            f"<Certificate {self.common_name}, valid until {self.valid_until:%Y-%m-%d}>"
        )
