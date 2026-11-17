"""The environments of the service and who signs their confirmations."""

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from cryptography import x509


@dataclass(frozen=True, slots=True)
class Endpoint:
    """An environment of the service: where to send, and whose confirmations to accept.

    A confirmation counts only if it is signed with a certificate that was
    issued directly by one of ``authorities``, is valid at that moment,
    belongs to the tax administration and has ``signer`` as its common name.

    The tax administration may replace its certificate at any time. If it
    does so before this library follows, make your own endpoint:
    ``dataclasses.replace(PRODUCTION, signer=...)`` for a new common name,
    ``dataclasses.replace(PRODUCTION, authorities=PRODUCTION.authorities + pem)``
    for a new issuing authority.
    """

    url: str
    """Address of the service: an ``https`` URL in plain ASCII, without a
    user name, password or fragment."""

    test: bool
    """Whether this is a test environment. Confirmations say which kind of
    environment issued them, and that must agree."""

    signer: str
    """Common name of the certificate that signs confirmations."""

    authorities: str = field(repr=False)
    """Certificates of the authorities that may have issued the signer's
    certificate, in PEM, one after another."""

    def __post_init__(self) -> None:
        if not isinstance(self.url, str):
            raise TypeError("url must be a str")
        if not isinstance(self.signer, str):
            raise TypeError("signer must be a str")
        if not isinstance(self.test, bool):
            raise TypeError("test must be a bool")
        if not _is_https_address(self.url):
            raise ValueError(f"url {self.url!r} is not a usable https address")
        if not self.signer:
            raise ValueError("signer must not be empty")
        _authorities(self)


def _is_https_address(url: str) -> bool:
    """Whether the client can use the address exactly as it is written."""
    if not re.fullmatch(r"[!-~]+", url):
        return False
    try:
        parts = urlsplit(url)
        return bool(
            parts.scheme == "https"
            and parts.hostname
            and parts.hostname.encode("idna")
            and parts.port != 0
            and parts.username is None
            and parts.password is None
            and not parts.fragment
        )
    except ValueError:
        # a port that is not a number, or a host name with an empty or
        # overlong label
        return False


def _authorities(endpoint: Endpoint) -> list[x509.Certificate]:
    if not isinstance(endpoint.authorities, str):
        raise TypeError("authorities must be a str with certificates in PEM")
    try:
        return x509.load_pem_x509_certificates(endpoint.authorities.encode())
    except (ValueError, x509.InvalidVersion) as error:
        raise ValueError("authorities holds no readable certificate in PEM") from error


# I.CA Public CA/RSA 06/2022, valid until 17 June 2032. It issued the
# certificates that sign the confirmations of both environments.
# SHA-256 of the certificate:
# df5baf6d7e1a7d14e9911c5b8c676ec6ebcad9354a74f4ac7314e133e07a94de
_ICA_PUBLIC_CA_RSA_06_2022 = """\
-----BEGIN CERTIFICATE-----
MIIHGDCCBQCgAwIBAgIEBfXlJzANBgkqhkiG9w0BAQsFADB4MSEwHwYDVQQDDBhJ
LkNBIFJvb3QgQ0EvUlNBIDA1LzIwMjIxLTArBgNVBAoMJFBydm7DrSBjZXJ0aWZp
a2HEjW7DrSBhdXRvcml0YSwgYS5zLjEXMBUGA1UEYQwOTlRSQ1otMjY0MzkzOTUx
CzAJBgNVBAYTAkNaMB4XDTIyMDYyMDEyMDAyMloXDTMyMDYxNzEyMDAyMlowejEj
MCEGA1UEAwwaSS5DQSBQdWJsaWMgQ0EvUlNBIDA2LzIwMjIxLTArBgNVBAoMJFBy
dm7DrSBjZXJ0aWZpa2HEjW7DrSBhdXRvcml0YSwgYS5zLjEXMBUGA1UEYQwOTlRS
Q1otMjY0MzkzOTUxCzAJBgNVBAYTAkNaMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
MIICCgKCAgEA0Rx1NU5khYSCByOeB4ugDclXTyL8RHQWZsoTMP3HKJ+27ugjg2DS
rsjFMgsZM7nfsGJgM53PWjhcnUSkNNX+BMQlQx8xvmy9QjOlgGvkLhMyqCnGmGmn
hyiwpBqwZIG5mcffOSfdA8zfKJFLWQwjtoZcn7rIFWHsrDg6Na8Wm2+lt3fEqKBO
z3UyoD86RrAjw9vsVbdSngwSv5CkxhJnnIesKAkfKSvzKFgvSoiNezvKf+K4fROj
itiBmh7jTt4SKK9NROnuPy72vrS6VMYPP0Y8TS86j6awU88BoIqUD7+ssL5l0kqk
MMxivKRLzwid1M1XPjOcfYnhIAXdHTdaKUoe3oSmjWE2cdqf810VhCES9ZU52vhx
K0VoCQLy0lb8ZHu+TVwR/43NwXQ/pEcNsYosrHBud+NhO/VajXHnUOv5CYr6Xvg1
rRa/qTkt1HdZLaahmWS/djLEQLe86M5CxdqYOx8LTF0CkLiWclZKESY1K/CAGG5u
GWCWgv+5TRCAu4zhqVQjRSP4XHQaMWeiZYYV2GujP3u+oTV+7awC2ONKG4GgG61y
WcAnbgD9DtBgKPIPOiCgMFPfIo7XdBGq4vgO0XVmNcps2tXbC47TyGGpKpX3NTNn
onA+iEL++n00nkKSG9x+rHb4/VU1/zdoWK5deSK6v+6QLCAdUtiUd3ECAwEAAaOC
AaYwggGiMBEGA1UdIAQKMAgwBgYEVR0gADASBgNVHRMBAf8ECDAGAQH/AgEAMA4G
A1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUX0rtVQRvqQRvkBDTqs4RPal5WgowHwYD
VR0jBBgwFoAU+87+8S3hiIuKF0aIaqm67qoibOcwgYwGA1UdHwSBhDCBgTApoCeg
JYYjaHR0cDovL3FjcmxkcDEuaWNhLmN6L3JjYTIyX3JzYS5jcmwwKaAnoCWGI2h0
dHA6Ly9xY3JsZHAyLmljYS5jei9yY2EyMl9yc2EuY3JsMCmgJ6AlhiNodHRwOi8v
cWNybGRwMy5pY2EuY3ovcmNhMjJfcnNhLmNybDBjBggrBgEFBQcBAQRXMFUwKQYI
KwYBBQUHMAKGHWh0dHA6Ly9yLmljYS5jei9yY2EyMl9yc2EuY2VyMCgGCCsGAQUF
BzABhhxodHRwOi8vb2NzcC5pY2EuY3ovcmNhMjJfcnNhMDUGA1UdJQQuMCwGCCsG
AQUFBwMEBgorBgEEAYI3CgMMBgorBgEEAYI3FAICBggrBgEFBQcDAjANBgkqhkiG
9w0BAQsFAAOCAgEAZkDVhHYJPo7TDB6kaEv4YzdieIk7tAMTMUpaO5L+Vce+t0fa
X0hBqhTmPJjs1iusoK9Vbn+jQiAmgyVPyP0fjiGlMEUjRaG1aFCEw3GFALn8x82f
39KOsyeotyo1M51yHePBseVhsMSK2ql8rwF/69OJjreLIeA/rZGedjf0b7DewIbS
UM9w4LmCBJbEGa8uDmSyeKzH5FleUZAu5vrr5ScCrg25hiR7JdpULAZ3UUgKzkLF
riW+3pUBiH74y17JMQ8lssiP719EeYVU/BvA48OM+ajeOALnenJvxKG9oammTh9m
RYQCEq4vwB6wI6m8j0uhdGhJV3l02BrVw5LlBmT6GtczhR8w0dNIG7LTbx1HB/6X
2H+j6C216bq1+fRIAtDS0UgaSoQES5ZrEivGp2n3tANCtg4WR81qnXmkl8MvPJwk
PDbZyQvzGffU5zMlw4WiqrJJXBsTthV3N6gZ/Gb89qNkjKfDNflzFZNOIbAfAaKh
fGoNRISJOY3yab0REipASvzCM2yXzG93L9Mqe2tXRSl7NJandlticjpozPYJDR14
H4qvROE989jpSUK6AVKWvjbOtEWbgTgfL9yqDiCkt+MBxcoHExK1fJ4MOzQq7s33
FOt458gmfPbWVxeB3LWtyIaNnG8N+4rkcOqG9wgw7R9oTlTVHzkD7JPr9pY=
-----END CERTIFICATE-----
"""

PLAYGROUND = Endpoint(
    url="https://pg.trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4",
    test=True,
    signer="NEOSTRE - playground prostredi EET",
    authorities=_ICA_PUBLIC_CA_RSA_06_2022,
)
"""The public test environment. It registers nothing."""

PRODUCTION = Endpoint(
    url="https://trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4",
    test=False,
    signer="Spolecne technicke zarizeni spravce dane EET",
    authorities=_ICA_PUBLIC_CA_RSA_06_2022,
)
"""The production environment."""
