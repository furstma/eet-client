"""Checks against the files that the tax administration publishes.

They download from eet.gov.cz, so they run only on request: ``pytest -m live``.
"""

import base64
import hashlib
import io
import urllib.request
import zipfile

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from eet_client import Certificate
from eet_client._signature import _canonical, verify
from eet_client._xml import DS, SOAP, WSSE, parse

pytestmark = pytest.mark.live

SOURCE = "https://eet.gov.cz/assets/cs/cmsmedia/pro-vyvojare/"
ARCHIVE = "CAEET_Playground_2026_v1.zip"
ARCHIVE_SHA256 = "711ca591e2e58e906212befab55ea72cbc5d960af49e444765b0428751002491"
IDENTITIES = ["CZ00000019", "CZ683555118", "CZ8551015704"]
NS = {"soapenv": SOAP, "wsse": WSSE, "ds": DS}


def download(name: str) -> bytes:
    with urllib.request.urlopen(SOURCE + name, timeout=30) as response:  # noqa: S310
        data: bytes = response.read()
    return data


@pytest.fixture(scope="session")
def archive() -> dict[str, bytes]:
    """The public test certificates. They are kept in memory, never on disk."""
    data = download(ARCHIVE)
    assert hashlib.sha256(data).hexdigest() == ARCHIVE_SHA256
    with zipfile.ZipFile(io.BytesIO(data)) as files:
        return {name: files.read(name) for name in files.namelist()}


@pytest.mark.parametrize("identity", IDENTITIES)
def test_official_signed_sample(identity: str, archive: dict[str, bytes]) -> None:
    password = archive["password_pokladni_cert_playground.txt"].decode().strip()
    certificate = Certificate.from_pkcs12(
        archive[f"CA_EET-Playground-{identity}.p12"], password
    )
    assert certificate.common_name == identity

    sample = parse(download(f"{identity}.eet.v4.req.xml"))
    assert verify(sample).public_bytes(Encoding.DER) == certificate.der

    # RSA with PKCS #1 v1.5 padding is deterministic, so signing the same
    # SignedInfo with the same key must give the signature in the sample.
    [signed_info] = sample.iterfind(
        "soapenv:Header/wsse:Security/ds:Signature/ds:SignedInfo", NS
    )
    [method] = signed_info.iterfind("ds:CanonicalizationMethod", NS)
    [value] = sample.iterfind(
        "soapenv:Header/wsse:Security/ds:Signature/ds:SignatureValue", NS
    )
    assert certificate.sign(_canonical(signed_info, method)) == base64.b64decode(
        value.text or ""
    )
