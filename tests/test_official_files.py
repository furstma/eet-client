"""Checks against the files that the tax administration publishes.

They download from eet.gov.cz, so they run only on request: ``pytest -m live``.
"""

import base64
from collections.abc import Callable

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from eet_client import Certificate
from eet_client._signature import _canonical, verify
from eet_client._xml import DS, SOAP, WSSE, parse

pytestmark = pytest.mark.live

NS = {"soapenv": SOAP, "wsse": WSSE, "ds": DS}


@pytest.mark.parametrize("identity", ["CZ00000019", "CZ683555118", "CZ8551015704"])
def test_official_signed_sample(
    identity: str,
    playground_certificates: dict[str, Certificate],
    official_file: Callable[[str], bytes],
) -> None:
    certificate = playground_certificates[identity]
    assert certificate.common_name == identity

    sample = parse(official_file(f"{identity}.eet.v4.req.xml"))
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
