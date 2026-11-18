"""The verifier against changed, rearranged and forged messages."""

import base64
import copy
import hashlib
from collections.abc import Callable
from datetime import UTC, datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from lxml import etree

from eet_client import Certificate, Sale
from eet_client._message import build
from eet_client._signature import EXC_C14N, verify
from eet_client._xml import DS, EET, SOAP, WSSE, WSU, MessageError, parse

Issue = Callable[..., x509.Certificate]

NS = {"soapenv": SOAP, "eet": EET, "wsse": WSSE, "ds": DS, "ec": EXC_C14N}
WSU_ID = f"{{{WSU}}}Id"

SIGNATURE = "soapenv:Header/wsse:Security/ds:Signature"
SIGNED_INFO = f"{SIGNATURE}/ds:SignedInfo"
REFERENCE = f"{SIGNED_INFO}/ds:Reference"
CERTIFICATE = "soapenv:Header/wsse:Security/wsse:BinarySecurityToken"
KEY_REFERENCE = f"{SIGNATURE}/ds:KeyInfo/wsse:SecurityTokenReference/wsse:Reference"

# every element that the signature consists of, and the Body it covers
PARTS = [
    "soapenv:Header",
    "soapenv:Header/wsse:Security",
    CERTIFICATE,
    SIGNATURE,
    SIGNED_INFO,
    f"{SIGNED_INFO}/ds:CanonicalizationMethod",
    f"{SIGNED_INFO}/ds:SignatureMethod",
    REFERENCE,
    f"{REFERENCE}/ds:Transforms",
    f"{REFERENCE}/ds:Transforms/ds:Transform",
    f"{REFERENCE}/ds:DigestMethod",
    f"{REFERENCE}/ds:DigestValue",
    f"{SIGNATURE}/ds:SignatureValue",
    f"{SIGNATURE}/ds:KeyInfo",
    f"{SIGNATURE}/ds:KeyInfo/wsse:SecurityTokenReference",
    KEY_REFERENCE,
    "soapenv:Body",
]


@pytest.fixture
def root(sale: Sale, certificate: Certificate) -> etree._Element:
    """A signed message, parsed."""
    sent_at = datetime(2027, 1, 9, 3, 25, 30, tzinfo=UTC)
    message = build(
        sale, certificate, repeat=False, verification=False, sent_at=sent_at
    )
    return parse(message.xml)


def one(root: etree._Element, path: str) -> etree._Element:
    [element] = root.iterfind(path, NS)
    return element


def check(root: etree._Element) -> x509.Certificate:
    """Verify the message the way a receiver gets it: as bytes."""
    return verify(parse(etree.tostring(root)))


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def canonical(element: etree._Element, method: etree._Element) -> bytes:
    prefixes = [
        prefix
        for inclusive in method.iterfind("ec:InclusiveNamespaces", NS)
        for prefix in inclusive.get("PrefixList", "").split()
    ]
    return etree.tostring(
        element,
        method="c14n",
        exclusive=True,
        with_comments=False,
        inclusive_ns_prefixes=prefixes or None,
    )


def resign(
    root: etree._Element,
    key: rsa.RSAPrivateKey,
    certificate: x509.Certificate | None = None,
) -> etree._Element:
    """Sign the message again as it stands now, as another implementation would."""
    root = parse(etree.tostring(root))
    if certificate is not None:
        one(root, CERTIFICATE).text = b64(
            certificate.public_bytes(serialization.Encoding.DER)
        )
    transform = one(root, f"{REFERENCE}/ds:Transforms/ds:Transform")
    digest = hashlib.sha256(canonical(one(root, "soapenv:Body"), transform)).digest()
    one(root, f"{REFERENCE}/ds:DigestValue").text = b64(digest)
    signed_info = canonical(
        one(root, SIGNED_INFO), one(root, f"{SIGNED_INFO}/ds:CanonicalizationMethod")
    )
    one(root, f"{SIGNATURE}/ds:SignatureValue").text = b64(
        key.sign(signed_info, padding.PKCS1v15(), hashes.SHA256())
    )
    return root


def forged_body(root: etree._Element) -> etree._Element:
    """A copy of the Body that reports another amount."""
    forged = copy.deepcopy(one(root, "soapenv:Body"))
    one(forged, "eet:Trzba/eet:Data").set("celk_trzba", "1.00")
    return forged


def test_untouched_message_verifies(
    root: etree._Element, x509_certificate: x509.Certificate
) -> None:
    assert check(root) == x509_certificate


def test_changed_body(root: etree._Element) -> None:
    one(root, "soapenv:Body/eet:Trzba/eet:Data").set("celk_trzba", "1.00")
    with pytest.raises(MessageError, match="does not match its digest"):
        check(root)


def test_added_element_in_the_body(root: etree._Element) -> None:
    etree.SubElement(one(root, "soapenv:Body"), f"{{{EET}}}Data")
    with pytest.raises(MessageError, match="does not match its digest"):
        check(root)


def test_changed_body_with_its_digest_recomputed(root: etree._Element) -> None:
    body = one(root, "soapenv:Body")
    one(body, "eet:Trzba/eet:Data").set("celk_trzba", "1.00")
    transform = one(root, f"{REFERENCE}/ds:Transforms/ds:Transform")
    digest = hashlib.sha256(canonical(parse(etree.tostring(body)), transform)).digest()
    one(root, f"{REFERENCE}/ds:DigestValue").text = b64(digest)
    with pytest.raises(MessageError, match="signature is not valid"):
        check(root)


def test_changed_signature_value(root: etree._Element) -> None:
    value = one(root, f"{SIGNATURE}/ds:SignatureValue")
    signature = bytearray(base64.b64decode(value.text or ""))
    signature[-1] ^= 1
    value.text = b64(bytes(signature))
    with pytest.raises(MessageError, match="signature is not valid"):
        check(root)


def test_certificate_swapped_without_signing_again(
    root: etree._Element, other_key: rsa.RSAPrivateKey, issue: Issue
) -> None:
    other = issue("CZ00000019", other_key)
    one(root, CERTIFICATE).text = b64(other.public_bytes(serialization.Encoding.DER))
    with pytest.raises(MessageError, match="signature is not valid"):
        check(root)


def test_verify_names_the_signer_and_leaves_trust_to_the_caller(
    root: etree._Element,
    other_key: rsa.RSAPrivateKey,
    issue: Issue,
    x509_certificate: x509.Certificate,
) -> None:
    forger = issue("CZ00000019", other_key)
    one(root, "soapenv:Body/eet:Trzba/eet:Data").set("celk_trzba", "1.00")
    signer = check(resign(root, other_key, forger))
    assert signer == forger
    assert signer != x509_certificate


def test_wrapping_signed_body_moved_into_the_header(root: etree._Element) -> None:
    signed = one(root, "soapenv:Body")
    forged = forged_body(root)
    del forged.attrib[WSU_ID]
    root.replace(signed, forged)
    etree.SubElement(one(root, "soapenv:Header"), "Wrapper").append(signed)
    with pytest.raises(MessageError, match="does not cover the SOAP Body"):
        check(root)


def test_wrapping_forged_body_with_another_id(root: etree._Element) -> None:
    signed = one(root, "soapenv:Body")
    forged = forged_body(root)
    forged.set(WSU_ID, "other")
    root.replace(signed, forged)
    etree.SubElement(one(root, "soapenv:Header"), "Wrapper").append(signed)
    with pytest.raises(MessageError, match="does not cover the SOAP Body"):
        check(root)


def test_wrapping_forged_body_with_the_same_id(root: etree._Element) -> None:
    signed = one(root, "soapenv:Body")
    root.replace(signed, forged_body(root))
    etree.SubElement(one(root, "soapenv:Header"), "Wrapper").append(signed)
    with pytest.raises(MessageError, match="does not match its digest"):
        check(root)


def test_wrapping_signed_body_inside_the_forged_one(root: etree._Element) -> None:
    signed = one(root, "soapenv:Body")
    forged = forged_body(root)
    del forged.attrib[WSU_ID]
    root.replace(signed, forged)
    forged.append(signed)
    with pytest.raises(MessageError, match="does not cover the SOAP Body"):
        check(root)


def test_wrapping_signed_body_inside_the_signature(root: etree._Element) -> None:
    signed = one(root, "soapenv:Body")
    root.replace(signed, forged_body(root))
    etree.SubElement(one(root, SIGNATURE), f"{{{DS}}}Object").append(signed)
    with pytest.raises(MessageError, match="does not match its digest"):
        check(root)


@pytest.mark.parametrize("path", PARTS)
def test_missing_part(root: etree._Element, path: str) -> None:
    element = one(root, path)
    parent = element.getparent()
    assert parent is not None
    parent.remove(element)
    name = etree.QName(element).localname
    with pytest.raises(MessageError, match=f"expected one {name} element, found 0"):
        check(root)


@pytest.mark.parametrize("path", PARTS)
def test_doubled_part(root: etree._Element, path: str) -> None:
    element = one(root, path)
    element.addnext(copy.deepcopy(element))
    name = etree.QName(element).localname
    with pytest.raises(MessageError, match=f"expected one {name} element, found 2"):
        check(root)


@pytest.mark.parametrize(
    ("path", "algorithm", "message"),
    [
        (
            f"{SIGNED_INFO}/ds:SignatureMethod",
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            "signature method is not RSA with SHA-256",
        ),
        (
            f"{REFERENCE}/ds:DigestMethod",
            "http://www.w3.org/2000/09/xmldsig#sha1",
            "digest method is not SHA-256",
        ),
        (
            f"{REFERENCE}/ds:Transforms/ds:Transform",
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "canonicalization is not exclusive C14N",
        ),
        (
            f"{SIGNED_INFO}/ds:CanonicalizationMethod",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            "canonicalization is not exclusive C14N",
        ),
    ],
)
def test_other_algorithm(
    root: etree._Element, path: str, algorithm: str, message: str
) -> None:
    element = one(root, path)
    element.set("Algorithm", algorithm)
    with pytest.raises(MessageError, match=message):
        check(root)
    del element.attrib["Algorithm"]
    with pytest.raises(MessageError, match=message):
        check(root)


@pytest.mark.parametrize("uri", ["", "#", "#other", "body", None])
def test_reference_to_something_else(root: etree._Element, uri: str | None) -> None:
    reference = one(root, REFERENCE)
    if uri is None:
        del reference.attrib["URI"]
    else:
        reference.set("URI", uri)
    with pytest.raises(MessageError, match="does not cover the SOAP Body"):
        check(root)


def test_body_without_an_id(root: etree._Element) -> None:
    del one(root, "soapenv:Body").attrib[WSU_ID]
    with pytest.raises(MessageError, match="does not cover the SOAP Body"):
        check(root)


def test_body_and_reference_with_an_empty_id(root: etree._Element) -> None:
    one(root, "soapenv:Body").set(WSU_ID, "")
    one(root, REFERENCE).set("URI", "#")
    with pytest.raises(MessageError, match="does not cover the SOAP Body"):
        check(root)


def test_key_reference_to_something_else(root: etree._Element) -> None:
    one(root, KEY_REFERENCE).set("URI", "#other")
    with pytest.raises(MessageError, match="does not name the certificate"):
        check(root)


def test_token_without_an_id(root: etree._Element) -> None:
    del one(root, CERTIFICATE).attrib[WSU_ID]
    one(root, KEY_REFERENCE).set("URI", "#")
    with pytest.raises(MessageError, match="does not name the certificate"):
        check(root)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("@@@", "BinarySecurityToken is not valid base64"),
        ("á", "BinarySecurityToken is not valid base64"),
        ("", "certificate in the message cannot be read"),
        (b64(b"not a certificate"), "certificate in the message cannot be read"),
    ],
)
def test_unreadable_certificate(root: etree._Element, text: str, message: str) -> None:
    one(root, CERTIFICATE).text = text
    with pytest.raises(MessageError, match=message):
        check(root)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("a003020102", "a003020103"),  # a version that does not exist
        ("2a864886f70d010101", "2a864886f70d010163"),  # an unknown kind of key
        ("0203010001", "0203000001"),  # a public key that is not valid DER
    ],
)
def test_certificate_that_cannot_be_used(
    root: etree._Element, x509_certificate: x509.Certificate, old: str, new: str
) -> None:
    der = x509_certificate.public_bytes(serialization.Encoding.DER)
    assert der.count(bytes.fromhex(old)) == 1
    one(root, CERTIFICATE).text = b64(
        der.replace(bytes.fromhex(old), bytes.fromhex(new))
    )
    with pytest.raises(MessageError, match="certificate in the message cannot be read"):
        check(root)


@pytest.mark.parametrize("path", ["soapenv:Body", SIGNED_INFO])
def test_namespace_without_a_canonical_form(root: etree._Element, path: str) -> None:
    # a relative namespace name is well-formed, but canonical XML refuses it
    etree.SubElement(one(root, path), "{relative}a")
    with pytest.raises(MessageError, match="cannot be canonicalized"):
        check(root)


def test_certificate_with_another_kind_of_key(
    root: etree._Element, issue: Issue
) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = issue("CZ00000019", key)
    one(root, CERTIFICATE).text = b64(
        certificate.public_bytes(serialization.Encoding.DER)
    )
    with pytest.raises(MessageError, match="does not hold an RSA key"):
        check(root)


@pytest.mark.parametrize(
    ("path", "text", "message"),
    [
        (f"{REFERENCE}/ds:DigestValue", "@@@", "DigestValue is not valid base64"),
        (f"{REFERENCE}/ds:DigestValue", "", "does not match its digest"),
        (f"{SIGNATURE}/ds:SignatureValue", "@@@", "SignatureValue is not valid base64"),
        (f"{SIGNATURE}/ds:SignatureValue", "", "signature is not valid"),
    ],
)
def test_unreadable_values(
    root: etree._Element, path: str, text: str, message: str
) -> None:
    one(root, path).text = text
    with pytest.raises(MessageError, match=message):
        check(root)


def test_base64_may_be_wrapped(root: etree._Element) -> None:
    # not the digest: it is inside the signed part, where every character counts
    for path in [CERTIFICATE, f"{SIGNATURE}/ds:SignatureValue"]:
        element = one(root, path)
        text = element.text or ""
        element.text = (
            "\n" + "\n".join(text[i : i + 64] for i in range(0, len(text), 64)) + "\n"
        )
    check(root)


@pytest.mark.parametrize(
    "data",
    [
        b"<Envelope/>",
        b'<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"/>',
        b'<Body xmlns="http://schemas.xmlsoap.org/soap/envelope/"/>',
    ],
)
def test_not_a_soap_envelope(data: bytes) -> None:
    with pytest.raises(MessageError, match="not a SOAP envelope"):
        verify(parse(data))


def with_prefix_lists(root: etree._Element) -> etree._Element:
    """Declare a prefix that the Body does not use and name it in both prefix lists."""
    data = etree.tostring(root).replace(
        b"<soapenv:Envelope ", b'<soapenv:Envelope xmlns:unused="urn:example" ', 1
    )
    root = parse(data)
    for path in [
        f"{SIGNED_INFO}/ds:CanonicalizationMethod",
        f"{REFERENCE}/ds:Transforms/ds:Transform",
    ]:
        etree.SubElement(
            one(root, path),
            f"{{{EXC_C14N}}}InclusiveNamespaces",
            PrefixList="unused soapenv",
        )
    return root


def test_prefix_list_is_honored(
    root: etree._Element, key: rsa.RSAPrivateKey, x509_certificate: x509.Certificate
) -> None:
    root = with_prefix_lists(root)
    with pytest.raises(MessageError, match="does not match its digest"):
        check(root)
    signed = resign(root, key)
    assert check(signed) == x509_certificate

    # without the lists the canonical forms differ, so the lists were used
    for inclusive in signed.iterfind(".//ec:InclusiveNamespaces", NS):
        parent = inclusive.getparent()
        assert parent is not None
        parent.remove(inclusive)
    with pytest.raises(MessageError, match="does not match its digest"):
        check(signed)


def test_unknown_canonicalization_parameters(root: etree._Element) -> None:
    method = one(root, f"{SIGNED_INFO}/ds:CanonicalizationMethod")
    etree.SubElement(method, "Other")
    with pytest.raises(
        MessageError, match="expected one InclusiveNamespaces element, found 0"
    ):
        check(root)
    etree.SubElement(method, f"{{{EXC_C14N}}}InclusiveNamespaces", PrefixList="soapenv")
    with pytest.raises(MessageError, match="unexpected canonicalization parameters"):
        check(root)
