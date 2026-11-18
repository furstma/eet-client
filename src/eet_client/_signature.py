"""The XML signature over the SOAP Body, in the WS-Security form the interface uses."""

import base64
import binascii
import hashlib
import hmac

from cryptography import x509
from cryptography.exceptions import (
    InternalError,
    InvalidSignature,
    UnsupportedAlgorithm,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.utils import CryptographyDeprecationWarning
from lxml import etree

from eet_client._certificate import Certificate
from eet_client._xml import DS, SOAP, WSSE, WSU, MessageError, only

EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
BASE64_BINARY = (
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0"
    "#Base64Binary"
)
X509_V3 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"

_WSU_ID = f"{{{WSU}}}Id"


def sign(envelope: etree._Element, certificate: Certificate) -> None:
    """Sign the Body of ``envelope`` and put the signature into its Header."""
    header = only(envelope, f"{{{SOAP}}}Header")
    body = only(envelope, f"{{{SOAP}}}Body")
    body.set(_WSU_ID, "body")

    security = etree.SubElement(
        header, f"{{{WSSE}}}Security", nsmap={"wsse": WSSE, "wsu": WSU}
    )
    token = etree.SubElement(security, f"{{{WSSE}}}BinarySecurityToken")
    token.set("EncodingType", BASE64_BINARY)
    token.set("ValueType", X509_V3)
    token.set(_WSU_ID, "certificate")
    token.text = _b64(certificate.der)

    signature = etree.SubElement(security, f"{{{DS}}}Signature", nsmap={"ds": DS})
    signed_info = etree.SubElement(signature, f"{{{DS}}}SignedInfo")
    canonicalization = etree.SubElement(
        signed_info, f"{{{DS}}}CanonicalizationMethod", Algorithm=EXC_C14N
    )
    etree.SubElement(signed_info, f"{{{DS}}}SignatureMethod", Algorithm=RSA_SHA256)
    reference = etree.SubElement(signed_info, f"{{{DS}}}Reference", URI="#body")
    transforms = etree.SubElement(reference, f"{{{DS}}}Transforms")
    transform = etree.SubElement(transforms, f"{{{DS}}}Transform", Algorithm=EXC_C14N)
    etree.SubElement(reference, f"{{{DS}}}DigestMethod", Algorithm=SHA256)
    digest = hashlib.sha256(_canonical(body, transform)).digest()
    etree.SubElement(reference, f"{{{DS}}}DigestValue").text = _b64(digest)

    signature_value = etree.SubElement(signature, f"{{{DS}}}SignatureValue")
    key_info = etree.SubElement(signature, f"{{{DS}}}KeyInfo")
    token_reference = etree.SubElement(key_info, f"{{{WSSE}}}SecurityTokenReference")
    etree.SubElement(
        token_reference, f"{{{WSSE}}}Reference", URI="#certificate", ValueType=X509_V3
    )
    signature_value.text = _b64(
        certificate.sign(_canonical(signed_info, canonicalization))
    )


def verify(envelope: etree._Element) -> x509.Certificate:
    """Check the signature over the Body of ``envelope``.

    Returns the certificate whose key made the signature. Whether that
    certificate is to be trusted is for the caller to decide.
    """
    if envelope.tag != f"{{{SOAP}}}Envelope":
        raise MessageError("not a SOAP envelope")
    body = only(envelope, f"{{{SOAP}}}Body")
    security = only(only(envelope, f"{{{SOAP}}}Header"), f"{{{WSSE}}}Security")
    token = only(security, f"{{{WSSE}}}BinarySecurityToken")
    signature = only(security, f"{{{DS}}}Signature")
    signed_info = only(signature, f"{{{DS}}}SignedInfo")

    if only(signed_info, f"{{{DS}}}SignatureMethod").get("Algorithm") != RSA_SHA256:
        raise MessageError("the signature method is not RSA with SHA-256")

    # The one reference must point at the very Body that will be read. The Body
    # is never looked up by its Id, so a second element with that Id changes nothing.
    reference = only(signed_info, f"{{{DS}}}Reference")
    body_id = body.get(_WSU_ID)
    if not body_id or reference.get("URI") != "#" + body_id:
        raise MessageError("the signature does not cover the SOAP Body")
    transform = only(only(reference, f"{{{DS}}}Transforms"), f"{{{DS}}}Transform")
    if only(reference, f"{{{DS}}}DigestMethod").get("Algorithm") != SHA256:
        raise MessageError("the digest method is not SHA-256")
    digest = hashlib.sha256(_canonical(body, transform)).digest()
    if not hmac.compare_digest(
        digest, _decode(only(reference, f"{{{DS}}}DigestValue"))
    ):
        raise MessageError("the SOAP Body does not match its digest")

    key_reference = only(
        only(only(signature, f"{{{DS}}}KeyInfo"), f"{{{WSSE}}}SecurityTokenReference"),
        f"{{{WSSE}}}Reference",
    )
    token_id = token.get(_WSU_ID)
    if not token_id or key_reference.get("URI") != "#" + token_id:
        raise MessageError("the signature does not name the certificate in the message")
    der = _decode(token)
    try:
        certificate = x509.load_der_x509_certificate(der)
        public_key = certificate.public_key()
    # cryptography before 45 raises InternalError for some keys, and its
    # warnings are raised where warnings are turned into errors
    except (
        ValueError,
        x509.InvalidVersion,
        UnsupportedAlgorithm,
        InternalError,
        CryptographyDeprecationWarning,
    ) as error:
        raise MessageError("the certificate in the message cannot be read") from error
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise MessageError("the certificate in the message does not hold an RSA key")
    try:
        public_key.verify(
            _decode(only(signature, f"{{{DS}}}SignatureValue")),
            _canonical(
                signed_info, only(signed_info, f"{{{DS}}}CanonicalizationMethod")
            ),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature as error:
        raise MessageError("the signature is not valid") from error
    return certificate


def _canonical(element: etree._Element, method: etree._Element) -> bytes:
    """Exclusive canonical form of ``element``, as ``method`` asks for it."""
    if method.get("Algorithm") != EXC_C14N:
        raise MessageError("the canonicalization is not exclusive C14N")
    prefixes = None
    if len(method):
        inclusive = only(method, f"{{{EXC_C14N}}}InclusiveNamespaces")
        if len(method) != 1:
            raise MessageError("unexpected canonicalization parameters")
        prefixes = inclusive.get("PrefixList", "").split()
    # lxml keeps comments unless told otherwise, which would be a different
    # algorithm. It finds the listed prefixes only in the thread that parsed
    # the element and never honors "#default"; a signature that needs either
    # is refused.
    try:
        return etree.tostring(
            element,
            method="c14n",
            exclusive=True,
            with_comments=False,
            inclusive_ns_prefixes=prefixes,
        )
    except etree.C14NError as error:
        raise MessageError("the message cannot be canonicalized") from error


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode(element: etree._Element) -> bytes:
    try:
        return base64.b64decode("".join((element.text or "").split()), validate=True)
    except (binascii.Error, ValueError) as error:
        name = etree.QName(element).localname
        raise MessageError(f"{name} is not valid base64") from error
