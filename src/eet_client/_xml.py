"""Namespaces and parsing of the XML that the interface exchanges."""

from lxml import etree

SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
EET = "http://fs.gov.cz/eet/schema/v4"
WSSE = (
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
)
WSU = (
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
)
DS = "http://www.w3.org/2000/09/xmldsig#"


class MessageError(Exception):
    """The XML is not a message of this interface, or its signature does not hold."""


def parse(data: bytes) -> etree._Element:
    """Parse a message.

    Entities are not resolved and nothing is fetched. A document type
    declaration is refused, and so is a comment or a processing instruction
    inside the root element: the interface uses none of them, and each can
    change what a reader sees without changing what a signature covers.
    Comments and processing instructions outside the root element are ignored.
    """
    parser = etree.XMLParser(
        resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False
    )
    try:
        root = etree.fromstring(data, parser)
    except etree.XMLSyntaxError as error:
        raise MessageError("not well-formed XML") from error
    if root.getroottree().docinfo.doctype:
        raise MessageError("a document type declaration is not allowed")
    for node in root.iter():
        if not isinstance(node.tag, str):
            raise MessageError("comments and processing instructions are not allowed")
    return root


def only(parent: etree._Element, tag: str) -> etree._Element:
    """The one child of ``parent`` that has this tag."""
    children = parent.findall(tag)
    if len(children) != 1:
        name = etree.QName(tag).localname
        raise MessageError(f"expected one {name} element, found {len(children)}")
    return children[0]
