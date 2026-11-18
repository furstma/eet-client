from pathlib import Path

import pytest
from lxml import etree

from eet_client._xml import MessageError, only, parse


def test_parse_returns_the_root_element() -> None:
    root = parse(b"<?xml version='1.0' encoding='UTF-8'?>\n<a><b x='1'/>text</a>\n")
    assert root.tag == "a"
    assert root[0].get("x") == "1"


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not xml",
        b"<a>",
        b"<a></b>",
        b"<a>&undefined;</a>",
        b"<a/><b/>",
        # deeper than libxml2 allows without huge_tree
        b"<a>" * 300 + b"</a>" * 300,
    ],
)
def test_parse_refuses_what_is_not_well_formed(data: bytes) -> None:
    with pytest.raises(MessageError, match="not well-formed"):
        parse(data)


@pytest.mark.parametrize(
    "data",
    [
        b"<!DOCTYPE a><a/>",
        b'<!DOCTYPE a [<!ENTITY e "x">]><a>&e;</a>',
        b'<!DOCTYPE a [<!ENTITY e "x">]><a b="&e;"/>',
        b'<!DOCTYPE a SYSTEM "http://localhost/a.dtd"><a/>',
        b'<!DOCTYPE a [<!ENTITY e SYSTEM "file:///etc/passwd">]><a>&e;</a>',
        b'<!DOCTYPE a [<!ENTITY x "xxxxxxxxxx"><!ENTITY y "&x;&x;&x;&x;&x;&x;&x;&x;">]><a>&y;</a>',
    ],
)
def test_parse_refuses_a_document_type_declaration(data: bytes) -> None:
    with pytest.raises(MessageError, match="document type"):
        parse(data)


def test_parse_reads_no_external_entity(tmp_path: Path) -> None:
    # if the file were read, the error would be "not well-formed XML" instead
    part = tmp_path / "part.xml"
    part.write_text("<unclosed")
    data = f'<!DOCTYPE a [<!ENTITY e SYSTEM "{part.as_uri()}">]><a>&e;</a>'
    with pytest.raises(MessageError, match="document type"):
        parse(data.encode())


@pytest.mark.parametrize(
    "data",
    [
        b"<a><!-- comment --></a>",
        b"<a><b>text<!-- comment -->more</b></a>",
        b"<a><?target data?></a>",
    ],
)
def test_parse_refuses_comments_and_processing_instructions(data: bytes) -> None:
    with pytest.raises(MessageError, match="comments"):
        parse(data)


def test_parse_ignores_comments_outside_the_root_element() -> None:
    assert parse(b"<!-- before --><a/><!-- after -->").tag == "a"


def test_only() -> None:
    root = etree.fromstring(b"<a><b/><c/><c/></a>")
    assert only(root, "b").tag == "b"
    with pytest.raises(MessageError, match="expected one c element, found 2"):
        only(root, "c")
    with pytest.raises(MessageError, match="expected one d element, found 0"):
        only(root, "{urn:example}d")
