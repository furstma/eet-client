import dataclasses
import http.client
import re
import socket
import ssl
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from eet_client import (
    PLAYGROUND,
    Certificate,
    Client,
    Confirmation,
    InvalidReply,
    Message,
    Rejected,
    Sale,
    ServiceWarning,
    Unavailable,
    Verification,
    _transport,
)
from eet_client._xml import MessageError, parse

VERIFIED = "Datovou zpravu evidovane trzby v overovacim modu se podarilo zpracovat"
FAULT = (
    b'<env:Envelope xmlns:env="http://schemas.xmlsoap.org/soap/envelope/"><env:Body>'
    b"<env:Fault><faultcode>env:Client</faultcode>"
    b"<faultstring>EET Request processing: Internal Error</faultstring>"
    b"</env:Fault></env:Body></env:Envelope>"
)
TRANSACTION = [("X-Global-Transaction-Id", "bc626a986afcbcc40394b312")]


def uuid_of(xml: bytes) -> str:
    match = re.search(rb'uuid_zpravy="([^"]+)"', xml)
    assert match
    return match.group(1).decode()


@pytest.fixture
def client(certificate: Certificate, service: Any, server: Any) -> Client:
    """A client of the local server, which signs the way ``service`` does."""
    return Client(certificate, dataclasses.replace(service.endpoint, url=server.url))


def confirm(server: Any, service: Any, *, status: int = 200) -> None:
    server.respond = lambda handler, request: server.reply(
        handler,
        service.confirmation(uuid_of(request.body)),
        status=status,
        headers=TRANSACTION,
    )


def answer(server: Any, body: bytes, *, status: int = 200) -> None:
    server.respond = lambda handler, request: server.reply(
        handler, body, status=status, headers=TRANSACTION
    )


def test_build(client: Client, sale: Sale, server: Any) -> None:
    before = datetime.now(UTC) - timedelta(seconds=1)
    message = client.build(sale)
    assert isinstance(message, Message)
    assert message.sale is sale
    assert message.repeat is False
    assert before <= message.sent_at <= datetime.now(UTC)
    assert message.sent_at.microsecond == 0
    header = parse(message.xml)[1][0][0]
    assert header.get("uuid_zpravy") == message.uuid
    assert header.get("prvni_zaslani") == "true"
    assert header.get("overeni") is None
    assert server.requests == []


def test_build_a_repeat(client: Client, sale: Sale) -> None:
    first = client.build(sale)
    again = client.build(sale, repeat=True)
    assert again.repeat is True
    assert again.uuid != first.uuid
    assert parse(again.xml)[1][0][0].get("prvni_zaslani") == "false"
    # the data of the sale are the same, character for character
    data = re.compile(rb"<eet:Data [^>]*/>")
    assert data.findall(again.xml) == data.findall(first.xml) != []


def test_build_refuses_what_is_not_a_sale(client: Client, sale: Sale) -> None:
    with pytest.raises(TypeError, match="sale must be a Sale"):
        client.build("sale")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="repeat must be a bool"):
        client.build(sale, repeat=1)  # type: ignore[arg-type]


def test_send(client: Client, sale: Sale, server: Any, service: Any) -> None:
    confirm(server, service)
    message = client.build(sale)
    confirmation = client.send(message)
    assert confirmation == Confirmation(
        pok=service.pok,
        received_at=confirmation.received_at,
        message_uuid=message.uuid,
        test=True,
        warnings=(),
        transaction_id="bc626a986afcbcc40394b312",
    )
    [request] = server.requests
    assert request.body == message.xml
    assert request.headers["content-type"] == "text/xml; charset=utf-8"
    assert request.headers["soapaction"] == '"http://fs.gov.cz/eet/OdeslaniTrzby"'
    assert request.headers["user-agent"] == "eet-client"
    assert request.headers["connection"] == "close"


def test_send_with_warnings(
    client: Client, sale: Sale, server: Any, service: Any
) -> None:
    text = "EIC poplatnika v datove zprave se neshoduje s EIC v certifikatu"
    server.respond = lambda handler, request: server.reply(
        handler, service.confirmation(uuid_of(request.body), warnings=[("1", text)])
    )
    confirmation = client.send(client.build(sale))
    assert confirmation.warnings == (ServiceWarning(1, text),)
    assert confirmation.transaction_id is None


def test_send_refuses_what_is_not_a_message(client: Client, sale: Sale) -> None:
    with pytest.raises(TypeError, match="message must be a Message"):
        client.send(sale)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="message must be a Message"):
        client.send(b"<xml/>")  # type: ignore[arg-type]


def test_rejected(client: Client, sale: Sale, server: Any, service: Any) -> None:
    answer(server, service.error(4, "Neplatny podpis SOAP zpravy"))
    with pytest.raises(Rejected) as caught:
        client.send(client.build(sale))
    assert (caught.value.code, caught.value.text) == (4, "Neplatny podpis SOAP zpravy")
    assert caught.value.transaction_id == "bc626a986afcbcc40394b312"
    assert len(server.requests) == 1


def test_temporary_error(client: Client, sale: Sale, server: Any, service: Any) -> None:
    answer(server, service.error(-1, "Docasna technicka chyba zpracovani"))
    with pytest.raises(Unavailable) as caught:
        client.send(client.build(sale))
    assert caught.value.code == -1
    assert caught.value.transaction_id == "bc626a986afcbcc40394b312"
    assert len(server.requests) == 1


def test_confirmation_of_another_message(
    client: Client, sale: Sale, server: Any, service: Any
) -> None:
    answer(server, service.confirmation("1cdd935d-8082-40e8-b78e-f725afd863b6"))
    with pytest.raises(InvalidReply, match="answers another message"):
        client.send(client.build(sale))


def test_confirmation_from_another_signer(
    certificate: Certificate, sale: Sale, server: Any, service: Any
) -> None:
    confirm(server, service)
    client = Client(certificate, dataclasses.replace(PLAYGROUND, url=server.url))
    with pytest.raises(InvalidReply, match="not issued by an accepted authority"):
        client.send(client.build(sale))


def test_soap_fault(client: Client, sale: Sale, server: Any) -> None:
    answer(server, FAULT, status=500)
    with pytest.raises(Unavailable) as caught:
        client.send(client.build(sale))
    assert type(caught.value) is Unavailable
    assert str(caught.value) == (
        "the service answered with a SOAP fault: EET Request processing: Internal Error"
    )
    assert caught.value.transaction_id == "bc626a986afcbcc40394b312"


@pytest.mark.parametrize("status", [202, 302, 403, 500, 502, 503])
def test_unreadable_reply_with_a_status_other_than_200(
    client: Client, sale: Sale, server: Any, status: int
) -> None:
    answer(server, b"<html><body>Not today</body></html>", status=status)
    with pytest.raises(Unavailable) as caught:
        client.send(client.build(sale))
    assert type(caught.value) is Unavailable
    assert str(caught.value) == f"the service answered with HTTP status {status}"
    assert caught.value.transaction_id == "bc626a986afcbcc40394b312"
    assert isinstance(caught.value.__cause__, InvalidReply)
    assert len(server.requests) == 1


@pytest.mark.parametrize("body", [b"", b"<html><body>Hello</body></html>", b"\xff"])
def test_unreadable_reply_with_status_200(
    client: Client, sale: Sale, server: Any, body: bytes
) -> None:
    answer(server, body)
    with pytest.raises(InvalidReply, match="the reply cannot be accepted") as caught:
        client.send(client.build(sale))
    assert caught.value.transaction_id == "bc626a986afcbcc40394b312"
    assert isinstance(caught.value.__cause__, MessageError)


def test_the_reply_decides_whatever_the_status(
    client: Client, sale: Sale, server: Any, service: Any
) -> None:
    confirm(server, service, status=500)
    assert client.send(client.build(sale)).pok == service.pok
    answer(
        server,
        service.error(3, "XML zprava nevyhovela kontrole XML schematu"),
        status=500,
    )
    with pytest.raises(Rejected):
        client.send(client.build(sale))


def test_reply_that_is_too_long(client: Client, sale: Sale, server: Any) -> None:
    answer(server, b"<a>" + b"x" * _transport.MAX_REPLY + b"</a>")
    with pytest.raises(InvalidReply, match="longer than 65536 bytes") as caught:
        client.send(client.build(sale))
    assert caught.value.transaction_id == "bc626a986afcbcc40394b312"


def test_reply_of_exactly_the_limit_is_read(
    client: Client, sale: Sale, server: Any
) -> None:
    answer(server, b"<a>" + b"x" * (_transport.MAX_REPLY - 7) + b"</a>")
    with pytest.raises(InvalidReply, match="the reply cannot be accepted"):
        client.send(client.build(sale))


def test_reply_that_is_too_long_with_an_error_status(
    client: Client, sale: Sale, server: Any
) -> None:
    answer(server, b"<a>" + b"x" * _transport.MAX_REPLY + b"</a>", status=503)
    for call in (lambda: client.send(client.build(sale)), lambda: client.verify(sale)):
        with pytest.raises(Unavailable) as caught:
            call()
        assert type(caught.value) is Unavailable
        assert str(caught.value) == "the service answered with HTTP status 503"
        assert "longer than 65536 bytes" in str(caught.value.__cause__)


@pytest.mark.parametrize(
    ("value", "kept"),
    [
        ("x" * 64, True),
        ("a-b_c.d:e/f=g+h", True),
        ("x" * 65, False),
        ("two words", False),
        ("tab\there", False),
        ("caf\xe9", False),
        ("", False),
    ],
)
def test_transaction_id_is_passed_on_only_in_its_documented_form(
    client: Client, sale: Sale, server: Any, service: Any, value: str, kept: bool
) -> None:
    server.respond = lambda handler, request: server.reply(
        handler,
        service.error(4, "Neplatny podpis SOAP zpravy"),
        headers=[("X-Global-Transaction-Id", value)],
    )
    with pytest.raises(Rejected) as caught:
        client.send(client.build(sale))
    assert caught.value.transaction_id == (value if kept else None)


def test_status_line_that_is_not_http(client: Client, sale: Sale, server: Any) -> None:
    def respond(handler: Any, request: object) -> None:
        handler.wfile.write(b"hello\x1b[31m there" + b"Z" * 60_000 + b"\r\n\r\n")

    server.respond = respond
    with pytest.raises(Unavailable, match="BadStatusLine: hello") as caught:
        client.send(client.build(sale))
    assert len(str(caught.value)) < 260
    assert str(caught.value).isprintable()


def test_server_that_is_not_trusted(
    client: Client, sale: Sale, server: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SSL_CERT_FILE")
    with pytest.raises(Unavailable, match="SSLCertVerificationError") as caught:
        client.send(client.build(sale))
    assert type(caught.value) is Unavailable
    assert isinstance(caught.value.__cause__, ssl.SSLCertVerificationError)
    assert server.requests == []


def failing(error: Exception) -> Any:
    def post(*args: object, **kwargs: object) -> None:
        raise error

    return post


def test_no_answer_in_time(
    certificate: Certificate, sale: Sale, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []

    def post(url: str, body: bytes, headers: object, *, timeout: float) -> None:
        calls.append((url, timeout))
        raise TimeoutError("timed out")

    monkeypatch.setattr(_transport, "post", post)
    client = Client(certificate, PLAYGROUND, timeout=2.5)
    with pytest.raises(Unavailable) as caught:
        client.send(client.build(sale))
    assert type(caught.value) is Unavailable
    assert str(caught.value) == (
        "the service did not answer within 2.5 seconds: timed out"
    )
    assert caught.value.code is None
    assert caught.value.transaction_id is None
    assert isinstance(caught.value.__cause__, TimeoutError)
    assert calls == [(PLAYGROUND.url, 2.5)]


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (ConnectionRefusedError(61, "Connection refused"), "ConnectionRefusedError"),
        (socket.gaierror(8, "nodename nor servname provided"), "gaierror"),
        (ssl.SSLError("handshake failure"), "SSLError"),
        (http.client.RemoteDisconnected("closed"), "RemoteDisconnected: closed"),
        (http.client.IncompleteRead(b"<a", 10), "IncompleteRead"),
        (http.client.BadStatusLine("hello"), "BadStatusLine: hello"),
    ],
)
def test_exchange_that_fails(
    certificate: Certificate,
    sale: Sale,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    message: str,
) -> None:
    monkeypatch.setattr(_transport, "post", failing(error))
    client = Client(certificate, PLAYGROUND)
    for call in (lambda: client.send(client.build(sale)), lambda: client.verify(sale)):
        with pytest.raises(Unavailable, match=message) as caught:
            call()
        assert type(caught.value) is Unavailable
        assert str(caught.value).startswith("the exchange with the service failed: ")
        assert caught.value.__cause__ is error


def test_verify(client: Client, sale: Sale, server: Any, service: Any) -> None:
    server.respond = lambda handler, request: server.reply(
        handler,
        service.error(0, VERIFIED, message_uuid=uuid_of(request.body)),
        headers=TRANSACTION,
    )
    verification = client.verify(sale)
    [request] = server.requests
    assert verification == Verification(
        message_uuid=uuid_of(request.body),
        test=True,
        warnings=(),
        transaction_id="bc626a986afcbcc40394b312",
    )
    header = parse(request.body)[1][0][0]
    assert header.get("overeni") == "true"
    assert header.get("prvni_zaslani") == "true"
    assert request.headers["soapaction"] == '"http://fs.gov.cz/eet/OdeslaniTrzby"'


def test_verify_that_finds_an_error(
    client: Client, sale: Sale, server: Any, service: Any
) -> None:
    answer(server, service.error(6, "EIC poplatnika ma chybnou strukturu"))
    with pytest.raises(Rejected) as caught:
        client.verify(sale)
    assert caught.value.code == 6
    assert caught.value.transaction_id == "bc626a986afcbcc40394b312"


def test_verify_answered_with_a_confirmation(
    client: Client, sale: Sale, server: Any, service: Any
) -> None:
    confirm(server, service)
    with pytest.raises(InvalidReply, match="in answer to a verification"):
        client.verify(sale)


def test_verify_with_an_unreadable_reply(
    client: Client, sale: Sale, server: Any
) -> None:
    answer(server, b"Bad Gateway", status=502)
    with pytest.raises(Unavailable, match="HTTP status 502") as caught:
        client.verify(sale)
    assert type(caught.value) is Unavailable
    answer(server, b"Bad Gateway")
    with pytest.raises(InvalidReply) as unreadable:
        client.verify(sale)
    assert isinstance(unreadable.value.__cause__, MessageError)


def test_verify_refuses_what_is_not_a_sale(client: Client) -> None:
    with pytest.raises(TypeError, match="sale must be a Sale"):
        client.verify(None)  # type: ignore[arg-type]


def test_arguments(certificate: Certificate) -> None:
    Client(certificate, PLAYGROUND, timeout=2)
    Client(certificate, PLAYGROUND, timeout=600)
    with pytest.raises(TypeError, match="certificate must be a Certificate"):
        Client(b"p12", PLAYGROUND)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="endpoint must be an Endpoint"):
        Client(certificate, PLAYGROUND.url)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        Client(certificate, PLAYGROUND, 5.0)  # type: ignore[call-arg]


@pytest.mark.parametrize("timeout", [None, "5", True, 5j])
def test_timeout_must_be_a_number(certificate: Certificate, timeout: Any) -> None:
    with pytest.raises(TypeError, match="timeout must be a number of seconds"):
        Client(certificate, PLAYGROUND, timeout=timeout)


@pytest.mark.parametrize(
    "timeout", [0, -1, 1.99, 600.1, float("inf"), float("nan"), 1e300]
)
def test_timeout_has_limits(certificate: Certificate, timeout: float) -> None:
    with pytest.raises(ValueError, match="between 2 and 600 seconds"):
        Client(certificate, PLAYGROUND, timeout=timeout)
