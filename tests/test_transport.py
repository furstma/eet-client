import http.client
import http.server
import socket
import ssl
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from eet_client import _transport
from eet_client._transport import MAX_REPLY, post

HEADERS = {"Content-Type": "text/xml; charset=utf-8", "User-Agent": "test"}
Handler = http.server.BaseHTTPRequestHandler


def test_post(server: Any) -> None:
    server.respond = lambda handler, request: server.reply(
        handler, b"<reply/>", headers=[("X-Global-Transaction-ID", "tx-1")]
    )
    status, headers, body = post(server.url, b"<message/>", HEADERS, timeout=5)
    assert (status, body) == (200, b"<reply/>")
    assert headers["x-global-transaction-id"] == "tx-1"

    [request] = server.requests
    assert request.method == "POST"
    assert request.path == "/eet/services/EETServiceSOAP/v4"
    assert request.version == "HTTP/1.1"
    assert request.body == b"<message/>"
    assert request.headers == {
        "host": f"127.0.0.1:{server.port}",
        "accept-encoding": "identity",
        "content-length": "10",
        "content-type": "text/xml; charset=utf-8",
        "user-agent": "test",
        "connection": "close",
    }


def test_query_is_kept_and_an_empty_path_is_the_root(server: Any) -> None:
    post(server.url + "?a=1&b=2", b"", HEADERS, timeout=5)
    post(f"https://127.0.0.1:{server.port}", b"", HEADERS, timeout=5)
    post(f"https://127.0.0.1:{server.port}?a=1", b"", HEADERS, timeout=5)
    assert [request.path for request in server.requests] == [
        "/eet/services/EETServiceSOAP/v4?a=1&b=2",
        "/",
        "/?a=1",
    ]


def test_every_call_makes_a_new_connection(
    server: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolved = []
    getaddrinfo = socket.getaddrinfo

    def counting(*args: Any, **kwargs: Any) -> Any:
        resolved.append(args)
        return getaddrinfo(*args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", counting)
    ports = []

    def respond(handler: Handler, request: object) -> None:
        ports.append(handler.client_address[1])
        server.reply(handler, b"")

    server.respond = respond
    post(server.url, b"", HEADERS, timeout=5)
    post(server.url, b"", HEADERS, timeout=5)
    assert len(resolved) == 2
    assert len(set(ports)) == 2


@pytest.mark.parametrize("status", [301, 302, 307, 404, 500, 503])
def test_any_status_is_returned_and_no_redirect_is_followed(
    server: Any, status: int
) -> None:
    server.respond = lambda handler, request: server.reply(
        handler, b"elsewhere", status=status, headers=[("Location", server.url + "/x")]
    )
    assert post(server.url, b"", HEADERS, timeout=5)[::2] == (status, b"elsewhere")
    assert len(server.requests) == 1


def test_chunked_reply(server: Any) -> None:
    def respond(handler: Handler, request: object) -> None:
        handler.send_response(200)
        handler.send_header("Transfer-Encoding", "chunked")
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(b"4\r\n<rep\r\n5\r\nly/>\n\r\n0\r\n\r\n")

    server.respond = respond
    assert post(server.url, b"", HEADERS, timeout=5)[2] == b"<reply/>\n"


@pytest.mark.parametrize("size", [b"-5", b"-" + b"f" * 24])
def test_chunked_reply_with_a_negative_chunk_size(server: Any, size: bytes) -> None:
    def respond(handler: Handler, request: object) -> None:
        handler.send_response(200)
        handler.send_header("Transfer-Encoding", "chunked")
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(size + b"\r\n<rep\r\n0\r\n\r\n")

    server.respond = respond
    with pytest.raises(http.client.HTTPException, match="not valid HTTP"):
        post(server.url, b"", HEADERS, timeout=5)


def test_reply_without_a_length_ends_with_the_connection(server: Any) -> None:
    def respond(handler: Handler, request: object) -> None:
        handler.send_response(200)
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(b"<reply/>")

    server.respond = respond
    assert post(server.url, b"", HEADERS, timeout=5)[2] == b"<reply/>"


def test_no_more_than_the_limit_is_read(server: Any) -> None:
    server.respond = lambda handler, request: server.reply(handler, b"x" * MAX_REPLY)
    assert len(post(server.url, b"", HEADERS, timeout=5)[2]) == MAX_REPLY
    server.respond = lambda handler, request: server.reply(
        handler, b"x" * (MAX_REPLY * 3)
    )
    assert len(post(server.url, b"", HEADERS, timeout=5)[2]) == MAX_REPLY + 1


def test_chunk_size_minus_one_does_not_lift_the_limit(server: Any) -> None:
    # http.client reads a chunk of size -1 to the end of the connection
    def respond(handler: Handler, request: object) -> None:
        handler.send_response(200)
        handler.send_header("Transfer-Encoding", "chunked")
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(b"-1\r\n" + b"x" * (MAX_REPLY * 3))

    server.respond = respond
    with pytest.raises(http.client.HTTPException, match="too long"):
        post(server.url, b"", HEADERS, timeout=5)


def test_headers_count_towards_the_limit(server: Any) -> None:
    server.respond = lambda handler, request: server.reply(
        handler, b"<reply/>", headers=[(f"A{n}", "a" * 60000) for n in range(3)]
    )
    with pytest.raises(http.client.HTTPException, match="too long"):
        post(server.url, b"", HEADERS, timeout=5)


def test_proxy_settings_are_not_used(
    server: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "HTTP_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    assert post(server.url, b"", HEADERS, timeout=5)[0] == 200


def test_server_that_sends_nothing(server: Any) -> None:
    release = threading.Event()
    server.respond = lambda handler, request: release.wait(10)
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        post(server.url, b"", HEADERS, timeout=0.5)
    release.set()
    assert 0.4 < time.monotonic() - started < 2


def test_reply_that_trickles_in_does_not_outlast_the_timeout(server: Any) -> None:
    def respond(handler: Handler, request: object) -> None:
        handler.send_response(200)
        handler.send_header("Content-Length", "1000")
        handler.send_header("Connection", "close")
        handler.end_headers()
        for _ in range(50):
            handler.wfile.write(b"x")
            handler.wfile.flush()
            time.sleep(0.1)

    server.respond = respond
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        post(server.url, b"", HEADERS, timeout=0.5)
    assert 0.4 < time.monotonic() - started < 2


def test_headers_that_trickle_in_do_not_outlast_the_timeout(server: Any) -> None:
    def respond(handler: Handler, request: object) -> None:
        for byte in b"HTTP/1.1 200 OK\r\nX-Slow: " + b"x" * 50:
            handler.wfile.write(bytes([byte]))
            handler.wfile.flush()
            time.sleep(0.05)

    server.respond = respond
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        post(server.url, b"", HEADERS, timeout=0.5)
    assert 0.4 < time.monotonic() - started < 2


def test_reply_cut_short_at_the_limit(server: Any) -> None:
    def respond(handler: Handler, request: object) -> None:
        handler.send_response(200)
        handler.send_header("Content-Length", str(MAX_REPLY + 10))
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(b"x" * MAX_REPLY)

    server.respond = respond
    with pytest.raises(http.client.IncompleteRead, match="10 more expected"):
        post(server.url, b"", HEADERS, timeout=5)


def test_reply_cut_short(server: Any) -> None:
    def respond(handler: Handler, request: object) -> None:
        handler.send_response(200)
        handler.send_header("Content-Length", "1000")
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(b"<reply")

    server.respond = respond
    with pytest.raises(http.client.IncompleteRead, match="994 more expected"):
        post(server.url, b"", HEADERS, timeout=5)


def test_reply_with_a_length_and_no_body(server: Any) -> None:
    def respond(handler: Handler, request: object) -> None:
        handler.send_response(200)
        handler.send_header("Content-Length", "1000")
        handler.send_header("Connection", "close")
        handler.end_headers()

    server.respond = respond
    with pytest.raises(http.client.IncompleteRead, match="1000 more expected"):
        post(server.url, b"", HEADERS, timeout=5)


def test_chunked_reply_cut_short(server: Any) -> None:
    def respond(handler: Handler, request: object) -> None:
        handler.send_response(200)
        handler.send_header("Transfer-Encoding", "chunked")
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(b"4\r\n<rep\r\n5\r\nly")

    server.respond = respond
    with pytest.raises(http.client.IncompleteRead):
        post(server.url, b"", HEADERS, timeout=5)


def test_connection_closed_without_a_reply(server: Any) -> None:
    server.respond = lambda handler, request: None
    with pytest.raises(http.client.RemoteDisconnected):
        post(server.url, b"", HEADERS, timeout=5)


def test_reply_that_is_not_http(server: Any) -> None:
    server.respond = lambda handler, request: handler.wfile.write(b"hello\r\n\r\n")
    with pytest.raises(http.client.BadStatusLine):
        post(server.url, b"", HEADERS, timeout=5)


def test_server_certificate_must_be_trusted(
    server: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SSL_CERT_FILE")
    with pytest.raises(ssl.SSLCertVerificationError):
        post(server.url, b"", HEADERS, timeout=5)
    assert server.requests == []


def test_server_certificate_must_name_the_host(
    server: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    getaddrinfo = socket.getaddrinfo
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, *args, **kwargs: getaddrinfo("127.0.0.1", *args, **kwargs),
    )
    url = f"https://pg.trzbyeet.gov.cz:{server.port}/"
    with pytest.raises(ssl.SSLCertVerificationError, match="[Hh]ostname mismatch"):
        post(url, b"", HEADERS, timeout=5)
    assert server.requests == []


def test_plain_http_server_is_refused() -> None:
    with socket.create_server(("127.0.0.1", 0)) as listener:
        port = listener.getsockname()[1]

        def answer() -> None:
            connection, _ = listener.accept()
            with connection:
                # all of the ClientHello: a close with unread data sends a
                # reset, which on some systems discards the reply
                connection.recv(65536)
                connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

        thread = threading.Thread(target=answer, daemon=True)
        thread.start()
        with pytest.raises(ssl.SSLError):
            post(f"https://127.0.0.1:{port}/", b"", HEADERS, timeout=5)
        thread.join()


def test_handshake_gets_the_time_left_after_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # with two addresses, connecting to the first gets half the time
    tcp = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "")
    with socket.create_server(("127.0.0.1", 0)) as listener:
        port = listener.getsockname()[1]
        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *args, **kwargs: [(*tcp, ("127.0.0.1", port))] * 2,
        )
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            post(f"https://127.0.0.1:{port}/", b"", HEADERS, timeout=0.5)
        assert 0.4 < time.monotonic() - started < 2


def test_connection_is_closed_when_the_time_runs_out_before_the_handshake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connected: list[socket.socket] = []
    connect = _transport._connect

    def connect_too_late(addresses: Any, deadline: float) -> socket.socket:
        connected.append(connect(addresses, deadline))
        time.sleep(0.4)
        return connected[0]

    monkeypatch.setattr(_transport, "_connect", connect_too_late)
    with socket.create_server(("127.0.0.1", 0)) as listener:
        port = listener.getsockname()[1]
        with pytest.raises(TimeoutError):
            post(f"https://127.0.0.1:{port}/", b"", HEADERS, timeout=0.3)
    assert connected[0].fileno() == -1


def test_request_that_cannot_be_sent_does_not_outlast_the_timeout(
    server: Any, _running_server: tuple[Any, Path]
) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(_running_server[1].parent / "server.pem")
    release = threading.Event()
    with socket.create_server(("127.0.0.1", 0)) as listener:
        port = listener.getsockname()[1]

        def handshake_then_read_nothing() -> None:
            connection, _ = listener.accept()
            try:
                with context.wrap_socket(connection, server_side=True):
                    release.wait(10)
            except OSError:
                pass

        thread = threading.Thread(target=handshake_then_read_nothing, daemon=True)
        thread.start()
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            post(f"https://127.0.0.1:{port}/", b"x" * 64_000_000, HEADERS, timeout=0.5)
        elapsed = time.monotonic() - started
        release.set()
        thread.join()
    assert 0.4 < elapsed < 2


def test_tls_handshake_that_never_ends() -> None:
    with socket.create_server(("127.0.0.1", 0)) as listener:
        port = listener.getsockname()[1]
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            post(f"https://127.0.0.1:{port}/", b"", HEADERS, timeout=0.5)
        assert 0.4 < time.monotonic() - started < 2


def test_default_context_refuses_old_tls() -> None:
    context = ssl.create_default_context()
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname


def test_nothing_listens() -> None:
    with socket.create_server(("127.0.0.1", 0)) as listener:
        port = listener.getsockname()[1]
    # Windows takes two seconds to report that nothing listens
    with pytest.raises(ConnectionRefusedError):
        post(f"https://127.0.0.1:{port}/", b"", HEADERS, timeout=10)


def test_name_that_does_not_resolve(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(socket.gaierror, match="Name or service not known"):
        post("https://pg.trzbyeet.gov.cz/", b"", HEADERS, timeout=5)


def test_any_failure_of_the_resolver_is_raised_in_the_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise UnicodeError("label empty or too long")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(UnicodeError, match="label empty or too long"):
        post("https://pg.trzbyeet.gov.cz/", b"", HEADERS, timeout=5)


def test_resolver_thread_that_cannot_be_started(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(self: threading.Thread) -> None:
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(threading.Thread, "start", fail)
    with pytest.raises(OSError, match="cannot start the thread") as caught:
        post("https://pg.trzbyeet.gov.cz/", b"", HEADERS, timeout=5)
    assert isinstance(caught.value.__cause__, RuntimeError)


def test_name_resolution_that_hangs(monkeypatch: pytest.MonkeyPatch) -> None:
    release = threading.Event()
    daemon = []

    def hang(*args: object, **kwargs: object) -> None:
        daemon.append(threading.current_thread().daemon)
        release.wait(10)

    monkeypatch.setattr(socket, "getaddrinfo", hang)
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="resolving the name"):
        post("https://pg.trzbyeet.gov.cz/", b"", HEADERS, timeout=0.3)
    release.set()
    assert 0.2 < time.monotonic() - started < 2
    # a thread left behind must not keep the interpreter from exiting
    assert daemon == [True]


def test_next_address_is_tried_when_one_refuses(
    server: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    with socket.create_server(("127.0.0.1", 0)) as listener:
        closed = listener.getsockname()[1]
    tcp = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "")
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (*tcp, ("127.0.0.1", closed)),
            (*tcp, ("127.0.0.1", server.port)),
        ],
    )
    assert post(server.url, b"", HEADERS, timeout=10)[0] == 200


def test_next_address_is_tried_when_no_socket_can_be_made_for_one(
    server: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    tcp = (socket.SOCK_STREAM, socket.IPPROTO_TCP, "")
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (9999, *tcp, ("127.0.0.1", server.port)),
            (socket.AF_INET, *tcp, ("127.0.0.1", server.port)),
        ],
    )
    assert post(server.url, b"", HEADERS, timeout=10)[0] == 200


class FakeSocket:
    """Records the timeout of every connection attempt and when it was set,
    and fails each attempt."""

    timeouts: list[tuple[float, float]]

    def __init__(self, *args: object) -> None:
        pass

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append((timeout, time.monotonic()))

    def connect(self, address: object) -> None:
        time.sleep(0.05)
        raise TimeoutError("timed out")

    def close(self) -> None:
        pass


def test_socket_is_closed_when_connecting_is_interrupted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed = []

    class Interrupted(FakeSocket):
        def connect(self, address: object) -> None:
            raise KeyboardInterrupt

        def close(self) -> None:
            closed.append(True)

    Interrupted.timeouts = []
    monkeypatch.setattr(socket, "socket", Interrupted)
    with pytest.raises(KeyboardInterrupt):
        _transport._connect(
            [(None, None, None, "", ("192.0.2.1", 443))], time.monotonic() + 1
        )
    assert closed == [True]


def test_addresses_share_the_time_that_is_left(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeSocket.timeouts = []
    monkeypatch.setattr(socket, "socket", FakeSocket)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, "", ("192.0.2.1", 443))] * 4,
    )
    deadline = time.monotonic() + 4
    with pytest.raises(TimeoutError):
        post("https://pg.trzbyeet.gov.cz/", b"", HEADERS, timeout=4)
    assert len(FakeSocket.timeouts) == 4
    for position, (timeout, at) in enumerate(FakeSocket.timeouts):
        assert timeout == pytest.approx((deadline - at) / (4 - position), abs=0.01)


def test_no_connection_is_tried_after_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeSocket.timeouts = []
    monkeypatch.setattr(socket, "socket", FakeSocket)
    addresses = [(None, None, None, "", ("192.0.2.1", 443))] * 2
    with pytest.raises(TimeoutError):
        _transport._connect(addresses, time.monotonic() - 1)
    assert FakeSocket.timeouts == []
