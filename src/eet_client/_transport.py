"""One HTTPS request, with a single time limit for all of it."""

import http.client
import io
import socket
import ssl
import threading
import time
from typing import Any
from urllib.parse import urlsplit

# A reply is a few kilobytes. More than this is not read.
MAX_REPLY = 64 * 1024


def post(
    url: str, body: bytes, headers: dict[str, str], *, timeout: float
) -> tuple[int, http.client.HTTPMessage, bytes]:
    """Send ``body`` to ``url`` and return the status, headers and body of the reply.

    Resolving the name, connecting, the TLS handshake, sending and reading
    must all end within ``timeout`` seconds. A new connection is made every
    time, to an address that is resolved every time. Redirects are not
    followed and proxy settings are not used. The server's certificate is
    checked against the system's certificate authorities.

    No more than ``MAX_REPLY + 1`` bytes of the body are read, so a longer
    reply shows as one of that length, and reading stops once more than
    ``2 * MAX_REPLY`` bytes have come in. Raises ``OSError`` (``TimeoutError``
    is one) or ``http.client.HTTPException``.
    """
    deadline = time.monotonic() + timeout
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or 443
    context = ssl.create_default_context()
    plain = _connect(_resolve(host, port, deadline), deadline)
    try:
        plain.settimeout(_left(deadline))
        sock = context.wrap_socket(plain, server_hostname=host)
    except BaseException:
        plain.close()
        raise
    try:
        connection = http.client.HTTPSConnection(host, port, context=context)
        # http.client connects by itself only when it has no socket.
        connection.sock = _Bounded(sock, deadline)
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
        connection.request(
            "POST", target, body=body, headers={**headers, "Connection": "close"}
        )
        response = connection.getresponse()
        try:
            data = response.read(MAX_REPLY + 1)
        except (ValueError, OverflowError) as error:
            # http.client hands a negative chunk size on to the reader
            raise http.client.HTTPException("the reply is not valid HTTP") from error
        if len(data) <= MAX_REPLY and response.length:
            # a read with a limit does not report a body that ends early
            raise http.client.IncompleteRead(data, response.length)
        return response.status, response.headers, data
    finally:
        sock.close()


def _left(deadline: float) -> float:
    """The seconds that remain."""
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("timed out")
    return left


def _resolve(host: str, port: int, deadline: float) -> list[Any]:
    """The addresses of the host, as ``socket.getaddrinfo`` gives them.

    The system's resolver takes no time limit. It runs in a thread of its
    own, which is left behind if it has not answered in time.
    """
    outcome: list[Any] = []

    def lookup() -> None:
        try:
            outcome.append(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except Exception as error:  # noqa: BLE001
            # whatever it is, it is raised in the calling thread below
            outcome.append(error)

    thread = threading.Thread(target=lookup, daemon=True)
    try:
        thread.start()
    except RuntimeError as error:
        raise OSError("cannot start the thread that resolves the name") from error
    thread.join(_left(deadline))
    if not outcome:
        raise TimeoutError("timed out resolving the name")
    if isinstance(outcome[0], Exception):
        raise outcome[0]
    addresses: list[Any] = outcome[0]
    return addresses


def _connect(addresses: list[Any], deadline: float) -> socket.socket:
    """Connect to the first address that accepts.

    Each address gets an equal share of the time that is left, so that one
    address that does not answer cannot use up the time of the others.
    """
    failure = OSError("the name has no address")
    for position, (family, kind, protocol, _, address) in enumerate(addresses):
        try:
            sock = socket.socket(family, kind, protocol)
        except OSError as error:
            failure = error
            continue
        try:
            sock.settimeout(_left(deadline) / (len(addresses) - position))
            sock.connect(address)
        except OSError as error:
            sock.close()
            failure = error
        except BaseException:
            sock.close()
            raise
        else:
            return sock
    raise failure


class _Bounded:
    """A connected socket on which every step must end before the deadline.

    ``http.client`` writes with ``sendall`` and reads through ``makefile``.
    A timeout set once on the socket would start again with every read, so
    a reply that trickles in could take any amount of time.
    """

    def __init__(self, sock: socket.socket, deadline: float) -> None:
        self._sock = sock
        self._deadline = deadline

    def sendall(self, data: bytes) -> None:
        self._sock.settimeout(_left(self._deadline))
        self._sock.sendall(data)

    def makefile(self, mode: str) -> io.BufferedReader:
        return io.BufferedReader(_Reader(self._sock, self._deadline))

    def close(self) -> None:
        # http.client closes its socket as soon as it has the headers of a
        # reply that ends the connection, and reads the body after that.
        # The socket is closed by post().
        pass


class _Reader(io.RawIOBase):
    def __init__(self, sock: socket.socket, deadline: float) -> None:
        self._sock = sock
        self._deadline = deadline
        # Headers, chunk framing and a body of MAX_REPLY + 1 bytes fit easily.
        # The limit also holds where http.client reads without one: headers,
        # and a chunk whose size is given as -1.
        self._room = 2 * MAX_REPLY

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        self._sock.settimeout(_left(self._deadline))
        count = self._sock.recv_into(buffer)
        self._room -= count
        if self._room < 0:
            raise http.client.HTTPException("the reply is too long")
        return count
