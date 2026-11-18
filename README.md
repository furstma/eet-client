# eet-client

Unofficial Python client for the Czech EET 2.0 sales registration service
(evidence tržeb, zákon č. 180/2026 Sb., in force from 1 January 2027).

It builds the message for a sale, signs it with the taxpayer's certificate,
sends it to the tax administration and checks the signed confirmation. Storing
sales and deciding when to send them again stay in your application.

Neoficiální klient pro EET 2.0 v Pythonu: sestaví a podepíše datovou zprávu
evidované tržby, odešle ji a ověří podpis potvrzení. Ukládání tržeb a
plánování opakovaného zaslání zůstávají na vaší aplikaci.

## Status

Version 0.x. The API may still change, and so may the service: it starts on
1 January 2027. The library is tested against the Playground, the public
test environment of the tax administration. The production environment has
not been used yet; the name of the certificate that signs its confirmations
is taken from the published access document.

The package is not on PyPI yet. Until the first release, install it from the
repository:

```console
$ python -m pip install "eet-client @ git+https://github.com/furstma/eet-client"
```

It needs Python 3.11 or newer and installs `cryptography` and `lxml` (and
`tzdata` on Windows). It also reads the IANA time zone database, which macOS
and most Linux systems have; on a minimal container image install the
system's `tzdata` package or `tzdata` from PyPI.

## Example

```python
from datetime import datetime
from decimal import Decimal
from zoneinfo import ZoneInfo

from eet_client import PLAYGROUND, Certificate, Client, Rejected, Sale, Unavailable

with open("CA_EET-Playground-CZ00000019.p12", "rb") as file:
    certificate = Certificate.from_pkcs12(file.read(), password)

client = Client(certificate, PLAYGROUND, timeout=5.0)

sale = Sale(
    eic="CZ00000019",
    unit_id=11,
    device_id="POS-1",
    sequence="2027/0001",
    sold_at=datetime(2027, 1, 4, 9, 30, 0, tzinfo=ZoneInfo("Europe/Prague")),
    total=Decimal("1500.00"),
)

message = client.build(sale)  # signed, not sent yet
# Record message.uuid and message.sent_at now, before anything goes out.
try:
    confirmation = client.send(message)
except Unavailable:
    ...  # not confirmed: send the sale again later, as a repeat
except Rejected as error:
    ...  # refused: error.code and error.text say why
else:
    confirmation.pok  # the confirmation code
    confirmation.warnings  # what the service found wrong but accepted
```

The test certificates and their password are published with the other
[documents for developers](https://eet.gov.cz/cs/o-eet/dokumenty-k-eet-2-0).
For real sales, pass `PRODUCTION` instead of `PLAYGROUND`.

## The sale

`Sale` checks every value against the official schema when it is created and
raises `ValueError` or `TypeError` for one that does not fit. Nothing is
rounded, cut or guessed:

- amounts are `Decimal` with at most two decimal places;
- `sold_at` is timezone-aware and in whole seconds; it is reported as Czech
  local time whatever zone it is given in;
- optional values that do not apply are left out, not set to zero.

A refund is a sale with a negative `total`, its own `sequence` and the time of
the refund.

The interface description also requires `eic`, `unit_id`, `device_id` and
`sold_at` to be unique together, so one device must not report two sales in
the same second. The library keeps no state and cannot check this.

## Sending again

`send` makes one attempt. When it raises `Unavailable`, the sale may or may not
have been registered, and reporting it again is the right thing to do:

```python
confirmation = client.send(client.build(sale, repeat=True))
```

- Use `repeat=True` for every attempt after the first, even if the first one
  never left the machine. That is why the attempt is recorded before `send`.
- Build the repeat from a `Sale` with the same values. The service recognizes
  a sale by `eic`, `unit_id`, `device_id`, `sequence`, `sold_at` and `total`,
  so store them as they were sent.
- Each attempt is a new message with its own `uuid`, and each confirmation
  has its own `pok`.
- When and how often to try again is up to the application. The act asks for
  it without delay once the cause has passed, and within 48 hours of the sale
  (§ 20). The duty does not end there: keep trying until a confirmation comes.

`Rejected` means the service refused the message. `error.code` is usually one
of the codes in `ErrorCode`, but the service may add new ones. The same
message would be refused again, so it needs a person.

`InvalidReply` is a kind of `Unavailable`: a reply came, but it could not be
read or its signature could not be trusted. Handle it like any `Unavailable`,
and look into it if it keeps happening.

All three carry `transaction_id`, the identifier that the service gave to the
exchange, if it answered. Quote it when you ask the tax administration about
a message.

## The confirmation

A reply counts as a confirmation only if its signature holds, it answers the
message that was sent, and its signer is the one that the endpoint names: a
certificate of the tax administration issued by I.CA, the authority whose
certificate the library carries. A confirmation that fails one of these
raises `InvalidReply`.

The service does not sign its error replies or its answers in verification
mode, so those are only as trustworthy as the TLS connection they came over.

If the tax administration changes its signing certificate before this library
follows, describe the new one yourself. Pass only what has changed:

```python
import dataclasses

endpoint = dataclasses.replace(
    PRODUCTION,
    signer="...",  # common name of the new certificate
    authorities="...",  # its issuing authority's certificate, as PEM text
)
```

## The time limit

`timeout` bounds the whole exchange: resolving the name, connecting, the TLS
handshake, sending and reading the reply. It is given in seconds, defaults to
5 and cannot be less than 2, the shortest response limit that the act lets a
taxpayer set (§ 19), or more than 600.

Every call opens a new connection. Proxy settings are not used, redirects are
not followed, and the server's certificate is always checked against the
system's certificate authorities.

## Verification mode

```python
verification = client.verify(sale)
```

sends the sale in verification mode: the service checks the message and
registers nothing. It answers without a signature and without a confirmation
code, so the result shows that the message and the certificate are accepted,
not that a sale was registered.

## Not included

Storing sales and attempts, scheduling repeats, renewing certificates, proxy
support, an asynchronous API and a command-line tool.

## Contributing

See [CONTRIBUTING.md](https://github.com/furstma/eet-client/blob/main/CONTRIBUTING.md).
Security problems are reported privately, see
[SECURITY.md](https://github.com/furstma/eet-client/blob/main/SECURITY.md).

## Disclaimer

This is an unofficial project. It is not affiliated with or endorsed by the
Czech Financial Administration (Finanční správa České republiky). You remain
responsible for meeting your obligations under the act.

## License

[MIT](https://github.com/furstma/eet-client/blob/main/LICENSE)
