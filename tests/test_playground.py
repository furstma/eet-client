"""Exchanges with the Playground, the public test environment of the service.

They need the network, so they run only on request: ``pytest -m live``.
"""

import secrets
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from eet_client import (
    PLAYGROUND,
    Certificate,
    Client,
    ErrorCode,
    Rejected,
    Sale,
    WarningCode,
)

pytestmark = pytest.mark.live


@pytest.fixture
def client(playground_certificates: dict[str, Certificate]) -> Client:
    certificate = playground_certificates["CZ00000019"]
    # The service would answer with error 4, which reads like a fault in signing.
    if certificate.valid_until <= datetime.now(UTC):
        pytest.fail(
            "the Playground test certificate expired on "
            f"{certificate.valid_until:%Y-%m-%d}; "
            "update _ARCHIVE and _ARCHIVE_SHA256 in conftest.py"
        )
    return Client(certificate, PLAYGROUND, timeout=10)


def a_sale(eic: str = "CZ00000019") -> Sale:
    return Sale(
        eic=eic,
        unit_id=11,
        device_id="eet-client",
        sequence=f"T-{secrets.token_hex(5)}",
        sold_at=datetime.now(UTC).replace(microsecond=0),
        total=Decimal("123.00"),
    )


def test_verification(client: Client) -> None:
    verification = client.verify(a_sale())
    assert verification.test is True
    assert verification.warnings == ()
    assert verification.transaction_id


def test_send_and_repeat(client: Client) -> None:
    sale = a_sale()
    message = client.build(sale)
    confirmation = client.send(message)
    assert confirmation.message_uuid == message.uuid
    assert confirmation.test is True
    assert confirmation.warnings == ()
    assert confirmation.transaction_id
    assert abs(confirmation.received_at - datetime.now(UTC)) < timedelta(minutes=5)

    again = client.send(client.build(sale, repeat=True))
    assert again.pok != confirmation.pok
    assert again.warnings == ()


def test_refund(client: Client) -> None:
    sale = a_sale()
    refund = Sale(
        eic=sale.eic,
        unit_id=sale.unit_id,
        device_id=sale.device_id,
        sequence=f"{sale.sequence}-S",
        sold_at=sale.sold_at + timedelta(seconds=1),
        total=-sale.total,
    )
    client.send(client.build(sale))
    assert client.send(client.build(refund)).warnings == ()


def test_warning_when_the_certificate_belongs_to_another_taxpayer(
    client: Client,
) -> None:
    confirmation = client.send(client.build(a_sale("CZ683555118")))
    assert [warning.code for warning in confirmation.warnings] == [
        WarningCode.EIC_NOT_IN_CERTIFICATE
    ]


def test_certificate_of_an_unknown_authority_is_rejected(
    certificate: Certificate,
) -> None:
    client = Client(certificate, PLAYGROUND, timeout=10)
    with pytest.raises(Rejected) as caught:
        client.send(client.build(a_sale()))
    assert caught.value.code == ErrorCode.INVALID_SIGNATURE
    assert caught.value.transaction_id
