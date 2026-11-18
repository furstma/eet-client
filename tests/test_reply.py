import dataclasses
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from cryptography import x509
from cryptography.exceptions import InternalError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import NameOID

from eet_client import (
    Confirmation,
    EETError,
    Endpoint,
    InvalidReply,
    Rejected,
    ServiceWarning,
    Unavailable,
    Verification,
    WarningCode,
)
from eet_client._reply import read_confirmation, read_verification

Issue = Callable[..., x509.Certificate]

UUID = "2dfed444-4111-4f66-a8c2-582ecd9385e0"
OTHER_UUID = "1cdd935d-8082-40e8-b78e-f725afd863b6"
NOW = datetime.now(UTC)

# The texts of the official code lists.
ERRORS = {
    -1: "Docasna technicka chyba zpracovani - odeslete prosim datovou zpravu pozdeji",
    2: "Kodovani XML neni platne",
    3: "XML zprava nevyhovela kontrole XML schematu",
    4: "Neplatny podpis SOAP zpravy",
    6: "EIC poplatnika ma chybnou strukturu",
    7: "Datova zprava je prilis velka",
    8: "Datova zprava nebyla zpracovana kvuli technicke chybe nebo chybe dat",
}
VERIFIED = "Datovou zpravu evidovane trzby v overovacim modu se podarilo zpracovat"
WARNINGS = {
    1: "EIC poplatnika v datove zprave se neshoduje s EIC v certifikatu",
    2: "Chybny format EIC poverujiciho poplatnika",
    4: "Datum a cas uskutecneni trzby je novejsi nez datum a cas prijeti zpravy",
    5: "Datum a cas uskutecneni trzby je vyrazne v minulosti",
    6: "id_jednotky neodpovida formatem pridelenemu c. evidencni jednotky",
    7: "EIC poverujiciho se shoduje s EIC poplatnika",
}


def read(data: bytes, endpoint: Endpoint, **options: Any) -> Confirmation:
    arguments: dict[str, Any] = {
        "message_uuid": UUID,
        "now": NOW,
        "transaction_id": "tx-1",
    }
    arguments.update(options)
    return read_confirmation(data, endpoint=endpoint, **arguments)


def refused(data: bytes, endpoint: Endpoint, message: str, **options: Any) -> None:
    """The reply is not accepted, and the caller is told to report again."""
    with pytest.raises(InvalidReply, match=message) as caught:
        read(data, endpoint, **options)
    assert caught.value.transaction_id == "tx-1"
    assert caught.value.code is None


def test_confirmation(service: Any) -> None:
    confirmation = read(service.confirmation(UUID), service.endpoint)
    assert confirmation == Confirmation(
        pok="e6e9e626-3c24-4ec3-9a52-986a62bc7247-ff",
        received_at=datetime(
            2027, 1, 9, 4, 25, 31, tzinfo=timezone(timedelta(hours=1))
        ),
        message_uuid=UUID,
        test=True,
        warnings=(),
        transaction_id="tx-1",
    )
    assert confirmation.received_at.utcoffset() == timedelta(hours=1)


def test_confirmation_without_a_transaction_id(service: Any) -> None:
    confirmation = read(
        service.confirmation(UUID), service.endpoint, transaction_id=None
    )
    assert confirmation.transaction_id is None


def test_confirmation_names_the_message_in_other_case(service: Any) -> None:
    assert (
        read(service.confirmation(UUID.upper()), service.endpoint).message_uuid == UUID
    )


@pytest.mark.parametrize(("code", "text"), WARNINGS.items())
def test_confirmation_with_a_documented_warning(
    service: Any, code: int, text: str
) -> None:
    data = service.confirmation(UUID, warnings=[(str(code), f"\n      {text}\n   ")])
    [warning] = read(data, service.endpoint).warnings
    assert warning == ServiceWarning(code=code, text=text)
    assert warning.code == WarningCode(code)


def test_confirmation_with_several_warnings(service: Any) -> None:
    given = [("1", WARNINGS[1]), ("6", WARNINGS[6]), ("3", ""), ("999", "Neco noveho")]
    assert read(
        service.confirmation(UUID, warnings=given), service.endpoint
    ).warnings == (
        ServiceWarning(1, WARNINGS[1]),
        ServiceWarning(6, WARNINGS[6]),
        ServiceWarning(3, ""),
        ServiceWarning(999, "Neco noveho"),
    )


def test_documented_warning_codes() -> None:
    assert {code.name: code.value for code in WarningCode} == {
        "EIC_NOT_IN_CERTIFICATE": 1,
        "INVALID_AUTHORIZING_EIC": 2,
        "SOLD_AT_IN_FUTURE": 4,
        "SOLD_AT_TOO_OLD": 5,
        "INVALID_UNIT_ID": 6,
        "AUTHORIZING_EIC_IS_EIC": 7,
    }


@pytest.mark.parametrize(
    "code",
    # the escape is FULLWIDTH DIGIT ONE
    ["", "0", "-1", "1000", "1.0", "+1", "01", " 1", "x", "\uff11"],
)
def test_confirmation_with_an_unreadable_warning_code(service: Any, code: str) -> None:
    data = service.confirmation(UUID, warnings=[(code, "text")])
    refused(data, service.endpoint, "warning code is not a number from 1 to 999")


@pytest.mark.parametrize(
    ("header", "message"),
    [
        (
            f'<eet:Hlavicka uuid_zpravy="{OTHER_UUID}" dat_prij="2027-01-09T04:25:31+01:00"/>',
            "answers another message",
        ),
        (
            '<eet:Hlavicka dat_prij="2027-01-09T04:25:31+01:00"/>',
            "does not name the message",
        ),
        (
            '<eet:Hlavicka uuid_zpravy="" dat_prij="2027-01-09T04:25:31+01:00"/>',
            "does not name the message",
        ),
        (
            '<eet:Hlavicka uuid_zpravy="2dfed444" dat_prij="2027-01-09T04:25:31+01:00"/>',
            "does not name the message",
        ),
        (f'<eet:Hlavicka uuid_zpravy="{UUID}"/>', "time of receipt is missing"),
        (
            f'<eet:Hlavicka uuid_zpravy="{UUID}" dat_odmit="2027-01-09T04:25:31+01:00"/>',
            "time of receipt is missing",
        ),
        (
            f'<eet:Hlavicka uuid_zpravy="{UUID}" dat_prij="2027-01-09T04:25:31"/>',
            "does not have the prescribed form",
        ),
        (
            f'<eet:Hlavicka uuid_zpravy="{UUID}" dat_prij="2027-01-09 04:25:31+01:00"/>',
            "does not have the prescribed form",
        ),
        (
            f'<eet:Hlavicka uuid_zpravy="{UUID}" dat_prij="2027-13-09T04:25:31+01:00"/>',
            "not a valid date and time",
        ),
        # the version digit 0 and the variant digit c are outside the mask
        (
            (
                f'<eet:Hlavicka uuid_zpravy="{UUID[:14]}0{UUID[15:]}"'
                ' dat_prij="2027-01-09T04:25:31+01:00"/>'
            ),
            "does not name the message it answers",
        ),
        (
            (
                f'<eet:Hlavicka uuid_zpravy="{UUID[:19]}c{UUID[20:]}"'
                ' dat_prij="2027-01-09T04:25:31+01:00"/>'
            ),
            "does not name the message it answers",
        ),
        ("", "expected one Hlavicka element, found 0"),
        (
            f'<eet:Hlavicka uuid_zpravy="{UUID}" dat_prij="2027-01-09T04:25:31+01:00"/>'
            * 2,
            "expected one Hlavicka element, found 2",
        ),
    ],
)
def test_confirmation_with_a_wrong_header(
    service: Any, header: str, message: str
) -> None:
    refused(service.confirmation(UUID, header=header), service.endpoint, message)


def test_time_of_receipt_in_utc(service: Any) -> None:
    header = f'<eet:Hlavicka uuid_zpravy="{UUID}" dat_prij="2027-01-09T03:25:31Z"/>'
    confirmation = read(service.confirmation(UUID, header=header), service.endpoint)
    assert confirmation.received_at == datetime(2027, 1, 9, 3, 25, 31, tzinfo=UTC)


POK = "e6e9e626-3c24-4ec3-9a52-986a62bc7247-ff"


@pytest.mark.parametrize(
    ("outcome", "message"),
    [
        (
            '<eet:Potvrzeni test="true"/>',
            "confirmation code does not have the prescribed form",
        ),
        ('<eet:Potvrzeni pok="" test="true"/>', "confirmation code does not have"),
        (
            f'<eet:Potvrzeni pok="{POK[:-3]}" test="true"/>',
            "confirmation code does not have",
        ),
        (
            f'<eet:Potvrzeni pok="{POK}\xa0" test="true"/>',  # NO-BREAK SPACE
            "confirmation code does not have",
        ),
        # the version digit 3 and the variant digit c are outside the mask
        (
            f'<eet:Potvrzeni pok="{POK[:14]}3{POK[15:]}" test="true"/>',
            "confirmation code does not have",
        ),
        (
            f'<eet:Potvrzeni pok="{POK[:19]}c{POK[20:]}" test="true"/>',
            "confirmation code does not have",
        ),
        (f'<eet:Potvrzeni pok="{POK}" test="yes"/>', "test flag is not a boolean"),
        # xs:boolean is case-sensitive
        (f'<eet:Potvrzeni pok="{POK}" test="TRUE"/>', "test flag is not a boolean"),
        (f'<eet:Potvrzeni pok="{POK}" test="True"/>', "test flag is not a boolean"),
        (f'<eet:Potvrzeni pok="{POK}" test=""/>', "test flag is not a boolean"),
        (f'<eet:Potvrzeni pok="{POK}"/>', "comes from a production environment"),
        (
            f'<eet:Potvrzeni pok="{POK}" test="false"/>',
            "comes from a production environment",
        ),
        (
            f'<eet:Potvrzeni pok="{POK}" test="0"/>',
            "comes from a production environment",
        ),
        ("", "expected one Potvrzeni or Chyba element, found 0"),
        (
            f'<eet:Potvrzeni pok="{POK}" test="true"/>' * 2,
            "expected one Potvrzeni or Chyba element, found 2",
        ),
        (
            f'<eet:Potvrzeni pok="{POK}" test="true"/><eet:Chyba kod="3">x</eet:Chyba>',
            "expected one Potvrzeni or Chyba element, found 2",
        ),
    ],
)
def test_confirmation_with_a_wrong_outcome(
    service: Any, outcome: str, message: str
) -> None:
    refused(service.confirmation(UUID, outcome=outcome), service.endpoint, message)


@pytest.mark.parametrize("flag", ["true", "1", " true "])
def test_test_flag_spellings(service: Any, flag: str) -> None:
    outcome = f'<eet:Potvrzeni pok="{POK}" test="{flag}"/>'
    assert (
        read(service.confirmation(UUID, outcome=outcome), service.endpoint).test is True
    )


@pytest.mark.parametrize("flag", ['test="false"', 'test="0"', ""])
def test_production_confirmation(service: Any, flag: str) -> None:
    production = dataclasses.replace(service.endpoint, test=False)
    outcome = f'<eet:Potvrzeni pok="{POK}" {flag}/>'
    assert read(service.confirmation(UUID, outcome=outcome), production).test is False


def test_test_confirmation_at_a_production_endpoint(service: Any) -> None:
    production = dataclasses.replace(service.endpoint, test=False)
    refused(service.confirmation(UUID), production, "comes from a test environment")


def test_changed_confirmation(service: Any) -> None:
    data = service.confirmation(UUID).replace(b"e6e9e626", b"f6e9e626")
    refused(data, service.endpoint, "does not match its digest")


def test_unsigned_confirmation(service: Any) -> None:
    data = service.error(3).replace(
        b'<eet:Chyba kod="3" test="true"></eet:Chyba>',
        f'<eet:Potvrzeni pok="{POK}" test="true"/>'.encode(),
    )
    assert b"Potvrzeni" in data
    refused(data, service.endpoint, "expected one Security element, found 0")


def test_confirmation_signed_by_a_stranger(
    service: Any, key: rsa.RSAPrivateKey, issue: Issue
) -> None:
    stranger = issue("Test signer", key, organization_identifier="NTRCZ-72080043")
    data = service.confirmation(UUID, key=key, certificate=stranger)
    refused(data, service.endpoint, "not issued by an accepted authority")


def test_confirmation_signed_under_an_authority_of_the_same_name(
    service: Any, key: rsa.RSAPrivateKey, issue: Issue
) -> None:
    impostor = issue("Test authority", key)
    certificate = issue(
        "Test signer",
        key,
        issuer=impostor,
        issuer_key=key,
        organization_identifier="NTRCZ-72080043",
    )
    data = service.confirmation(UUID, key=key, certificate=certificate)
    refused(data, service.endpoint, "not issued by an accepted authority")


def test_confirmation_signed_two_steps_below_the_authority(
    service: Any,
    key: rsa.RSAPrivateKey,
    authority: x509.Certificate,
    authority_key: rsa.RSAPrivateKey,
    issue: Issue,
) -> None:
    intermediate = issue(
        "Intermediate", key, issuer=authority, issuer_key=authority_key
    )
    certificate = issue(
        "Test signer",
        key,
        issuer=intermediate,
        issuer_key=key,
        organization_identifier="NTRCZ-72080043",
    )
    data = service.confirmation(UUID, key=key, certificate=certificate)
    refused(data, service.endpoint, "not issued by an accepted authority")


@pytest.mark.parametrize(
    ("names", "message"),
    [
        (
            {
                "common_name": "Another signer",
                "organization_identifier": "NTRCZ-72080043",
            },
            r"signs with, its common name is \['Another signer'\]",
        ),
        (
            {"common_name": "test signer", "organization_identifier": "NTRCZ-72080043"},
            "not the one this endpoint signs with",
        ),
        (
            {"common_name": None, "organization_identifier": "NTRCZ-72080043"},
            "not the one this endpoint signs with",
        ),
        (
            {"common_name": "Test signer", "organization_identifier": "NTRCZ-26439395"},
            "does not belong to the tax administration",
        ),
        (
            {"common_name": "Test signer", "organization_identifier": None},
            "does not belong to the tax administration",
        ),
    ],
)
def test_confirmation_signed_by_another_subject_of_the_authority(
    service: Any,
    key: rsa.RSAPrivateKey,
    authority: x509.Certificate,
    authority_key: rsa.RSAPrivateKey,
    issue: Issue,
    names: dict[str, str | None],
    message: str,
) -> None:
    certificate = issue(
        names["common_name"],
        key,
        issuer=authority,
        issuer_key=authority_key,
        organization_identifier=names["organization_identifier"],
    )
    data = service.confirmation(UUID, key=key, certificate=certificate)
    refused(data, service.endpoint, message)


@pytest.mark.parametrize(
    "attributes",
    [
        # a second common name
        [
            (NameOID.COMMON_NAME, "Test signer"),
            (NameOID.COMMON_NAME, "Another signer"),
            (NameOID.ORGANIZATION_IDENTIFIER, "NTRCZ-72080043"),
        ],
        # a second organization identifier
        [
            (NameOID.COMMON_NAME, "Test signer"),
            (NameOID.ORGANIZATION_IDENTIFIER, "NTRCZ-72080043"),
            (NameOID.ORGANIZATION_IDENTIFIER, "NTRCZ-26439395"),
        ],
        # the identifier as the organization name
        [
            (NameOID.COMMON_NAME, "Test signer"),
            (NameOID.ORGANIZATION_NAME, "NTRCZ-72080043"),
        ],
    ],
)
def test_signer_names_must_be_exactly_the_expected_ones(
    service: Any,
    key: rsa.RSAPrivateKey,
    authority: x509.Certificate,
    authority_key: rsa.RSAPrivateKey,
    issue: Issue,
    attributes: list[tuple[x509.ObjectIdentifier, str]],
) -> None:
    subject = x509.Name([x509.NameAttribute(oid, value) for oid, value in attributes])
    certificate = issue(
        None, key, issuer=authority, issuer_key=authority_key, subject=subject
    )
    data = service.confirmation(UUID, key=key, certificate=certificate)
    refused(data, service.endpoint, "signer's certificate")


def test_signer_certificate_valid_to_the_second(
    service: Any,
    key: rsa.RSAPrivateKey,
    authority: x509.Certificate,
    authority_key: rsa.RSAPrivateKey,
    issue: Issue,
) -> None:
    start = (NOW - timedelta(hours=1)).replace(microsecond=0)
    end = (NOW + timedelta(days=30)).replace(microsecond=0)
    certificate = issue(
        "Test signer",
        key,
        issuer=authority,
        issuer_key=authority_key,
        not_before=start,
        not_after=end,
        organization_identifier="NTRCZ-72080043",
    )
    data = service.confirmation(UUID, key=key, certificate=certificate)
    read(data, service.endpoint, now=start)
    read(data, service.endpoint, now=end)
    second = timedelta(seconds=1)
    refused(data, service.endpoint, "not valid at this time", now=start - second)
    refused(data, service.endpoint, "not valid at this time", now=end + second)


@pytest.mark.parametrize(
    "now",
    [NOW - timedelta(days=2), NOW + timedelta(days=366)],
)
def test_signer_certificate_outside_its_validity(service: Any, now: datetime) -> None:
    refused(
        service.confirmation(UUID), service.endpoint, "not valid at this time", now=now
    )


def test_authority_outside_its_validity(
    service: Any, key: rsa.RSAPrivateKey, authority_key: rsa.RSAPrivateKey, issue: Issue
) -> None:
    expired = issue(
        "Expired authority",
        authority_key,
        not_before=NOW - timedelta(days=30),
        not_after=NOW - timedelta(days=1),
    )
    certificate = issue(
        "Test signer",
        key,
        issuer=expired,
        issuer_key=authority_key,
        not_before=NOW - timedelta(days=30),
        organization_identifier="NTRCZ-72080043",
    )
    endpoint = dataclasses.replace(
        service.endpoint,
        authorities=expired.public_bytes(serialization.Encoding.PEM).decode(),
    )
    data = service.confirmation(UUID, key=key, certificate=certificate)
    refused(data, endpoint, "not issued by an accepted authority")
    # with the authority still valid, the same confirmation is accepted
    read(data, endpoint, now=NOW - timedelta(days=2))


def test_authority_not_yet_valid(
    service: Any, key: rsa.RSAPrivateKey, authority_key: rsa.RSAPrivateKey, issue: Issue
) -> None:
    future = issue(
        "Future authority",
        authority_key,
        not_before=NOW + timedelta(days=1),
        not_after=NOW + timedelta(days=60),
    )
    certificate = issue(
        "Test signer",
        key,
        issuer=future,
        issuer_key=authority_key,
        organization_identifier="NTRCZ-72080043",
    )
    endpoint = dataclasses.replace(
        service.endpoint,
        authorities=future.public_bytes(serialization.Encoding.PEM).decode(),
    )
    data = service.confirmation(UUID, key=key, certificate=certificate)
    refused(data, endpoint, "not issued by an accepted authority")
    read(data, endpoint, now=NOW + timedelta(days=2))


def damaged(certificate: x509.Certificate, old: bytes, new: bytes) -> x509.Certificate:
    der = certificate.public_bytes(serialization.Encoding.DER)
    assert old in der
    return x509.load_der_x509_certificate(der.replace(old, new))


def test_signer_certificate_signed_with_an_unknown_algorithm(
    service: Any,
    key: rsa.RSAPrivateKey,
    authority: x509.Certificate,
    authority_key: rsa.RSAPrivateKey,
    issue: Issue,
) -> None:
    certificate = issue(
        "Test signer",
        key,
        issuer=authority,
        issuer_key=authority_key,
        organization_identifier="NTRCZ-72080043",
        rsa_padding=padding.PSS(padding.MGF1(hashes.SHA256()), salt_length=32),
    )
    data = service.confirmation(UUID, key=key, certificate=certificate)
    assert read(data, service.endpoint).pok == POK
    # the same certificate, naming a hash that does not exist
    sha256 = bytes.fromhex("608648016503040201")
    certificate = damaged(certificate, sha256, sha256[:-1] + b"\x63")
    data = service.confirmation(UUID, key=key, certificate=certificate)
    refused(data, service.endpoint, "not issued by an accepted authority")


@pytest.mark.parametrize(
    "error",
    [
        InternalError("Unknown OpenSSL error", []),  # cryptography before 45
        CryptographyDeprecationWarning("negative serial number"),  # warnings as errors
    ],
)
def test_certificate_that_cryptography_cannot_handle(
    service: Any, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    data = service.confirmation(UUID)

    def load(der: bytes) -> x509.Certificate:
        raise error

    monkeypatch.setattr(x509, "load_der_x509_certificate", load)
    refused(data, service.endpoint, "certificate in the message cannot be read")


def test_signer_certificate_with_a_date_out_of_range(
    service: Any,
    key: rsa.RSAPrivateKey,
    authority: x509.Certificate,
    authority_key: rsa.RSAPrivateKey,
    issue: Issue,
) -> None:
    certificate = issue(
        "Test signer",
        key,
        issuer=authority,
        issuer_key=authority_key,
        not_before=datetime(2050, 1, 1, tzinfo=UTC),
        not_after=datetime(2051, 1, 1, tzinfo=UTC),
        organization_identifier="NTRCZ-72080043",
    )
    certificate = damaged(certificate, b"20500101000000Z", b"00000101000000Z")
    data = service.confirmation(UUID, key=key, certificate=certificate)
    refused(data, service.endpoint, "not valid at this time")


def test_any_of_several_authorities_may_have_issued_the_signer(
    service: Any, key: rsa.RSAPrivateKey, issue: Issue
) -> None:
    unrelated = issue("Unrelated authority", key)
    pem = unrelated.public_bytes(serialization.Encoding.PEM).decode()
    endpoint = dataclasses.replace(
        service.endpoint, authorities=pem + service.endpoint.authorities
    )
    assert read(service.confirmation(UUID), endpoint).pok == POK


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"", "not well-formed XML"),
        (b"<html><body>502 Bad Gateway</body></html>", "not a SOAP envelope"),
        (b"<!DOCTYPE a><a/>", "document type declaration"),
        (
            b'<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"/>',
            "expected one Body element, found 0",
        ),
        (
            b'<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body/></Envelope>',
            "expected one Odpoved element, found 0",
        ),
        (
            (
                b'<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body>'
                b'<Odpoved xmlns="http://fs.gov.cz/eet/schema/v3"/></Body></Envelope>'
            ),
            "expected one Odpoved element, found 0",
        ),
    ],
)
def test_reply_that_is_not_one(service: Any, data: bytes, message: str) -> None:
    refused(data, service.endpoint, message)
    with pytest.raises(InvalidReply, match=message):
        read_verification(data, message_uuid=UUID, transaction_id=None)


@pytest.mark.parametrize(("code", "text"), ERRORS.items())
def test_documented_error(service: Any, code: int, text: str) -> None:
    data = service.error(code, f"\n              {text}\n      ", message_uuid=UUID)
    with pytest.raises(EETError) as caught:
        read(data, service.endpoint)
    error = caught.value
    assert error.transaction_id == "tx-1"
    if code in (-1, 8):
        assert type(error) is Unavailable
        assert error.code == code
        assert str(error) == f"the service answered with error {code}: {text}"
    else:
        assert type(error) is Rejected
        assert (error.code, error.text) == (code, text)


@pytest.mark.parametrize("code", [-999, -500, -2])
def test_reserved_negative_error_means_try_again(service: Any, code: int) -> None:
    with pytest.raises(Unavailable) as caught:
        read(service.error(code, "Neco noveho"), service.endpoint)
    assert type(caught.value) is Unavailable
    assert caught.value.code == code


@pytest.mark.parametrize("code", [1, 5, 9, 500, 999])
def test_reserved_positive_error_means_rejected(service: Any, code: int) -> None:
    with pytest.raises(Rejected) as caught:
        read(service.error(code, "Neco noveho"), service.endpoint)
    assert (caught.value.code, caught.value.text) == (code, "Neco noveho")


@pytest.mark.parametrize(
    "code",
    # the escape is FULLWIDTH DIGIT ONE
    ["", "x", "1.0", "+1", " 1", "1 ", "1000", "-1000", "--1", "\uff11", "0x1"],
)
def test_unreadable_error_code(service: Any, code: str) -> None:
    refused(service.error(code), service.endpoint, "error code is not a number")


def test_error_without_a_code(service: Any) -> None:
    data = service.error(3).replace(b' kod="3"', b"")
    refused(data, service.endpoint, "error code is not a number")


def test_error_reply_needs_no_signature_and_no_uuid(service: Any) -> None:
    with pytest.raises(Rejected):
        read(service.error(3, ERRORS[3]), service.endpoint)
    with pytest.raises(Rejected):
        read(service.error(3, ERRORS[3], test=None), service.endpoint)


def test_error_reply_for_another_message(service: Any) -> None:
    data = service.error(3, ERRORS[3], message_uuid=OTHER_UUID)
    refused(data, service.endpoint, "answers another message")


def test_verification_answer_to_a_normal_send(service: Any) -> None:
    data = service.error(0, VERIFIED, message_uuid=UUID)
    refused(data, service.endpoint, "belongs to the verification mode")


def test_soap_fault(service: Any) -> None:
    data = (
        b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        b"<soapenv:Body><soapenv:Fault><faultcode>soapenv:Client</faultcode>"
        b"<faultstring>\n  Internal Error (from client)\n</faultstring>"
        b"</soapenv:Fault></soapenv:Body></soapenv:Envelope>"
    )
    for call in (
        lambda: read(data, service.endpoint),
        lambda: read_verification(data, message_uuid=UUID, transaction_id="tx-1"),
    ):
        with pytest.raises(Unavailable) as caught:
            call()
        assert type(caught.value) is Unavailable
        assert str(caught.value) == (
            "the service answered with a SOAP fault: Internal Error (from client)"
        )
        assert caught.value.transaction_id == "tx-1"


def test_soap_fault_without_a_text(service: Any) -> None:
    data = (
        b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        b"<soapenv:Body><soapenv:Fault/></soapenv:Body></soapenv:Envelope>"
    )
    with pytest.raises(Unavailable, match="SOAP fault: $"):
        read(data, service.endpoint)


def verification(data: bytes, **options: Any) -> Verification:
    arguments: dict[str, Any] = {"message_uuid": UUID, "transaction_id": "tx-1"}
    arguments.update(options)
    return read_verification(data, **arguments)


def test_verification(service: Any) -> None:
    data = service.error(0, VERIFIED, message_uuid=UUID)
    assert verification(data) == Verification(
        message_uuid=UUID, test=True, warnings=(), transaction_id="tx-1"
    )


def test_verification_in_production_with_warnings(service: Any) -> None:
    data = service.error(
        0, VERIFIED, test=None, warnings=[("4", WARNINGS[4]), ("6", WARNINGS[6])]
    )
    assert verification(data, transaction_id=None) == Verification(
        message_uuid=UUID,
        test=False,
        warnings=(ServiceWarning(4, WARNINGS[4]), ServiceWarning(6, WARNINGS[6])),
        transaction_id=None,
    )


def test_verification_answered_with_a_confirmation(service: Any) -> None:
    with pytest.raises(
        InvalidReply, match="confirmation came in answer to a verification"
    ) as caught:
        verification(service.confirmation(UUID))
    assert caught.value.transaction_id == "tx-1"


def test_verification_for_another_message(service: Any) -> None:
    with pytest.raises(InvalidReply, match="answers another message"):
        verification(service.error(0, VERIFIED, message_uuid=OTHER_UUID))


@pytest.mark.parametrize(("code", "text"), ERRORS.items())
def test_verification_that_found_an_error(service: Any, code: int, text: str) -> None:
    kind = Unavailable if code in (-1, 8) else Rejected
    with pytest.raises(kind) as caught:
        verification(service.error(code, text, message_uuid=UUID))
    assert type(caught.value) is kind
    assert caught.value.code == code
    assert caught.value.transaction_id == "tx-1"
