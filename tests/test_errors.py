import pickle

import pytest

from eet_client import EETError, ErrorCode, InvalidReply, Rejected, Unavailable


def test_every_failure_is_one_of_two_kinds() -> None:
    assert issubclass(Unavailable, EETError)
    assert issubclass(Rejected, EETError)
    assert issubclass(InvalidReply, Unavailable)
    assert not issubclass(Rejected, Unavailable)
    assert not issubclass(Unavailable, Rejected)


def test_unavailable() -> None:
    error = Unavailable("no answer within 5 seconds")
    assert str(error) == "no answer within 5 seconds"
    assert error.code is None
    assert error.transaction_id is None

    error = Unavailable(
        "the service answered with error -1", code=-1, transaction_id="abc"
    )
    assert error.code == ErrorCode.TEMPORARY_FAILURE
    assert error.transaction_id == "abc"


def test_rejected() -> None:
    error = Rejected(4, "Neplatny podpis SOAP zpravy", transaction_id="abc")
    assert str(error) == "error 4: Neplatny podpis SOAP zpravy"
    assert error.code == ErrorCode.INVALID_SIGNATURE
    assert error.text == "Neplatny podpis SOAP zpravy"
    assert error.transaction_id == "abc"
    assert Rejected(999, "").transaction_id is None


def test_documented_error_codes() -> None:
    assert {code.name: code.value for code in ErrorCode} == {
        "TEMPORARY_FAILURE": -1,
        "INVALID_ENCODING": 2,
        "SCHEMA_VIOLATION": 3,
        "INVALID_SIGNATURE": 4,
        "INVALID_EIC": 6,
        "TOO_LARGE": 7,
        "NOT_PROCESSED": 8,
    }


@pytest.mark.parametrize(
    "error",
    [
        EETError("failed", transaction_id="abc"),
        Unavailable("not now", code=-1, transaction_id="abc"),
        InvalidReply("not signed", transaction_id="abc"),
        Rejected(
            3, "XML zprava nevyhovela kontrole XML schematu", transaction_id="abc"
        ),
    ],
)
def test_errors_survive_pickling(error: EETError) -> None:
    # exceptions cross process boundaries in worker pools
    copy = pickle.loads(pickle.dumps(error))  # noqa: S301
    assert type(copy) is type(error)
    assert str(copy) == str(error)
    assert vars(copy) == vars(error)
