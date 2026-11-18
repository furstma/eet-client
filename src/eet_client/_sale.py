"""The sale to be reported and its validation."""

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from zoneinfo import ZoneInfo

# The masks of EETXMLSchema.xsd, version 4.1. The schema writes \d, which in
# Python also matches digits outside ASCII, so the digits are spelled out.
_EIC = re.compile(r"CZ[0-9]{8,10}")
_DEVICE_ID = re.compile(r"[0-9a-zA-Z\.,:;/#\-_ ]{1,20}")
_SEQUENCE = re.compile(r"[0-9a-zA-Z\.,:;/#\-_ ]{1,25}")
_DATETIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(Z|[+\-][0-9]{2}:[0-9]{2})"
)

# Times are reported as Czech local time with its UTC offset.
_PRAGUE = ZoneInfo("Europe/Prague")


@dataclass(frozen=True, slots=True, kw_only=True)
class Sale:
    """One sale, as it is reported to the tax administration.

    Every value is checked against the official schema when the object is
    created. A value that does not fit raises ``ValueError``, a value of the
    wrong type ``TypeError``. Nothing is rounded, truncated or guessed.

    The tax administration identifies a sale by the first six values. A sale
    that is sent again must be built from the same values as the first time;
    the same moment gives the same message data whatever time zone it is
    given in.
    """

    eic: str
    """Registration identification number of the taxpayer (EIČ), ``CZ`` and
    8 to 10 digits (``eic_popl``)."""

    unit_id: int
    """Number of the unit, as assigned by the tax administration
    (``id_jednotky``)."""

    device_id: str
    """Label of the point of sale, chosen by the taxpayer: 1 to 20 ASCII
    letters, digits, spaces or ``.,:;/#-_`` (``id_pokl``)."""

    sequence: str
    """Sequence number of the sale, usually the receipt number: 1 to 25
    characters of the same set as ``device_id`` (``porad_cis``)."""

    sold_at: datetime
    """Moment of the sale; for a refund, the moment the money is returned.
    Timezone-aware and in whole seconds; reported as Czech local time
    whatever zone it is given in (``dat_trzby``)."""

    total: Decimal
    """Total in CZK, with at most two decimal places. Zero is allowed and a
    refund is negative (``celk_trzba``)."""

    authorizing_eic: str | None = None
    """Identifier of the taxpayer who authorized ``eic`` to report the sale
    (``eic_poverujiciho``). Left out for the taxpayer's own sales."""

    multiple_taxpayers: bool = False
    """The sale belongs to several taxpayers (``povereni_vice_popl``)."""

    to_be_drawn: Decimal | None = None
    """Part of the total that loads credit to be spent later: a top-up of an
    e-wallet or prepaid card, or a voucher for unspecified goods
    (``urceno_cerp_zuct``). Not for an advance payment on an order."""

    drawn: Decimal | None = None
    """Part of the total that is paid from such credit (``cerp_zuct``)."""

    def __post_init__(self) -> None:
        _data_attributes(self)


def _data_attributes(sale: Sale) -> dict[str, str]:
    """The attributes of the ``Data`` element, validated, in schema order."""
    attributes = {"eic_popl": _text("eic", sale.eic, _EIC)}
    if sale.authorizing_eic is not None:
        authorizing = _text("authorizing_eic", sale.authorizing_eic, _EIC)
        if authorizing == attributes["eic_popl"]:
            raise ValueError(
                "authorizing_eic must differ from eic; leave it out for own sales"
            )
        attributes["eic_poverujiciho"] = authorizing
    if not isinstance(sale.multiple_taxpayers, bool):
        raise TypeError("multiple_taxpayers must be a bool")
    if sale.multiple_taxpayers:
        attributes["povereni_vice_popl"] = "true"
    attributes["id_jednotky"] = _unit_id(sale.unit_id)
    attributes["id_pokl"] = _text("device_id", sale.device_id, _DEVICE_ID)
    attributes["porad_cis"] = _text("sequence", sale.sequence, _SEQUENCE)
    attributes["dat_trzby"] = _timestamp("sold_at", sale.sold_at)
    attributes["celk_trzba"] = _amount("total", sale.total)
    if sale.to_be_drawn is not None:
        attributes["urceno_cerp_zuct"] = _part("to_be_drawn", sale.to_be_drawn)
    if sale.drawn is not None:
        attributes["cerp_zuct"] = _part("drawn", sale.drawn)
    return attributes


def _text(name: str, value: object, mask: re.Pattern[str]) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a str")
    # the text itself: a subclass, such as an enum member, may print differently
    value = str.__str__(value)
    if not mask.fullmatch(value):
        raise ValueError(f"{name} {value[:40]!r} does not match {mask.pattern}")
    return value


def _unit_id(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("unit_id must be an int")
    value = int.__index__(value)  # the number itself, also for a subclass
    if not 1 <= value <= 999_999_999:
        raise ValueError("unit_id is not between 1 and 999999999")
    return f"{value:d}"


def _timestamp(name: str, value: object) -> str:
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be a datetime")
    if value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    if value.microsecond:
        raise ValueError(f"{name} must not have a fraction of a second")
    try:
        # by way of UTC: astimezone() returns a value that is already in the
        # target zone unchanged, even a local time that summer time skips
        text = value.astimezone(UTC).astimezone(_PRAGUE).isoformat()
    except OverflowError:
        raise ValueError(f"{name} {value} is out of range") from None
    if not _DATETIME.fullmatch(text):
        # before 1891 Prague kept local mean time, with seconds in its offset
        raise ValueError(f"{name} {text!r} does not match {_DATETIME.pattern}")
    return text


def _amount(name: str, value: object) -> str:
    if not isinstance(value, Decimal):
        raise TypeError(f"{name} must be a Decimal")
    if not value.is_finite():
        raise ValueError(f"{name} must be a finite number")
    if value.is_zero():
        return "0.00"
    # The position of the first digit bounds the text below to the digits of
    # the value: a Decimal can carry an exponent of any size.
    if value.adjusted() >= 8:
        raise ValueError(f"{name} {value} is not below 100 000 000 in absolute value")
    if value.adjusted() < -2:
        raise ValueError(f"{name} {value} has more than two decimal places")
    # exact: fixed-point formatting without a precision never rounds
    whole, _, fraction = Decimal.__format__(value, "f").partition(".")
    if fraction[2:].strip("0"):
        raise ValueError(f"{name} {value} has more than two decimal places")
    return f"{whole}.{fraction[:2]:0<2}"


def _part(name: str, value: object) -> str:
    text = _amount(name, value)
    if text == "0.00":
        # an optional amount that does not apply is left out, not sent as zero
        raise ValueError(f"{name} must not be zero; leave it out instead")
    return text
