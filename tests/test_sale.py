import dataclasses
import enum
import re
import string
import time
from datetime import UTC, date, datetime, timedelta, timezone, tzinfo
from decimal import Decimal
from typing import Any
from zoneinfo import ZoneInfo

import pytest

from eet_client import Sale
from eet_client._sale import _data_attributes

CET = timezone(timedelta(hours=1))
CEST = timezone(timedelta(hours=2))

# The masks as written in EETXMLSchema.xsd, version 4.1.
AMOUNT_MASK = r"((0|-?[1-9]\d{0,7})\.\d\d|-0\.(0[1-9]|[1-9]\d))"
XSD_MASKS = {
    "eic_popl": r"CZ[0-9]{8,10}",
    "eic_poverujiciho": r"CZ[0-9]{8,10}",
    "povereni_vice_popl": r"true|false|1|0",  # xs:boolean, which has no mask
    "id_jednotky": r"[1-9][0-9]{0,8}",
    "id_pokl": r"[0-9a-zA-Z\.,:;/#\-_ ]{1,20}",
    "porad_cis": r"[0-9a-zA-Z\.,:;/#\-_ ]{1,25}",
    "dat_trzby": r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(Z|[+\-]\d\d:\d\d)",
    "celk_trzba": AMOUNT_MASK,
    "urceno_cerp_zuct": AMOUNT_MASK,
    "cerp_zuct": AMOUNT_MASK,
}

# The taxpayers of the public test environment.
IDENTITIES = ["CZ00000019", "CZ683555118", "CZ8551015704"]

# Complete Data elements from the official documents.
EXAMPLES = [
    # interface description, section 3.3.4: every attribute at once
    (
        'eic_popl="CZ8551015704" eic_poverujiciho="CZ00000019" povereni_vice_popl="true" '
        'id_jednotky="181" id_pokl="00/2535/CN58" porad_cis="0/2482/IE25" '
        'dat_trzby="2027-01-07T22:01:00+01:00" celk_trzba="87988.00" '
        'urceno_cerp_zuct="343.00" cerp_zuct="237.00"'
    ),
    # interface description, section 4: the values that identify a sale
    (
        'eic_popl="CZ00000019" id_jednotky="243" id_pokl="24/A-6/Brno_2" '
        'porad_cis="#135433c/11/2027" dat_trzby="2027-01-09T16:45:36+01:00" celk_trzba="3264.50"'
    ),
    # guide to the data items: a credit top-up together with a purchase
    (
        'eic_popl="CZ00000019" id_jednotky="1551" id_pokl="0001" porad_cis="3210" '
        'dat_trzby="2028-06-01T17:21:45+02:00" celk_trzba="1050.00" urceno_cerp_zuct="1000.00"'
    ),
    # a purchase paid from credit
    (
        'eic_popl="CZ00000019" id_jednotky="1551" id_pokl="0001" porad_cis="3210" '
        'dat_trzby="2028-06-21T20:00:45+02:00" celk_trzba="290.00" cerp_zuct="290.00"'
    ),
    # a refund back to credit
    (
        'eic_popl="CZ00000019" id_jednotky="81" id_pokl="MC001" porad_cis="45-aja-68" '
        'dat_trzby="2028-05-22T14:21:12+02:00" celk_trzba="-121.00" cerp_zuct="-121.00"'
    ),
    # a sale reported for one authorizing taxpayer
    (
        'eic_popl="CZ683555118" eic_poverujiciho="CZ00000019" id_jednotky="31" id_pokl="Sto3" '
        'porad_cis="1234-812/9" dat_trzby="2027-03-22T15:39:01+01:00" celk_trzba="860.00"'
    ),
    # a sale that belongs to several taxpayers, the reporting one among them
    (
        'eic_popl="CZ8551015704" povereni_vice_popl="true" id_jednotky="35871" id_pokl="3" '
        'porad_cis="12252/22" dat_trzby="2027-03-22T15:39:01+01:00" celk_trzba="25000.00"'
    ),
    # a returned sale
    (
        'eic_popl="CZ00000019" id_jednotky="121" id_pokl="fra23" porad_cis="12829" '
        'dat_trzby="2027-09-10T17:08:33+02:00" celk_trzba="-5450.00"'
    ),
    # a partial refund
    (
        'eic_popl="CZ00000019" id_jednotky="51" id_pokl="04" porad_cis="7139935" '
        'dat_trzby="2027-09-04T08:12:46+02:00" celk_trzba="-24.00"'
    ),
]


class NoOffset(tzinfo):
    def utcoffset(self, dt: datetime | None) -> None:
        return None

    dst = tzname = utcoffset


def make(**changes: Any) -> Sale:
    values: dict[str, Any] = {
        "eic": "CZ00000019",
        "unit_id": 11,
        "device_id": "POS-1",
        "sequence": "2027/0001",
        "sold_at": datetime(2027, 1, 9, 4, 25, 28, tzinfo=CET),
        "total": Decimal("1500.00"),
    }
    values.update(changes)
    return Sale(**values)


def attributes(**changes: Any) -> dict[str, str]:
    result = _data_attributes(make(**changes))
    for name, value in result.items():
        assert re.fullmatch(XSD_MASKS[name], value, re.ASCII), (name, value)
    return result


def test_required_attributes_in_schema_order() -> None:
    assert list(attributes().items()) == [
        ("eic_popl", "CZ00000019"),
        ("id_jednotky", "11"),
        ("id_pokl", "POS-1"),
        ("porad_cis", "2027/0001"),
        ("dat_trzby", "2027-01-09T04:25:28+01:00"),
        ("celk_trzba", "1500.00"),
    ]


@pytest.mark.parametrize("example", EXAMPLES)
def test_official_examples_are_reproduced(example: str) -> None:
    given = dict(re.findall(r'(\w+)="([^"]*)"', example))
    optional = {
        name: Decimal(given[xml_name])
        for name, xml_name in [
            ("to_be_drawn", "urceno_cerp_zuct"),
            ("drawn", "cerp_zuct"),
        ]
        if xml_name in given
    }
    sale = Sale(
        eic=given["eic_popl"],
        authorizing_eic=given.get("eic_poverujiciho"),
        multiple_taxpayers=given.get("povereni_vice_popl") == "true",
        unit_id=int(given["id_jednotky"]),
        device_id=given["id_pokl"],
        sequence=given["porad_cis"],
        sold_at=datetime.fromisoformat(given["dat_trzby"]),
        total=Decimal(given["celk_trzba"]),
        **optional,
    )
    rendered = " ".join(
        f'{name}="{value}"' for name, value in _data_attributes(sale).items()
    )
    assert rendered == example


def test_sale_is_immutable() -> None:
    sale = make()
    with pytest.raises(dataclasses.FrozenInstanceError):
        sale.total = Decimal("1.00")  # type: ignore[misc]


def test_sale_takes_keyword_arguments_only() -> None:
    positional: Any = Sale
    with pytest.raises(TypeError):
        positional("CZ00000019", 11, "POS-1", "1", make().sold_at, Decimal(1))


def test_equal_values_make_equal_sales() -> None:
    in_utc = make(sold_at=datetime(2027, 1, 9, 3, 25, 28, tzinfo=UTC))
    assert in_utc == make()
    assert hash(in_utc) == hash(make())
    assert _data_attributes(in_utc) == _data_attributes(make())


@pytest.mark.parametrize("value", IDENTITIES)
def test_eic_accepted(value: str) -> None:
    other = IDENTITIES[IDENTITIES.index(value) - 1]
    assert attributes(eic=value)["eic_popl"] == value
    assert attributes(eic=other, authorizing_eic=value)["eic_poverujiciho"] == value


@pytest.mark.parametrize("field", ["eic", "authorizing_eic"])
@pytest.mark.parametrize(
    "value",
    [
        "",
        "CZ",
        "CZ0000001",  # 7 digits
        "CZ00000000019",  # 11 digits
        "cz00000019",
        "SK00000019",
        "CX00000019",
        "XZ00000019",
        "00000019",
        "CZ0000001X",
        " CZ00000019",
        "CZ00000019 ",
        "CZ00000019\n",
        "CZ0000001\u0661",  # ARABIC-INDIC DIGIT ONE
    ],
)
def test_eic_rejected(field: str, value: str) -> None:
    with pytest.raises(ValueError, match=field):
        make(**{field: value})


@pytest.mark.parametrize("field", ["eic", "authorizing_eic"])
@pytest.mark.parametrize("value", [19, b"CZ00000019"])
def test_eic_must_be_a_str(field: str, value: object) -> None:
    with pytest.raises(TypeError, match=field):
        make(**{field: value})


def test_eic_is_required() -> None:
    with pytest.raises(TypeError, match="eic"):
        make(eic=None)


def test_authorizing_eic_must_differ_from_eic() -> None:
    with pytest.raises(ValueError, match="authorizing_eic"):
        make(authorizing_eic="CZ00000019")


@pytest.mark.parametrize("value", [1, 24, 164968741, 999_999_999])
def test_unit_id_accepted(value: int) -> None:
    assert attributes(unit_id=value)["id_jednotky"] == str(value)


@pytest.mark.parametrize(
    "value", [0, -1, 1_000_000_000, pytest.param(10**5000, id="5001 digits")]
)
def test_unit_id_out_of_range(value: int) -> None:
    with pytest.raises(ValueError, match="unit_id"):
        make(unit_id=value)


@pytest.mark.parametrize("value", ["11", 11.0, Decimal(11), True, None])
def test_unit_id_must_be_an_int(value: object) -> None:
    with pytest.raises(TypeError, match="unit_id"):
        make(unit_id=value)


TEXT_FIELDS = [("device_id", "id_pokl", 20), ("sequence", "porad_cis", 25)]


@pytest.mark.parametrize(("field", "xml_name", "longest"), TEXT_FIELDS)
@pytest.mark.parametrize(
    "value",
    ["5a/A-q/5:22d_2", "#25/c-12/1A_2/2027", "0", " ", " a b ", "azAZ09.,:;/#-_ "],
)
def test_text_accepted(field: str, xml_name: str, longest: int, value: str) -> None:
    assert attributes(**{field: value})[xml_name] == value


@pytest.mark.parametrize(("field", "xml_name", "longest"), TEXT_FIELDS)
@pytest.mark.parametrize(
    "value",
    [
        "",
        "a\tb",
        "a\nb",
        "abc\n",
        "a+b",
        "a*b",
        "a\\b",
        "a'b",
        'a"b',
        "a<b",
        "a&b",
        "\u010d",  # č
        "\u0661",
    ],
)
def test_text_rejected(field: str, xml_name: str, longest: int, value: str) -> None:
    with pytest.raises(ValueError, match=field):
        make(**{field: value})


@pytest.mark.parametrize(("field", "xml_name", "longest"), TEXT_FIELDS)
def test_text_length(field: str, xml_name: str, longest: int) -> None:
    assert attributes(**{field: "x" * longest})[xml_name] == "x" * longest
    with pytest.raises(ValueError, match=field):
        make(**{field: "x" * (longest + 1)})


@pytest.mark.parametrize(("field", "xml_name", "longest"), TEXT_FIELDS)
def test_text_alphabet(field: str, xml_name: str, longest: int) -> None:
    allowed = set(string.digits + string.ascii_letters + ".,:;/#-_ ")
    for char in map(chr, range(0x250)):
        if char in allowed:
            assert attributes(**{field: char})[xml_name] == char
        else:
            with pytest.raises(ValueError, match=field):
                make(**{field: char})


@pytest.mark.parametrize(("field", "xml_name", "longest"), TEXT_FIELDS)
@pytest.mark.parametrize("value", [5, b"POS-1", None])
def test_text_must_be_a_str(
    field: str, xml_name: str, longest: int, value: object
) -> None:
    with pytest.raises(TypeError, match=field):
        make(**{field: value})


@pytest.mark.parametrize(("field", "xml_name", "longest"), TEXT_FIELDS)
def test_refused_text_is_cut_short_in_the_error(
    field: str, xml_name: str, longest: int
) -> None:
    with pytest.raises(ValueError, match=field) as refused:
        make(**{field: "\x00" * 10_000})
    assert len(str(refused.value)) < 300


def test_enum_members_are_reported_by_their_value() -> None:
    class Device(str, enum.Enum):
        MAIN = "POS-1"

    class Unit(int, enum.Enum):
        SHOP = 11

    result = attributes(device_id=Device.MAIN, unit_id=Unit.SHOP)
    assert f"{result['id_pokl']} {result['id_jednotky']}" == "POS-1 11"
    assert type(result["id_pokl"]) is str


@pytest.mark.parametrize(
    ("value", "text"),
    [
        (datetime(2027, 1, 9, 4, 25, 28, tzinfo=CET), "2027-01-09T04:25:28+01:00"),
        (datetime(2027, 6, 9, 5, 25, 28, tzinfo=CEST), "2027-06-09T05:25:28+02:00"),
        (datetime(2027, 1, 9, 3, 25, 28, tzinfo=UTC), "2027-01-09T04:25:28+01:00"),
        (datetime(2027, 6, 9, 3, 25, 28, tzinfo=UTC), "2027-06-09T05:25:28+02:00"),
        (
            datetime(2027, 6, 9, 3, 25, 28, tzinfo=ZoneInfo("Europe/Prague")),
            "2027-06-09T03:25:28+02:00",
        ),
        (
            datetime(
                2027, 6, 9, 3, 25, 28, tzinfo=timezone(-timedelta(hours=3, minutes=30))
            ),
            "2027-06-09T08:55:28+02:00",
        ),
        # an offset with seconds is still an exact moment
        (
            datetime(
                2027, 1, 9, 4, 25, 58, tzinfo=timezone(timedelta(hours=1, seconds=30))
            ),
            "2027-01-09T04:25:28+01:00",
        ),
        # the last second of winter time and the first of summer time
        (datetime(2027, 3, 28, 0, 59, 59, tzinfo=UTC), "2027-03-28T01:59:59+01:00"),
        (datetime(2027, 3, 28, 1, 0, 0, tzinfo=UTC), "2027-03-28T03:00:00+02:00"),
        # a local time that summer time skips is the same moment an hour later
        (
            datetime(2027, 3, 28, 2, 30, 0, tzinfo=ZoneInfo("Europe/Prague")),
            "2027-03-28T03:30:00+02:00",
        ),
        # the hour that repeats when summer time ends
        (datetime(2027, 10, 31, 0, 30, 0, tzinfo=UTC), "2027-10-31T02:30:00+02:00"),
        (datetime(2027, 10, 31, 1, 30, 0, tzinfo=UTC), "2027-10-31T02:30:00+01:00"),
    ],
)
def test_sold_at_is_reported_in_czech_local_time(value: datetime, text: str) -> None:
    assert attributes(sold_at=value)["dat_trzby"] == text


@pytest.mark.parametrize(
    "value",
    [
        datetime(2027, 1, 9, 4, 25, 28),  # noqa: DTZ001
        datetime(2027, 1, 9, 4, 25, 28, 1, tzinfo=CET),
        datetime(2027, 1, 9, 4, 25, 28, tzinfo=NoOffset()),
        datetime(
            2027, 1, 9, 4, 25, 28, tzinfo=timezone(timedelta(hours=1, microseconds=1))
        ),
        datetime(1850, 1, 1, tzinfo=UTC),  # local mean time, offset +00:57:44
        # no local time left to convert to
        datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC),
    ],
)
def test_sold_at_rejected(value: datetime) -> None:
    with pytest.raises(ValueError, match="sold_at"):
        make(sold_at=value)


@pytest.mark.parametrize(
    "value", ["2027-01-09T04:25:28+01:00", 1799465128, date(2027, 1, 9), None]
)
def test_sold_at_must_be_a_datetime(value: object) -> None:
    with pytest.raises(TypeError, match="sold_at"):
        make(sold_at=value)


AMOUNT_FIELDS = [
    ("total", "celk_trzba"),
    ("to_be_drawn", "urceno_cerp_zuct"),
    ("drawn", "cerp_zuct"),
]


@pytest.mark.parametrize(("field", "xml_name"), AMOUNT_FIELDS)
@pytest.mark.parametrize(
    ("value", "text"),
    [
        ("250.00", "250.00"),
        ("-187.20", "-187.20"),
        ("0.56", "0.56"),
        ("0.2", "0.20"),
        ("20.45", "20.45"),
        ("-100", "-100.00"),
        ("-0.01", "-0.01"),
        ("-0.10", "-0.10"),
        ("0.01", "0.01"),
        ("1500", "1500.00"),
        ("1500.000", "1500.00"),
        ("1.5E+3", "1500.00"),
        ("15E-1", "1.50"),
        ("99999999.99", "99999999.99"),
        ("-99999999.99", "-99999999.99"),
    ],
)
def test_amount_formatting(field: str, xml_name: str, value: str, text: str) -> None:
    assert attributes(**{field: Decimal(value)})[xml_name] == text


@pytest.mark.parametrize(("field", "xml_name"), AMOUNT_FIELDS)
@pytest.mark.parametrize(
    "value",
    [
        "0.001",
        "1.005",
        "-0.001",
        "1E-3",
        "100000000",
        "100000000.00",
        "-100000000",
        "1E+8",
        "99999999.999",
        "1.0000000000000000000000000000000000001",  # beyond the default context precision
        "1E+999999999999999999",
        "1E-999999999999999999",
        "-1E+999999999999999999",
        "NaN",
        "sNaN",
        "Infinity",
        "-Infinity",
    ],
)
def test_amount_rejected(field: str, xml_name: str, value: str) -> None:
    with pytest.raises(ValueError, match=field):
        make(**{field: Decimal(value)})


@pytest.mark.parametrize(("field", "xml_name"), AMOUNT_FIELDS)
@pytest.mark.parametrize("value", [1500, 1500.0, "1500.00", True])
def test_amount_must_be_a_decimal(field: str, xml_name: str, value: object) -> None:
    with pytest.raises(TypeError, match=field):
        make(**{field: value})


def test_amount_with_a_million_digits() -> None:
    # milliseconds here; work that grows with the square of the digits takes
    # half a minute
    zeros = "0" * 1_000_000
    started = time.monotonic()
    assert attributes(total=Decimal(f"1.{zeros}"))["celk_trzba"] == "1.00"
    with pytest.raises(ValueError, match="total"):
        make(total=Decimal(f"1.{zeros}1"))
    assert time.monotonic() - started < 2


def test_total_is_required() -> None:
    with pytest.raises(TypeError, match="total"):
        make(total=None)


@pytest.mark.parametrize(
    "value",
    [
        "0",
        "0.0",
        "0.00",
        "-0",
        "-0.00",
        "0E+999999999999999999",
        "0E-999999999999999999",
    ],
)
def test_total_may_be_zero(value: str) -> None:
    assert attributes(total=Decimal(value))["celk_trzba"] == "0.00"


@pytest.mark.parametrize("field", ["to_be_drawn", "drawn"])
@pytest.mark.parametrize("value", ["0", "0.00", "-0"])
def test_optional_amount_must_not_be_zero(field: str, value: str) -> None:
    with pytest.raises(ValueError, match=f"{field} must not be zero"):
        make(**{field: Decimal(value)})


def test_multiple_taxpayers() -> None:
    assert attributes(multiple_taxpayers=True)["povereni_vice_popl"] == "true"
    with pytest.raises(TypeError, match="multiple_taxpayers"):
        make(multiple_taxpayers=1)


def test_optional_attributes_are_left_out_when_not_given() -> None:
    assert list(attributes(multiple_taxpayers=False)) == [
        "eic_popl",
        "id_jednotky",
        "id_pokl",
        "porad_cis",
        "dat_trzby",
        "celk_trzba",
    ]
