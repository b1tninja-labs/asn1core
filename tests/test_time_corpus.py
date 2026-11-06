"""Time encoding: `dk.time`, with the two corpus rows about it corrected first.

The rules are quoted from RFC 5280 rather than recalled. §4.1.2.5.1: UTCTime in this profile
"MUST be expressed in Greenwich Mean Time (Zulu) and MUST include seconds (i.e., times are
YYMMDDHHMMSSZ)"; §4.1.2.5.2 says the same for GeneralizedTime at four-digit year width and adds
"MUST NOT include fractional seconds". Neither section carries a verified erratum (checked
2026-11-05).

**Two corpus rows were wrong, and the corrections are in `VECTORS.md`.**

`utc-ambiguity` gave the bytes `050506194000Z`, which is not an encoding of anything: it mixes
hex with a literal `Z` and declares a length that does not match its content. The vector below is
the real 13-octet form of the same intended instant.

`gen-time-after-2049` claimed a UTCTime "encoding a 2099 date" must be refused. No UTCTime
encodes 2099. `991231235959Z` is 1999 and must be read as 1999 - `YY >= 50` means `19YY`
unconditionally, which is the whole content of the ambiguity the row was worried about. The
2049/2050 boundary is real but lives elsewhere: §4.1.2.5 says a **CA** must spell validity dates
through 2049 as UTCTime and 2050 or later as GeneralizedTime. That is a production rule about a
certificate field, so it is checked on `Validity` (`asn1core.x509`) and not smuggled into the
type decoder, where it would have rejected legal UTCTime values.
"""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from asn1core import (
    CertificateError,
    DerViolation,
    check_generalized_time,
    check_utc_time,
    decode,
    encode_generalized_time,
    encode_utc_time,
    validity,
    validity_encoding_issue,
)

UTC = datetime.UTC

# (content octets, expected instant). Boundaries first: these are what an off-by-one on the
# century rule gets wrong, and both directions appear in the vendored fixtures below.
UTC_VECTORS = [
    ("500101000000Z", datetime.datetime(1950, 1, 1, 0, 0, 0, tzinfo=UTC)),
    ("491231235959Z", datetime.datetime(2049, 12, 31, 23, 59, 59, tzinfo=UTC)),
    ("960129000000Z", datetime.datetime(1996, 1, 29, 0, 0, 0, tzinfo=UTC)),
    ("210115000000Z", datetime.datetime(2021, 1, 15, 0, 0, 0, tzinfo=UTC)),
    ("991231235959Z", datetime.datetime(1999, 12, 31, 23, 59, 59, tzinfo=UTC)),
    ("050619040000Z", datetime.datetime(2005, 6, 19, 4, 0, 0, tzinfo=UTC)),
]

GEN_VECTORS = [
    ("19500101000000Z", datetime.datetime(1950, 1, 1, 0, 0, 0, tzinfo=UTC)),
    ("20491231235959Z", datetime.datetime(2049, 12, 31, 23, 59, 59, tzinfo=UTC)),
    ("20500101000000Z", datetime.datetime(2050, 1, 1, 0, 0, 0, tzinfo=UTC)),
    # §4.1.2.5: the "no well-defined expiration date" value a CA is told to use.
    ("99991231235959Z", datetime.datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)),
]


@pytest.mark.parametrize(("text", "moment"), UTC_VECTORS)
def test_utc_time_parses_to_the_instant_the_profile_specifies(
    text: str, moment: datetime.datetime
) -> None:
    content = text.encode("ascii")
    assert check_utc_time(content) == moment, text
    assert encode_utc_time(moment) == content, text


@pytest.mark.parametrize(("text", "moment"), GEN_VECTORS)
def test_generalized_time_parses_to_the_instant_it_spells(
    text: str, moment: datetime.datetime
) -> None:
    content = text.encode("ascii")
    assert check_generalized_time(content) == moment, text
    assert encode_generalized_time(moment) == content, text


@pytest.mark.parametrize("yy", range(100))
def test_the_century_rule_is_exhaustive_not_sampled(yy: int) -> None:
    """RFC 5280 §4.1.2.5.1, all hundred cases: `YY >= 50` means 19YY, anything else means 20YY.

    Sampling the boundary would leave the shape of the rule untested. There is no year that
    UTCTime expresses twice and no year in 1950-2049 it cannot express, which is what makes the
    profile's "through 2049" wording in §4.1.2.5 exact rather than loose.
    """
    content = f"{yy:02d}0101000000Z".encode("ascii")
    expected = (1900 if yy >= 50 else 2000) + yy
    assert check_utc_time(content).year == expected, yy


@pytest.mark.parametrize(
    "content",
    [
        b"",  # absent is not a value
        b"5001010000Z",  # 11 octets: minute precision, which §4.1.2.5.1 forbids here
        b"50010100000",  # 12 octets: truncated seconds
        b"500101000000.5Z",  # fractional seconds
        b"500101000000+0100",  # local differential instead of Zulu
        b"500101000000-0500",
        b"500101000000z",  # lowercase designator: not the canonical spelling
        b"50010100000A",  # neither numeric nor terminated
        b"5O0101000000Z",  # letter O for zero
        b"501301000000Z",  # month 13
        b"500132000000Z",  # day 32
        b"500101240000Z",  # hour 24
        b"500101006000Z",  # minute 60
        b"500230000000Z",  # 30 February
        b"500431000000Z",  # 31 April
        b"20500101000000Z",  # four-digit year in a two-digit field
    ],
)
def test_utc_time_forms_the_profile_forbids_are_refused_by_name(content: bytes) -> None:
    with pytest.raises(DerViolation):
        check_utc_time(content)


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"500101000000Z",  # two-digit year: GeneralizedTime carries the century
        b"205001010000Z",  # 14 octets
        b"20500101000000.5Z",  # fractional seconds, forbidden by §4.1.2.5.2
        b"20500101000000+0100",
        b"20500101000000z",
        b"00000101000000Z",  # year zero is not a year
        b"20501301000000Z",
        b"99991231235960Z",  # second 60 - see the note below
    ],
)
def test_generalized_time_forms_the_profile_forbids_are_refused_by_name(content: bytes) -> None:
    with pytest.raises(DerViolation):
        check_generalized_time(content)


def test_a_leap_second_is_refused_and_says_so_rather_than_becoming_the_next_minute() -> None:
    """An honest gap, recorded rather than hidden.

    X.690 permits a seconds field of 60 in some time encodings, and RFC 5280 neither requires nor
    forbids it. `datetime` cannot hold 60, and rolling it into the next minute would report an
    instant up to a minute away from the one the document contains - the kind of quiet
    reinterpretation this package is built not to do. So the value is refused under its own rule
    name, and `VECTORS.md` keeps the `[verify against X.690]` marker on this row.
    """
    with pytest.raises(DerViolation):
        check_utc_time(b"500101000060Z")
    with pytest.raises(DerViolation):
        check_generalized_time(b"20500101000060Z")


def test_the_der_path_checks_time_values_and_the_ber_path_leaves_them_alone() -> None:
    """Value-level strictness is a DER-path concern, exactly as it is for INTEGER and BIT STRING.

    In BER mode the content octets are kept verbatim and nobody interprets them, so a tolerant
    read cannot rewrite a date; on the DER path the canonical form is asserted or the document is
    refused.

    The identifiers are spelled here because they are easy to get wrong: UTCTime is universal 23,
    which is octet `17`, and GeneralizedTime is 24, octet `18`. `05` is NULL - the mistake the
    malformed corpus row invited, and the reason the original `utc-ambiguity` bytes could not
    parse as anything.
    """
    utc_time, general_time = 0x17, 0x18

    good = bytes([utc_time, 13]) + b"500101000000Z"
    node, _ = decode(good, der=True)
    assert node.tag.number == 23
    assert node.payload == b"500101000000Z"
    assert check_utc_time(node.payload).year == 1950

    for tag, bad in ((utc_time, b"5001010000Z"), (general_time, b"205001010000Z")):
        raw = bytes([tag, len(bad)]) + bad
        decoded, _ = decode(raw)  # BER: framed and preserved, value untouched
        assert decoded.payload == bad
        with pytest.raises(DerViolation):
            decode(raw, der=True)


def test_the_vendored_roots_read_the_same_dates_cryptography_reads() -> None:
    """The century rule, confirmed against issued documents rather than against my own encoder.

    `960129000000Z` in the RSA root and `460114235959Z` in the ECDSA one sit on opposite sides of
    the 1950 boundary, so a reversed rule cannot pass this test.
    """
    fixtures = Path(__file__).parent / "fixtures"
    expected = {
        "root-ecdsa.der": (
            datetime.datetime(2021, 1, 15, 0, 0, 0, tzinfo=UTC),
            datetime.datetime(2046, 1, 14, 23, 59, 59, tzinfo=UTC),
        ),
        "root-rsa.der": (
            datetime.datetime(1996, 1, 29, 0, 0, 0, tzinfo=UTC),
            datetime.datetime(2028, 8, 1, 23, 59, 59, tzinfo=UTC),
        ),
    }
    for name, (not_before, not_after) in expected.items():
        der = (fixtures / name).read_bytes()
        seen = validity(der)
        assert seen.not_before == not_before, name
        assert seen.not_after == not_after, name
        assert seen.not_before_raw in der, name  # still the stored TLV
        assert seen.not_after_raw in der, name
        assert validity_encoding_issue(der) is None, name


def _tlv(tag: int, content: bytes) -> bytes:
    """One definite-length object, built here so the expectation is not the encoder's own."""
    return bytes([tag, len(content)]) + content


def _certificate_with(validity_bytes: bytes) -> bytes:
    """A structurally valid certificate whose Validity field is whatever the caller supplies."""
    tbs = _tlv(
        0x30,
        b"".join(
            (
                _tlv(0xA0, _tlv(0x02, b"\x02")),  # version v3
                _tlv(0x02, b"\x01"),  # serialNumber
                _tlv(0x30, b""),  # signature AlgorithmIdentifier
                _tlv(0x30, b""),  # issuer
                validity_bytes,
                _tlv(0x30, b""),  # subject
                _tlv(0x30, b""),  # subjectPublicKeyInfo
            )
        ),
    )
    return _tlv(0x30, tbs + _tlv(0x30, b"") + _tlv(0x03, b"\x00"))


# UTCTime is identifier 17, GeneralizedTime is 18. Spelled as names because getting them wrong
# makes a test silently exercise NULL instead of a date.
UTCTIME, GENERALIZED_TIME = 0x17, 0x18


def test_a_2049_date_spelled_as_generalized_time_is_reported_and_not_rejected() -> None:
    """§4.1.2.5: through 2049 a CA MUST use UTCTime, and 2050 or later GeneralizedTime.

    Reported rather than raised, and the distinction is deliberate. This is a rule about what a CA
    may issue, not about whether the bytes are DER or the instant is well defined - both values
    below are unambiguous. Refusing it inside the decoder would repeat the retracted OID mistake:
    inventing a rejection that real documents can hit. Whoever validates certificates raises, and
    now has a named answer to raise about.
    """
    early = _tlv(
        0x30,
        _tlv(GENERALIZED_TIME, b"20490101000000Z") + _tlv(GENERALIZED_TIME, b"20491231235959Z"),
    )
    issue = validity_encoding_issue(_certificate_with(early))
    assert issue is not None
    assert "UTCTime" in issue

    on_time = _tlv(
        0x30, _tlv(UTCTIME, b"490101000000Z") + _tlv(GENERALIZED_TIME, b"20500101000000Z")
    )
    assert validity_encoding_issue(_certificate_with(on_time)) is None

    sentinel = _tlv(
        0x30,
        _tlv(UTCTIME, b"210115000000Z") + _tlv(GENERALIZED_TIME, b"99991231235959Z"),
    )
    assert validity_encoding_issue(_certificate_with(sentinel)) is None, "§4.1.2.5 prescribes this"


def test_validity_that_is_not_two_times_is_a_shape_error() -> None:
    """The Validity slot holds two time values; anything else means this is not a certificate."""
    wrong = _tlv(0x30, _tlv(0x02, b"\x01") + _tlv(0x02, b"\x02"))
    with pytest.raises(CertificateError):
        validity(_certificate_with(wrong))
    short = _tlv(0x30, _tlv(UTCTIME, b"210115000000Z"))
    with pytest.raises(CertificateError):
        validity(_certificate_with(short))
    # NULL, not a time: the tag this file originally got wrong, now a case of its own.
    null_slot = _tlv(0x30, _tlv(0x05, b"") + _tlv(UTCTIME, b"210115000000Z"))
    with pytest.raises(CertificateError):
        validity(_certificate_with(null_slot))


def test_encoders_refuse_instants_their_type_cannot_spell() -> None:
    """UTCTime covers 1950-2049 and nothing else, which is why §4.1.2.5 exists at all.

    A naive datetime is refused too: guessing that it meant UTC would put a locally built
    certificate's validity window an offset away from what its author intended, the same class of
    silent reinterpretation this package refuses elsewhere.
    """
    with pytest.raises(ValueError, match="no UTCTime spelling"):
        encode_utc_time(datetime.datetime(2050, 1, 1, tzinfo=UTC))
    with pytest.raises(ValueError, match="no UTCTime spelling"):
        encode_utc_time(datetime.datetime(1949, 12, 31, 23, 59, 59, tzinfo=UTC))
    with pytest.raises(ValueError, match="whole seconds only"):
        encode_generalized_time(datetime.datetime(2050, 1, 1, 0, 0, 0, 500000, tzinfo=UTC))
    with pytest.raises(ValueError, match="naive datetime"):
        encode_utc_time(datetime.datetime(2021, 1, 15))
    assert (
        encode_utc_time(datetime.datetime(2049, 12, 31, 23, 59, 59, tzinfo=UTC)) == b"491231235959Z"
    )
    assert encode_generalized_time(datetime.datetime(2050, 1, 1, tzinfo=UTC)) == b"20500101000000Z"
    assert encode_generalized_time(datetime.datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)) == (
        b"99991231235959Z"
    )
