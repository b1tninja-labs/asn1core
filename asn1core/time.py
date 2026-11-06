"""UTCTime and GeneralizedTime, with the rules quoted rather than recalled.

RFC 5280 §4.1.2.5.1: "UTCTime values MUST be expressed in Greenwich Mean Time (Zulu) and MUST
include seconds (i.e., times are YYMMDDHHMMSSZ), even where the number of seconds is zero", and
the year is read as "`YY >= 50` means 19YY, `YY < 50` means 20YY". §4.1.2.5.2 says the same of
GeneralizedTime at four-digit width and adds "MUST NOT include fractional seconds". No verified
erratum touches either section (checked 2026-11-05).

Two things this module deliberately does not do:

**It does not enforce the 2049 boundary.** That rule - validity dates "through the year 2049" as
UTCTime and "2050 or later" as GeneralizedTime - is in §4.1.2.5 about the `Validity` *field*, and
it constrains what a CA may issue rather than what a time value means. Enforcing it here would
reject legal UTCTime. See `asn1core.x509.validity_encoding_issue`.

**It does not read dates on the BER path.** Like INTEGER and BIT STRING, value-level checks are
DER-path only. A tolerant decode keeps the content octets and never rewrites an instant.

One X.690 question stays open: a seconds field of 60, which X.690 permits in some time encodings,
cannot be held by `datetime` and is refused under its own rule name rather than rolled into the
next minute. `VECTORS.md` keeps that row marked.
"""

from __future__ import annotations

import datetime

from .errors import DerViolation

__all__ = [
    "NO_EXPIRATION",
    "UTC_TIME_CEILING_YEAR",
    "UTC_TIME_FLOOR_YEAR",
    "check_generalized_time",
    "check_utc_time",
    "encode_generalized_time",
    "encode_utc_time",
    "time_tag_for",
]

UTC = datetime.UTC

# The window UTCTime can express once §4.1.2.5.1's rule is applied, and the value §4.1.2.5 tells a
# CA to use when a certificate has no well-defined expiration date.
UTC_TIME_FLOOR_YEAR = 1950
UTC_TIME_CEILING_YEAR = 2049
NO_EXPIRATION = datetime.datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)

_UTC_OCTETS = 13  # YYMMDDHHMMSSZ
_GENERALIZED_OCTETS = 15  # YYYYMMDDHHMMSSZ
_ZERO = 0x30
_NINE = 0x39
_ZULU = 0x5A


def check_utc_time(content: bytes, *, offset: int | None = None) -> datetime.datetime:
    """Parse a DER-canonical UTCTime, reading the two-digit year as §4.1.2.5.1 requires."""
    return _parse(content, four_digit_year=False, label="UTCTime", offset=offset)


def check_generalized_time(content: bytes, *, offset: int | None = None) -> datetime.datetime:
    """Parse a DER-canonical GeneralizedTime: century mandatory, seconds mandatory, no fraction."""
    return _parse(content, four_digit_year=True, label="GeneralizedTime", offset=offset)


def _parse(
    content: bytes, *, four_digit_year: bool, label: str, offset: int | None
) -> datetime.datetime:
    width = _GENERALIZED_OCTETS if four_digit_year else _UTC_OCTETS
    if len(content) != width:
        raise DerViolation(
            f"{label} is {len(content)} octets; this profile requires {width}",
            rule="time-not-canonical",
            offset=offset,
        )
    if content[-1] != _ZULU:
        raise DerViolation(
            f"{label} must end with the Zulu designator", rule="time-not-zulu", offset=offset
        )
    body = content[:-1]
    if any(b < _ZERO or b > _NINE for b in body):
        raise DerViolation(f"{label} has a non-digit octet", rule="time-not-numeric", offset=offset)

    text = body.decode("ascii")
    year_text, rest = (text[:4], text[4:]) if four_digit_year else (text[:2], text[2:])
    month, day, hour, minute, second = (int(rest[i : i + 2]) for i in (0, 2, 4, 6, 8))
    if second == 60:
        raise DerViolation(
            f"{label} carries a leap second, which cannot be represented here without moving "
            f"the instant by up to a minute",
            rule="time-leap-second",
            offset=offset,
        )
    year = int(year_text)
    if not four_digit_year:
        # §4.1.2.5.1, both halves. There is no other permitted reading, and no UTCTime value that
        # means a year outside 1950-2049 - which is what makes §4.1.2.5's wording exact.
        year = 1900 + year if year >= 50 else 2000 + year
    try:
        return datetime.datetime(year, month, day, hour, minute, second, tzinfo=UTC)
    except ValueError as exc:
        raise DerViolation(
            f"{label} is not a real instant: {exc}", rule="time-invalid-calendar", offset=offset
        ) from exc


def encode_utc_time(value: datetime.datetime) -> bytes:
    """Encode as UTCTime, refusing any year the two-digit form cannot carry."""
    return _encode(value, four_digit_year=False, label="UTCTime")


def encode_generalized_time(value: datetime.datetime) -> bytes:
    """Encode as GeneralizedTime: four-digit year, whole seconds, Zulu."""
    return _encode(value, four_digit_year=True, label="GeneralizedTime")


def _encode(value: datetime.datetime, *, four_digit_year: bool, label: str) -> bytes:
    if not isinstance(value, datetime.datetime):
        raise TypeError(f"{label} needs a datetime, got {type(value).__name__}")
    if value.tzinfo is None:
        raise ValueError(f"{label}: a naive datetime has no offset to guess; make it aware first")
    if value.microsecond:
        raise ValueError(f"{label}: the profile allows whole seconds only")
    moment = value.astimezone(UTC)
    if not four_digit_year and not UTC_TIME_FLOOR_YEAR <= moment.year <= UTC_TIME_CEILING_YEAR:
        raise ValueError(
            f"UTCTime covers {UTC_TIME_FLOOR_YEAR}-{UTC_TIME_CEILING_YEAR}; year {moment.year} "
            f"has no UTCTime spelling (§4.1.2.5.1), use GeneralizedTime"
        )
    year = f"{moment.year:04d}" if four_digit_year else f"{moment.year % 100:02d}"
    stamp = (
        f"{year}{moment.month:02d}{moment.day:02d}"
        f"{moment.hour:02d}{moment.minute:02d}{moment.second:02d}Z"
    )
    return stamp.encode("ascii")


def time_tag_for(value: datetime.datetime) -> int:
    """The universal tag number §4.1.2.5 tells a CA to use for this instant: 23 or 24.

    A naive datetime is read as written rather than shifted into a different year by an assumed
    offset - the year is the only thing this decision turns on.
    """
    moment = value.astimezone(UTC) if value.tzinfo is not None else value
    return 24 if moment.year > UTC_TIME_CEILING_YEAR else 23
