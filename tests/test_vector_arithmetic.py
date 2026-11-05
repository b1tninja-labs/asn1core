"""Re-derive the corpus's byte arithmetic from bit masks, independently of asn1core.

This file moved here from ``sdk-forge/check_vectors.py``, which is where the derivations
first ran - there was no package to hold them. ``VECTORS.md`` recorded that a corpus whose
expectations are checked by a script outside the repository that consumes it is a corpus that
will silently rot, so the script now lives with the tests it protects.

Nothing here imports ``asn1core``. These functions are a second, independent reading of the
encoding rules, used to confirm that the *expected* values in the corpus are right. If they
imported the module under test, every assertion would become a tautology - which is exactly
how ``ObjectTag.decode`` shipped uncovered: its expectations were derived from itself.
"""

from __future__ import annotations

import pytest


def identifier_parts(first: int) -> tuple[int, int, int]:
    """(class, constructed, number-or-31-sentinel) from one identifier octet."""
    return first >> 6, (first >> 5) & 1, first & 0x1F


def base128_number(octets: bytes) -> int:
    """X.690 8.1.2: value = (value << 7) | payload, high bit set means another follows."""
    value = 0
    for octet in octets:
        value = (value << 7) | (octet & 0x7F)
    return value


def length_of(octets: bytes) -> int:
    first = octets[0]
    if first < 0x80:
        return first
    if first == 0x80:
        return -1
    return int.from_bytes(octets[1 : 1 + (first & 0x7F)], "big")


def signed(content: bytes) -> int:
    return int.from_bytes(content, "big", signed=True)


# (hex identifier run, class, constructed, number) - the tag rows of VECTORS.md.
TAG_ROWS = [
    ("30", 0, 1, 16),  # SEQUENCE: universal, constructed
    ("02", 0, 0, 2),  # INTEGER
    ("a5", 2, 1, 5),  # context 5, constructed
    ("9e", 2, 0, 30),  # context 30: the last number fitting one octet
    ("9f1f", 2, 0, 31),  # 31 means "continuation follows", so the number is read next
    ("9f3f", 2, 0, 63),
    ("9f7f", 2, 0, 127),
    ("9f8100", 2, 0, 128),  # first value needing two continuation octets
    ("9fff7f", 2, 0, 16383),  # (127 << 7) | 127
    ("9f818000", 2, 0, 16384),  # (1 << 14) | (0 << 7) | 0
    ("5fce0f", 1, 0, 9999),  # application, PRIMITIVE: 5F has bit 5 clear
    ("7fce0f", 1, 1, 9999),  # application, CONSTRUCTED: bit 5 is the only place it can go
    ("c1", 3, 0, 1),  # private 1. 81 would be context 1 - the mistake this row exists for
    ("9f8001", 2, 0, 1),  # non-minimal base-128: a leading zero group
]


@pytest.mark.parametrize(("hex_string", "klass", "constructed", "number"), TAG_ROWS)
def test_identifier_octets_split_as_the_standard_says(
    hex_string: str, klass: int, constructed: int, number: int
) -> None:
    raw = bytes.fromhex(hex_string)
    got_class, got_constructed, low = identifier_parts(raw[0])
    assert (got_class, got_constructed) == (klass, constructed), hex_string
    got_number = low if low != 0x1F else base128_number(raw[1:])
    assert got_number == number, hex_string


def test_9e_is_the_ceiling_of_one_octet_tags_and_9f_is_not_a_number() -> None:
    """11111 in the low five bits is not 31; it is the flag that says read more octets."""
    assert identifier_parts(0x9E)[2] == 30
    assert identifier_parts(0x9F)[2] == 31  # sentinel, never a tag number in its own right
    assert base128_number(bytes.fromhex("1f")) == 31


def test_number_9999_needs_ce_0f_and_not_a3_0f() -> None:
    """The hand-written vector was wrong here first: A3 0F decodes to 4495, not 9999."""
    assert base128_number(bytes.fromhex("ce0f")) == 9999
    assert base128_number(bytes.fromhex("a30f")) == 4495


def test_high_tag_number_leaves_bit_5_for_constructedness() -> None:
    """The reason 5F and 7F are different tags, and why OR-ing the fields is wrong."""
    assert identifier_parts(0x5F)[:2] == (1, 0)
    assert identifier_parts(0x7F)[:2] == (1, 1)
    # A decoder that OR-ed class bits with number bits would read 5F as class 1, number 31
    # and then lose the constructed bit entirely.
    assert 0x5F >> 6 == 1
    assert 0x5F & 0x1F == 31


LENGTH_ROWS = [
    ("7f", 127),  # last short form
    ("8180", 128),  # first long form
    ("81ff", 255),
    ("820100", 256),  # the exact power of 256 that broke the float-based encoder
    ("83010000", 65536),
    ("817f", 127),  # long form for a value that fits short: legal BER, illegal DER
    ("82007f", 127),  # leading zero octet: legal BER, illegal DER
    ("80", -1),  # indefinite
]


@pytest.mark.parametrize(("hex_string", "length"), LENGTH_ROWS)
def test_length_octets_decode_to_the_documented_value(hex_string: str, length: int) -> None:
    assert length_of(bytes.fromhex(hex_string)) == length, hex_string


def test_nonminimal_and_canonical_lengths_agree_on_value_and_differ_on_legality() -> None:
    """81 7F and 7F both say 127. DER permits exactly one of those spellings."""
    assert length_of(bytes.fromhex("817f")) == length_of(bytes.fromhex("7F")) == 127


INTEGER_ROWS = [
    ("80", -128),  # minimal, and there is no negative zero in two's complement
    ("ff7f", -129),
    ("0080", 128),  # the leading 00 is load-bearing: 80 alone would read as -128
    ("00", 0),
    ("ff", -1),
    ("7f", 127),
]


@pytest.mark.parametrize(("hex_string", "value"), INTEGER_ROWS)
def test_two_s_complement_integers(hex_string: str, value: int) -> None:
    assert signed(bytes.fromhex(hex_string)) == value, hex_string


def test_leading_zero_is_redundant_only_when_the_next_octet_is_positive() -> None:
    """The rule that stops 'strip the leading zeros' from breaking ECDSA signatures.

    An r value whose high bit is set must keep its 00 octet. A codec that tidies it away
    produces a different signature from the same key, and the failure surfaces at the
    verification layer, far from the cause.
    """
    assert signed(bytes.fromhex("0080")) == 128  # 00 required
    assert signed(bytes.fromhex("007f")) == 127  # 00 redundant: 7f says the same thing
    assert signed(bytes.fromhex("ff80")) == -128  # FF redundant
    assert signed(bytes.fromhex("80")) == -128


def test_bit_string_unused_bits_rule() -> None:
    """bits-unused-nonzero: 03 03 03 41 41 declares 3 unused bits, and 0x41 has one set."""
    unused = 0x03
    assert 0x41 & ((1 << unused) - 1) == 1, "DER requires the unused bits to be zero"
    assert 0x40 & ((1 << unused) - 1) == 0  # the compliant spelling of the same data


def test_oid_first_content_octet_is_40a_plus_b() -> None:
    """oid-first-arc: 0x4F is 79 = 40*1 + 39, so this is 1.39 and never 1.47."""
    assert (0x4F // 40, 0x4F % 40) == (1, 39)
    # 0x7F implies arc 3, which the one-octet form cannot express. That is why snmpy's
    # min(2, octet // 40) fabricates 2.47 instead of refusing: it clamps into the legal
    # range rather than rejecting the illegal one.
    assert (0x7F // 40, 0x7F % 40) == (3, 7)
    assert 0x7F // 40 > 2


def test_base128_arc_accumulation_matches_the_tag_path() -> None:
    """oid-arc-continuation: 2C 81 00 is 1.4.128, the same bug class as tag-c-128."""
    assert base128_number(bytes.fromhex("8100")) == 128
    assert base128_number(bytes.fromhex("8001")) == 1  # non-minimal spelling of 1
