"""Cases ported from snmpy's own test suite for the `ber` package.

Provenance: `snmpy/ber/test_objectLength.py` and `snmpy/ber/test_objectTag.py`, MIT licensed
(© 2026 snmpy Contributors; see NOTICE). The *cases* are reused, not the code - they are
re-expressed against this package's API, because snmpy's API is what is being replaced.

This file is the reason `NOTICE` can claim a regression floor. What is **not** ported:
`snmpy/ber/test_objectIdentifier.py`, whose three tests exercise `ObjectIdentifier` as a
value type. There is no OID type here yet (`dk.oid` in PLAN.md is open), so those cases have
nowhere to land, and pretending the floor is complete would be worse than saying it is short.
Two of those three tests assert that an invalid OID raises `AssertionError` - which means
snmpy validates it with a bare `assert`, and `python -O` removes that protection entirely.
That is a defect class in its own right, and one this package forbids by rule
(SECURITY.md item 3, enforced by `test_library_contains_no_assert_statements`).
"""

from __future__ import annotations

import pytest

from asn1core import TagClass, decode_length, decode_tag, encode_length, encode_tag


@pytest.mark.parametrize(
    ("length", "expected_hex"),
    [
        (0b01111111, "7f"),  # 127: snmpy case 1
        (0b10000000, "8180"),  # 128: snmpy case 2
        (0b0000000100000001, "820101"),  # 257: snmpy case 3, two length octets
    ],
    ids=["snmpy-length-127", "snmpy-length-128", "snmpy-length-257"],
)
def test_snmpy_length_cases_still_hold(length: int, expected_hex: str) -> None:
    """The three length pairs snmpy tested, in both directions, unchanged.

    snmpy's own suite is the floor here: if one of these ever disagrees, a caller that moved
    from `ber` to this package changes behaviour on a path that was already covered.
    """
    encoded = encode_length(length)
    assert encoded == bytes.fromhex(expected_hex), length
    decoded, offset = decode_length(encoded)
    assert decoded == length, length
    assert offset == len(encoded), length


def test_snmpy_null_tag_encoding() -> None:
    """bytes(ObjectTag(universal, primitive, null)) == b'\\x05' in snmpy."""
    from asn1core import Tag

    assert encode_tag(Tag(5, constructed=False, tag_class=TagClass.universal)) == bytes([5])
    tag, offset = decode_tag(bytes([5]))
    assert (tag.number, tag.constructed, tag.tag_class, offset) == (5, False, TagClass.universal, 1)


def test_snmpy_sequence_tag_encoding() -> None:
    """bytes(ObjectTag(universal, constructed, sequence_of)) == b'\\x30' in snmpy."""
    from asn1core import Tag

    assert encode_tag(Tag(16, constructed=True, tag_class=TagClass.universal)) == bytes(
        [0b00110000]
    )
    tag, _ = decode_tag(bytes([0b00110000]))
    assert (tag.number, tag.constructed) == (16, True)


def test_high_tag_numbers_snmpy_never_tested() -> None:
    """The gap snmpy's suite left: it tested two low tags and nothing above 30.

    Those two cases pass in the original. The ones below are why the original is being
    replaced - `ObjectTag.decode` returns 3999 for the encoding of 31 and 508032 for 128.
    """
    from asn1core import Tag

    for number in (31, 128, 16384):
        raw = encode_tag(Tag(number, False, TagClass.universal))
        decoded, _ = decode_tag(raw)
        assert decoded.number == number, number
        assert raw[0] & 0x1F == 0x1F, number
