"""Object identifier rows from VECTORS.md, plus the ones snmpy gets wrong.

Every expected byte string here is derived from X.690 8.19 by hand: the first two arcs collapse
to `40a + b`, that value takes one octet while it is below 128, and above that it takes the
base-128 form. The `2.47.1` row is the one this repository previously got backwards - an earlier
corpus row demanded it be *refused*, which would have made the DER path reject every `2.5.x` OID
in existence. The evidence that settled it is in `PLAN.md`: 61 real certificates encode
`2.5.29.19` as `06 03 55 1D 13`.

`snmpy`'s own suite is mined here too. Its vector for `2.100.3` is `B4 03`, and `0xB4` has bit 8
set, which in this encoding means "another octet follows" - so a conforming decoder reads one
value rather than two arcs and produces a *different OID*. That is not canonicality tidiness; it
is identity substitution across implementations.
"""

from __future__ import annotations

import pytest

from asn1core import (
    Asn1Error,
    DecodeError,
    DerViolation,
    TruncatedError,
    check_oid,
    decode,
    decode_oid,
    encode_der,
    encode_oid,
    parse_oid_string,
)

# (dotted form, content octets) - canonical DER for each.
CANONICAL = [
    ("0.0", "00"),
    ("1.3.0", "2b00"),
    ("1.3.127", "2b7f"),
    ("1.3.128", "2b8100"),
    ("1.3.8571.3.2", "2bc27b0302"),  # snmpy's own vector, and it is right
    ("1.39", "4f"),  # 79 = 40*1 + 39: the corpus row that used to read 1.47
    ("2.0", "50"),  # 80 = 40*2 + 0, still one octet
    ("2.47.1", "7f01"),  # 127 = 40*2 + 47: the retracted "must refuse" row
    ("1.4.128", "2c8100"),  # the corpus row `06 03 2C 81 00`: same base-128 path as high tags
    (
        "2.48",
        "8100",
    ),  # 40*2 + 48 = 128, and 128 in base-128 is 81 00 - the first pair that needs two octets
    ("2.100.3", "813403"),  # what snmpy means; what it writes (B4 03) decodes as 2.6579
    ("2.5.29.19", "551d13"),  # basicConstraints, as 61 real certificates encode it
    ("2.16.840.1.113733.1", "6086480186f84501"),  # Microsoft's policy arc
]


@pytest.mark.parametrize(("text", "hex_content"), CANONICAL)
def test_oid_encodes_to_the_canonical_octets(text: str, hex_content: str) -> None:
    assert encode_oid(parse_oid_string(text)) == bytes.fromhex(hex_content), text


@pytest.mark.parametrize(("text", "hex_content"), CANONICAL)
def test_oid_decodes_back_to_the_same_arcs(text: str, hex_content: str) -> None:
    content = bytes.fromhex(hex_content)
    assert decode_oid(content) == parse_oid_string(text), text
    assert check_oid(content) == parse_oid_string(text), text


def test_the_two_encodings_of_2_100_are_not_equivalent() -> None:
    """The snmpy vector, demonstrated rather than asserted.

    `B4 03` is what snmpy's own suite expects for 2.100.3. Bit 8 of 0xB4 is set, so the first
    pair is one base-128 value continued into the next octet: (0x34 << 7) | 0x03 = 6659, which
    is 2.6579 with no third arc. `B4 03` is *valid DER* - for a different OID. The defect lives
    in snmpy's encoder, not in these bytes, and `check_oid` correctly has nothing to say about
    them.
    """
    canonical = encode_oid((2, 100, 3))
    snmpy_form = bytes.fromhex("b403")
    assert canonical == bytes.fromhex("813403")
    assert snmpy_form != canonical
    assert decode_oid(snmpy_form) == (2, 6579), "the pair folds, swallowing an arc"
    assert check_oid(snmpy_form) == (2, 6579), "well-formed DER, for the wrong identifier"


def test_no_single_octet_first_pair_encodes_an_arc_above_two() -> None:
    """Every one-octet first pair must decode to a first arc of 0, 1 or 2.

    The property, rather than a chosen byte: this is the rule that made the retracted corpus row
    wrong. 80-127 is not "arc 3 in disguise", it is arc 2 with a large second component.
    """
    for octet in range(0x80):
        arcs = decode_oid(bytes([octet]))
        assert arcs[0] in (0, 1, 2), octet
        if arcs[0] < 2:
            assert arcs[1] <= 39, octet


@pytest.mark.parametrize("text", ["3.0", "1.41", "", "1", "0.40", "1.40", "2.-1", "2.5.29.19."])
def test_invalid_dotted_forms_are_refused_not_repaired(text: str) -> None:
    """The defect snmpy runs with `assert`, so that `python -O` deletes the check.

    Under `-O` snmpy turns "3.0" into 2.40 and "1.41" into 2.1: validation vanishes and the
    `min(2, ...)` fallback fabricates a plausible identifier. Here these raise, and they raise as
    real checks, so the behaviour cannot change with `-O`.
    """
    with pytest.raises((ValueError, Asn1Error)):
        parse_oid_string(text)


def test_empty_oid_content_is_refused() -> None:
    """06 00: an OID carries at least the first-pair octet. Empty is not a value."""
    with pytest.raises((DecodeError, DerViolation)):
        check_oid(b"")
    with pytest.raises((DecodeError, DerViolation)):
        decode(b"0600", der=True)


def test_truncated_continuation_is_a_named_error() -> None:
    """A continuation bit that is never paid for, at the start and mid-stream."""
    with pytest.raises(TruncatedError):
        decode_oid(bytes.fromhex("81"))
    with pytest.raises(TruncatedError):
        decode_oid(bytes.fromhex("2b81"))


def test_nonminimal_subidentifier_ber_tolerates_der_refuses() -> None:
    """oid-arc-nonminimal: `80 01` is the value 1 written with a leading zero group."""
    content = bytes.fromhex("2b8001")
    assert decode_oid(content) == (1, 3, 1)  # BER accepts it
    with pytest.raises(DerViolation):
        check_oid(content)
    with pytest.raises(DerViolation):
        decode(bytes.fromhex("0603") + content, der=True)


def test_nonminimal_first_pair_ber_tolerates_der_refuses() -> None:
    """A first pair spelled with a needless continuation octet: `80 01` is 1, i.e. 0.1."""
    assert decode_oid(bytes.fromhex("8001")) == (0, 1)
    with pytest.raises(DerViolation):
        check_oid(bytes.fromhex("8001"))


def test_oid_object_round_trips_through_the_real_decoder() -> None:
    """The corpus asks for round-trip through the TLV layer, not only through a helper."""
    for text, hex_content in CANONICAL:
        content = bytes.fromhex(hex_content)
        raw = bytes([0x06, len(content)]) + content
        node, end = decode(raw, der=True)
        assert end == len(raw), text
        assert encode_der(node) == raw, text
        assert node.payload == content, text


def test_snmpys_bytes_pass_the_real_decoder_unchanged() -> None:
    """What the raw-bytes invariant is for: `06 02 B4 03` is well-formed, and means 2.6579.

    A conforming DER path accepts it because there is nothing to refuse. What a caller gets is
    the exact octets that arrived, so the difference between "2.100.3 was intended" and "2.6579
    was sent" stays observable instead of being smoothed away by re-encoding.
    """
    raw = bytes.fromhex("0602b403")
    node, _ = decode(raw, der=True)
    assert node.raw == raw
    assert node.payload == bytes.fromhex("b403")
    assert decode_oid(bytes.fromhex("b403")) == (2, 6579)
    assert encode_der(node) == raw, "already canonical, so re-encoding is a no-op"


def test_unbounded_arc_accumulation_is_refused() -> None:
    """Twenty continuation octets with no terminator: a named error, not a giant integer."""
    with pytest.raises(DecodeError):
        decode_oid(bytes([0x81] * 20))
