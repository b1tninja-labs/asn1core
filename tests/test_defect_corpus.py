"""The corpus rows that name the seven measured defects.

Every id here is a row in ``VECTORS.md``, and every expected value comes from the encoding
rule quoted there - never from what this package happens to do. That distinction is the whole
method: ``ObjectTag.decode`` in snmpy shipped with no coverage on the one function everything
else depended on, because its expectations would have been derived from itself.

Where snmpy produced a specific wrong answer, that answer is asserted **not** to appear. A
test that only checks the new value is correct would still pass if someone reintroduced the
bug in a form that happens to be right at the neighbouring boundary.

Run status is expected to be red until the corresponding obligation in PLAN.md is done.
"""

from __future__ import annotations

import pytest

from asn1core import (
    INDEFINITE,
    DecodeError,
    DerViolation,
    Node,
    Tag,
    TagClass,
    check_integer,
    decode,
    decode_length,
    decode_tag,
    encode_der,
    encode_length,
    encode_tag,
)

# ---------------------------------------------------------------------------
# Defect 1: high-tag-number decoding. These are snmpy's exact wrong answers.
# ---------------------------------------------------------------------------

SNMPY_WRONG_TAG_NUMBERS = {
    31: 3999,
    63: 4031,
    127: 4095,
    128: 508032,
    16383: 524287,
    16384: 65028096,
}


@pytest.mark.parametrize(
    ("case_id", "hex_string", "number"),
    [
        ("tag-c-31", "9f1f", 31),
        ("tag-c-63", "9f3f", 63),
        ("tag-c-127", "9f7f", 127),
        ("tag-c-128", "9f8100", 128),
        ("tag-c-16383", "9fff7f", 16383),
        ("tag-c-16384", "9f818000", 16384),
    ],
    ids=["tag-c-31", "tag-c-63", "tag-c-127", "tag-c-128", "tag-c-16383", "tag-c-16384"],
)
def test_high_tag_number_decodes_and_round_trips(
    case_id: str, hex_string: str, number: int
) -> None:
    raw = bytes.fromhex(hex_string)
    tag, offset = decode_tag(raw)
    assert tag == Tag(number, constructed=False, tag_class=TagClass.context), case_id
    assert offset == len(raw), case_id
    # The wrong answer, asserted absent: 9f1f must not become 3999.
    assert tag.number != SNMPY_WRONG_TAG_NUMBERS[number], case_id
    # And the encoder agrees with the decoder, which is where snmpy diverges.
    assert encode_tag(tag) == raw, case_id


def test_tag_c_30_is_the_last_single_octet_number() -> None:
    """0x9E: class 10, constructed 0, number 11110 = 30, the ceiling of one octet."""
    tag, offset = decode_tag(bytes.fromhex("9e"))
    assert (tag.number, tag.constructed, tag.tag_class, offset) == (30, False, TagClass.context, 1)
    assert encode_tag(Tag(30, False, TagClass.context)) == bytes.fromhex("9e")


def test_tag_class_and_constructed_bits_are_isolated_not_or_ed() -> None:
    """tag-a-9999 row: 5F is application *primitive*, 7F is application *constructed*.

    A high tag number needs 11111 in the low five bits, so bit 5 is the only place
    constructed-ness can live. A decoder that ORs class bits with number bits gets this
    exactly wrong, and the two spellings must not be confused.
    """
    primitive, _ = decode_tag(bytes.fromhex("5fce0f"))
    constructed, _ = decode_tag(bytes.fromhex("7fce0f"))
    assert primitive.number == constructed.number == 9999
    assert primitive.constructed is False
    assert constructed.constructed is True
    assert primitive.tag_class is TagClass.application
    assert constructed.tag_class is TagClass.application


def test_tag_p_1_is_private_not_context() -> None:
    """0xC1 is class bits 11 (private); writing 0x81 here would silently change its class."""
    tag, _ = decode_tag(bytes.fromhex("c1"))
    assert (tag.number, tag.tag_class, tag.constructed) == (1, TagClass.private, False)


def test_tag_nonminimal_is_accepted_by_ber_and_refused_by_der() -> None:
    """tag-nonminimal: 9F 80 01 is a base-128 number carrying a leading zero group."""
    tag, _ = decode_tag(bytes.fromhex("9f8001"))
    assert tag == Tag(1, constructed=False, tag_class=TagClass.context)
    with pytest.raises(DerViolation):
        decode_tag(bytes.fromhex("9f8001"), der=True)


# ---------------------------------------------------------------------------
# Defect 2: length encoding computed with float arithmetic. Crashes at every 256**k.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("case_id", "length", "expected_hex"),
    [
        ("len-short-max", 127, "7f"),
        ("len-long-128", 128, "8180"),
        ("len-long-255", 255, "81ff"),
        ("len-long-256", 256, "820100"),
        ("len-long-65535", 65535, "82ffff"),
        ("len-long-65536", 65536, "83010000"),
        ("len-long-16777216", 16777216, "8401000000"),
    ],
    ids=[
        "len-short-max",
        "len-long-128",
        "len-long-255",
        "len-long-256",
        "len-long-65535",
        "len-long-65536",
        "len-long-16777216",
    ],
)
def test_length_encode_is_exact_at_every_power_of_256(
    case_id: str, length: int, expected_hex: str
) -> None:
    """The reference encoder used ceil(log2(n)/8) and raised OverflowError at 256, 65536 ...

    Those rows are the point of this test; the others pin the boundaries either side of them.
    """
    encoded = encode_length(length)
    assert encoded == bytes.fromhex(expected_hex), case_id
    decoded, offset = decode_length(encoded)
    assert (decoded, offset) == (length, len(encoded)), case_id


# ---------------------------------------------------------------------------
# Defects 3 and 4: truncation and framing. Named errors, never IndexError, and
# never a successful parse that walks the caller off the end of the buffer.
# ---------------------------------------------------------------------------

TRUNCATION_CASES = [
    ("trunc-header-1", "30", "buffer ends after the identifier"),
    ("trunc-length", "308201", "long-form length promises 2 octets, supplies 1"),
    ("trunc-body", "30040102", "declares 4 content bytes, supplies 2"),
    ("trunc-tag", "9f", "high-tag-number form with nothing following"),
    ("trunc-tag-cont", "9f81", "continuation promised and not delivered"),
    ("trunc-eoc", "3080020100", "indefinite length never closed"),
    ("trunc-nested", "3006040441", "inner length overruns its parent"),
]


@pytest.mark.parametrize(
    ("case_id", "hex_string", "why"),
    TRUNCATION_CASES,
    ids=[case[0] for case in TRUNCATION_CASES],
)
def test_truncated_input_raises_a_named_error(case_id: str, hex_string: str, why: str) -> None:
    raw = bytes.fromhex(hex_string)
    # DecodeError excludes IndexError, struct.error and UnicodeDecodeError by construction:
    # none of them is a subclass, so if one escapes, this fails rather than passing quietly.
    with pytest.raises(DecodeError):
        decode(raw)


def test_truncation_never_returns_an_offset_past_the_buffer() -> None:
    """The reference decoder answered 6 for a 4-byte input and 8 for a 5-byte one."""
    for hex_string in ("30040102", "3006040441", "3080020100"):
        raw = bytes.fromhex(hex_string)
        with pytest.raises(DecodeError):
            decode(raw)


def test_zero_length_child_is_valid_and_distinguishable_from_absent() -> None:
    """trunc-zero-len-child: 30 02 30 00 parses. Length 0 is empty, not missing."""
    raw = bytes.fromhex("30023000")
    node, offset = decode(raw)
    assert offset == len(raw)
    assert node.constructed
    assert len(node.children) == 1
    child = node.children[0]
    assert child.tag.number == 16
    assert child.raw == bytes.fromhex("3000")
    assert child.content() == b""
    assert node.raw == raw


# ---------------------------------------------------------------------------
# Defect 5: reserved length forms, absurd lengths, and the EOC searched in content.
# ---------------------------------------------------------------------------


def test_reserved_length_form_is_refused() -> None:
    """len-undefined-high: 04 8F 01. A low nibble of 15 is reserved by X.690.

    The reference decoder read this as "15 length octets follow", consumed the one byte
    available, and reported a length of 1 without complaint.
    """
    with pytest.raises(DecodeError):
        decode(bytes.fromhex("048f01"))


def test_length_overflow_is_a_named_error_not_an_allocation() -> None:
    """len-overflow: 04 88 then eight FF octets, a request for 1.8e19 bytes."""
    raw = bytes.fromhex("0488" + "ff" * 8)
    with pytest.raises(DecodeError) as excinfo:
        decode(raw)
    assert not isinstance(excinfo.value, MemoryError)
    assert excinfo.value.offset is not None


def test_nonminimal_length_accepted_by_ber_refused_by_der() -> None:
    """len-nonminimal and len-leading-zero: two encodings of 127, one of them illegal DER."""
    for hex_body in ("817f", "82007f"):
        raw = bytes.fromhex(f"04{hex_body}") + b"A" * 127
        node, _ = decode(raw)
        assert node.content() == b"A" * 127
        assert node.raw == raw
        with pytest.raises(DerViolation):
            decode(raw, der=True)


def test_indefinite_length_is_ber_only_and_terminated_by_parsing() -> None:
    """len-indefinite and seq-indefinite rows."""
    inner = bytes.fromhex("020100")
    raw = bytes.fromhex("3080") + inner + bytes.fromhex("0000")
    node, offset = decode(raw)
    assert offset == len(raw)
    assert [child.raw for child in node.children] == [inner]
    with pytest.raises(DerViolation):
        decode(raw, der=True)


def test_indefinite_terminator_is_not_searched_for_inside_content() -> None:
    """The failure mode itself: buffer.index(b"\\0\\0") stops at the data, not at the EOC.

    A constructed indefinite object holding an OCTET STRING that begins with two NULs:

        30 80 | 04 03 00 00 41 | 00 00

    The terminator is the final pair, so the child's content is 00 00 41. A decoder that
    scans for a zero pair finds one three octets early, reports a two-byte content, and
    desynchronises everything after it. Two consecutive NULs are ordinary data - zero-padded
    integers, zero OID arcs, addresses - so this is not a pathological input.

    Note on the corpus row this replaces: VECTORS.md originally used 04 80 41 00 00 42 00 00,
    a *primitive* indefinite length, and dropped it as unresolvable. The drop was right; the stated
    cause was not. X.690 (02/2021) §8.1.3.2 a) requires a sender to use the definite form if the
    encoding is primitive (read 2026-11-07 via itulib), and §7.1 dynamic conformance gives a
    receiver no licence to accept what no conforming sender may emit - so the expected octets were
    never ambiguous, the input was illegal, and `node._parse` refuses it under a named error. What
    this test asserts is a different claim: that the terminator is found only at an object boundary,
    which the constructed form carries.
    """
    raw = bytes.fromhex("30800403" + "000041" + "0000")
    node, offset = decode(raw)
    assert offset == len(raw), f"parse stopped at {offset}, buffer is {len(raw)}"
    assert len(node.children) == 1
    child = node.children[0]
    assert child.content() == bytes.fromhex("000041"), f"got {child.content()!r}"
    with pytest.raises(DerViolation):
        decode(raw, der=True)


# ---------------------------------------------------------------------------
# Defect 6: the original bytes. Defect 7 territory: integer minimality, which
# cuts both ways and must not be "tidied".
# ---------------------------------------------------------------------------


def test_original_bytes_survive_a_noncanonical_parse() -> None:
    """rt-original-retained - invariant I3 of the certledger trust model.

    02 81 01 00 is INTEGER 0 written with a long-form length: legal BER, four octets. The
    reference codec decodes it, re-encodes as 02 01 00, and the original is gone - which does
    not merely lose a convenience. RFC 5280 4.1.3.2 requires the CA signature to be verified
    over the DER encoding of the TBSCertificate, and there is nothing to verify over once the
    octets have been rebuilt.
    """
    raw = bytes.fromhex("02810100")
    node, _ = decode(raw)
    assert node.raw == raw, "the original TLV octets must be retained verbatim"
    assert encode_der(node) == bytes.fromhex("020100")
    assert encode_der(node) != node.raw, "canonicalisation must be visible, never silent"
    assert isinstance(node, Node)


@pytest.mark.parametrize(
    ("case_id", "content", "value"),
    [
        ("int-minus128", "80", -128),
        ("int-minus129", "ff7f", -129),
        ("int-boundary-128", "0080", 128),
        ("int-zero", "00", 0),
    ],
    ids=["int-minus128", "int-minus129", "int-boundary-128", "int-zero"],
)
def test_minimal_integers_are_accepted(case_id: str, content: str, value: int) -> None:
    """int-minus128 row: the single octet 80 is -128, it is minimal, and there is no
    negative zero in two's complement to be confused about."""
    assert check_integer(bytes.fromhex(content)) == value, case_id


def test_nonminimal_integer_is_refused_without_being_normalised() -> None:
    """int-nonmin: 02 02 00 01 is 1, but DER refuses it rather than tidying it away."""
    raw = bytes.fromhex("02020001")
    node, _ = decode(raw)
    assert node.content() == bytes.fromhex("0001")
    with pytest.raises(DerViolation):
        check_integer(bytes.fromhex("0001"))
    with pytest.raises(DerViolation):
        decode(raw, der=True)


def test_redundant_ff_padding_is_refused() -> None:
    """int-minus128-nonmin: FF 80 is -128 with a padding octet that FF80 does not need."""
    assert check_integer(bytes.fromhex("80")) == -128
    with pytest.raises(DerViolation):
        check_integer(bytes.fromhex("ff80"))


def test_indefinite_sentinel_is_distinct_from_a_real_length() -> None:
    """None, 0 and INDEFINITE are three different answers and have to stay three of them."""
    length, _ = decode_length(bytes.fromhex("80"))
    assert length == INDEFINITE
    zero, _ = decode_length(bytes.fromhex("00"))
    assert zero == 0
    assert INDEFINITE != 0


def test_bounds_checks_survive_stripped_asserts() -> None:
    """no-asserts-on-wire: CI runs under python -O, which removes every assert statement.

    Nothing below is reachable through an assert in the implementation, so the corpus rows
    must still raise here. This test exists because a parser can pass the whole suite in
    debug mode and be unguarded in production.
    """
    if not __debug__:  # pragma: no cover - exercised by `python -O -m pytest`
        with pytest.raises(DecodeError):
            decode(bytes.fromhex("30040102"))
    # Either way, the error hierarchy itself must not depend on assertion rewriting.
    assert issubclass(DerViolation, Exception)
    assert not issubclass(DerViolation, DecodeError), "a policy refusal is not a parse failure"
