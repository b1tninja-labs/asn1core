"""Structure, round-trip and DER value rows from VECTORS.md.

The corpus is not only byte-level edge cases: the properties below are the ones that a defect
like "discards the original TLV bytes" survives untouched, because every individual object can
still decode correctly while the document as a whole is wrong. They are also the rows that
catch the bug I introduced and then fixed in this same package - the constructed branch of the
decoder returning before the value-level DER checks, which left SET OF ordering unenforced.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from asn1core import (
    DecodeError,
    DepthExceeded,
    DerViolation,
    check_bit_string,
    check_boolean,
    check_integer,
    check_set_of,
    decode,
    encode_der,
    encode_length,
    validate_der,
)

SEQUENCE = bytes.fromhex("300a020105040568656c6c6f")  # { INTEGER 5, OCTET STRING "hello" }


def test_canonical_document_round_trips_byte_for_byte() -> None:
    """rt-idempotent: decode then DER-encode must reproduce the input exactly."""
    node, end = decode(SEQUENCE)
    assert end == len(SEQUENCE)
    assert encode_der(node) == SEQUENCE
    assert node.raw == SEQUENCE
    assert validate_der(SEQUENCE).raw == SEQUENCE


def test_repeated_children_stay_distinct_nodes() -> None:
    """repeated-child: aliasing here silently produces wrong certificates."""
    raw = bytes.fromhex("3006020101020101")  # SEQUENCE { INTEGER 1, INTEGER 1 }
    node, _ = decode(raw)
    assert len(node.children) == 2
    first, second = node.children
    assert first.raw == second.raw
    assert first is not second, "identical children must not be the same object"
    assert encode_der(node) == raw


def test_unknown_tags_survive_decode_and_encode() -> None:
    """unknown-tag-preserved: extensions are the reason this library exists."""
    for raw in (
        bytes.fromhex("a503020105"),  # context 5, constructed, holding an INTEGER
        bytes.fromhex("c101ff"),  # private 1, primitive (E1 would be *constructed*: bit 5)
        bytes.fromhex("bf850203020105"),  # context 5 via high-tag-number form, definite length
    ):
        node, end = decode(raw)
        assert end == len(raw), raw.hex()
        assert encode_der(node) == raw, f"{raw.hex()} was not preserved verbatim"
        assert node.raw == raw


def test_depth_is_bounded_by_a_named_error() -> None:
    """depth-bound: a nested document must not become a stack overflow.

    The corpus row says 10,000 levels; the package stops at 64, and that is the point - a
    limit the parser enforces beats the interpreter's, because RecursionError surfacing from
    inside a library is not something a caller can tell apart from its own bug.
    """
    # Lengths must be encoded properly at every level: writing bytes([0x30, len(raw)]) turns
    # the 64th wrap into 0x80, which is *indefinite length*, and the test would then be
    # checking a completely different failure.
    raw = bytes.fromhex("3000")
    for _ in range(200):
        raw = bytes([0x30]) + encode_length(len(raw)) + raw
    with pytest.raises(DepthExceeded):
        decode(raw)

    shallow = bytes.fromhex("3000")
    for _ in range(10):
        shallow = bytes([0x30]) + encode_length(len(shallow)) + shallow
    node, end = decode(shallow)
    assert end == len(shallow)
    assert node.constructed


def test_a_two_hundred_byte_string_encodes_and_reparses() -> None:
    """End to end across the length boundary that crashed the reference encoder at 256."""
    for size in (127, 128, 255, 256, 300):
        raw = bytes([0x04]) + encode_length(size) + b"Z" * size
        node, end = decode(raw)
        assert end == len(raw), size
        assert len(node.content()) == size, size
        assert encode_der(node) == raw, size


def test_boolean_content_rules() -> None:
    """bool-nonzero: BER calls 01 01 02 true; DER refuses, because "elsewhere" means elsewhere."""
    node, _ = decode(bytes.fromhex("010102"))
    assert node.payload == bytes.fromhex("02")
    with pytest.raises(DerViolation):
        decode(bytes.fromhex("010102"), der=True)
    with pytest.raises(DerViolation):
        check_boolean(bytes.fromhex("02"))
    with pytest.raises(DerViolation):
        check_boolean(bytes.fromhex("00ff"))  # two content octets, whatever their values
    assert check_boolean(bytes.fromhex("ff")) is True
    assert check_boolean(bytes.fromhex("00")) is False


def test_bit_string_content_rules() -> None:
    """bits-empty and bits-unused-nonzero rows."""
    assert check_bit_string(bytes.fromhex("034040")) == (3, bytes.fromhex("4040"))
    with pytest.raises(DerViolation):
        check_bit_string(b"")
    with pytest.raises(DerViolation):
        check_bit_string(bytes.fromhex("0841"))  # unused count above 7
    with pytest.raises(DerViolation):
        check_bit_string(bytes.fromhex("034141"))  # 0x41 has a low bit set, 3 are unused

    node, _ = decode(bytes.fromhex("0303034141"))  # BER tolerates all of it
    assert node.content() == bytes.fromhex("034141")
    with pytest.raises(DerViolation):
        decode(bytes.fromhex("0303034141"), der=True)


def test_set_of_ordering_is_enforced_on_the_der_path() -> None:
    """setof-unsorted: X.509 compares RDN sets byte-wise, so order is not cosmetic.

    This is the row that fails if the constructed branch of the decoder returns before the
    value-level checks - the mistake the first draft of node.py made.
    """
    sorted_raw = bytes.fromhex("3106020101020102")
    unsorted_raw = bytes.fromhex("3106020102020101")

    node, _ = decode(unsorted_raw)
    assert len(node.children) == 2
    assert encode_der(node) == unsorted_raw, "the BER path preserves order, it does not sort"
    with pytest.raises(DerViolation):
        decode(unsorted_raw, der=True)
    with pytest.raises(DerViolation):
        check_set_of(node)
    assert validate_der(sorted_raw).raw == sorted_raw


def test_validate_der_rejects_trailing_octets_and_noncanonical_input() -> None:
    """One document per buffer: leftovers are a framing error, not extra data."""
    with pytest.raises(DerViolation):
        validate_der(SEQUENCE + b"\x00")
    with pytest.raises(DerViolation):
        validate_der(bytes.fromhex("02810100"))  # legal BER, so never a key for a store


def test_library_contains_no_assert_statements() -> None:
    """no-asserts-on-wire, enforced against the source rather than trusted to review.

    CI runs the suite under ``python -O``, which strips asserts from every module **except**
    the test modules pytest rewrites - so a bounds check written as an assert passes the whole
    suite in debug mode and protects nothing in production. That is the exact class of bug this
    package exists to stop repeating, and it is why this check parses the modules rather than
    sampling behaviour or trusting review.

    The first draft scanned lines with a regex, which flagged the word "assert" wherever it
    appeared in a docstring - a false positive on the very function whose job is to assert
    canonicality. Parsing the AST is both cheaper and correct.
    """
    package = pathlib.Path(__file__).resolve().parents[1] / "asn1core"
    offenders: list[str] = []
    for path in sorted(package.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        offenders += [
            f"{path.name}:{node.lineno}" for node in ast.walk(tree) if isinstance(node, ast.Assert)
        ]
    assert not offenders, f"library asserts are stripped by python -O: {offenders}"


def test_error_hierarchy_separates_policy_from_parse_failure() -> None:
    """A DER refusal is not a parse failure, and callers log them differently.

    Both surface as "this input was bad", but only one means the input was unintelligible.
    Collapsing them is how a store ends up treating a non-canonical certificate as a corrupt
    one, and how an anomaly feed loses the distinction between a liar and a broken line.
    """
    assert issubclass(DepthExceeded, DecodeError)
    assert issubclass(DerViolation, Exception)
    assert not issubclass(DerViolation, DecodeError)
    with pytest.raises(DerViolation) as der_case:
        check_integer(bytes.fromhex("0001"))
    assert der_case.value.rule == "integer-not-minimal"
    with pytest.raises(DecodeError) as parse_case:
        decode(bytes.fromhex("30040102"))
    assert parse_case.value.offset is not None
