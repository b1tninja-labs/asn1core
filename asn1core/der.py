"""DER restrictions: the rules BER bends and DER does not.

Every function here answers one question - *is this content octet string the canonical
encoding of a value?* - and raises ``DerViolation`` naming the rule when it is not. They are
separate from the decoder because tolerance is a policy choice: the BER path must accept
``02 02 00 01`` as 1 and the DER path must refuse it, and if that decision lives inside the
parser it eventually gets made once, wrong, for both.

Two of these are load-bearing for certificate work in a way that surprises people:

* **Integer minimality cuts both ways.** ``02 02 00 01`` is non-minimal and DER refuses it.
  But an ECDSA ``r`` value with the high bit set *must* carry a leading zero, and a codec
  that "tidies" that byte away changes the signature and breaks verification at exactly the
  layer that is supposed to be trustworthy. The rule is minimal two's complement, not "strip
  leading zeros", and `int_minus128` plus the ECDSA fixture in VECTORS.md keep that honest.
* **SET OF ordering.** DER requires SET OF components sorted by their encodings, and X.509
  compares relative distinguished names byte-wise during path validation. A decoder that
  normalises order silently makes two different names compare equal.
"""

from __future__ import annotations

from .errors import DerViolation
from .node import Node

__all__ = [
    "PRINTABLE_ALPHABET",
    "check_bit_string",
    "check_boolean",
    "check_integer",
    "check_printable_string",
    "check_set_of",
    "validate_der",
]


def validate_der(buffer: bytes) -> Node:
    """Parse and assert that ``buffer`` is canonical DER, returning the tree.

    Equivalent to ``decode(buffer, der=True)[0]`` and offered separately because "is this
    already canonical?" is the question a store asks before it hashes a document for a key.
    A document that fails here must never be re-encoded into a form that passes: that
    normalisation is how one certificate ends up with two identities.
    """
    from .node import decode

    node, end = decode(buffer, der=True)
    if end != len(buffer):
        raise DerViolation(
            f"{len(buffer) - end} octets remain after the first object",
            rule="trailing-octets",
            offset=end,
        )
    return node


def check_integer(content: bytes, *, offset: int | None = None) -> int:
    """Return the value, having asserted the content is minimal two's complement.

    Rejects an empty content octet string, a redundant leading ``00`` where the next octet's
    high bit is clear, and a redundant ``FF`` where the next octet's high bit is set. Accepts
    ``80`` as -128: it is minimal, and there is no negative zero in two's complement.

    The asymmetry is deliberate and it is the reason this is not ``content.lstrip(b"\\x00")``.
    An ECDSA ``r`` whose high bit is set carries a leading ``00`` that is load-bearing, and
    tidying it away produces a different signature from the same key - a failure that surfaces
    at the verification layer, far from the code that caused it.
    """
    if not content:
        raise DerViolation("INTEGER content is empty", rule="integer-empty", offset=offset)
    if len(content) > 1:
        first, second = content[0], content[1]
        if first == 0x00 and not second & 0x80:
            raise DerViolation(
                "INTEGER carries a redundant leading 00 octet",
                rule="integer-not-minimal",
                offset=offset,
            )
        if first == 0xFF and second & 0x80:
            raise DerViolation(
                "INTEGER carries a redundant leading FF octet",
                rule="integer-not-minimal",
                offset=offset,
            )
    return int.from_bytes(content, "big", signed=True)


def check_boolean(content: bytes, *, offset: int | None = None) -> bool:
    """Reject anything other than a single octet of ``00`` or ``FF``.

    BER permits any non-zero as true, which is how ``01 01 02`` becomes true here and false
    somewhere else.
    """
    if len(content) != 1 or content[0] not in (0x00, 0xFF):
        raise DerViolation(
            "BOOLEAN content must be a single 00 or FF octet",
            rule="boolean-not-canonical",
            offset=offset,
        )
    return bool(content[0])


def check_bit_string(content: bytes, *, offset: int | None = None) -> tuple[int, bytes]:
    """Return (unused_bits, data), rejecting a count above 7, non-zero unused bits, and
    empty content - a BIT STRING carries at least the unused-bits octet."""
    if not content:
        raise DerViolation(
            "BIT STRING carries no unused-bits octet", rule="bit-string-empty", offset=offset
        )
    unused = content[0]
    if unused > 7:
        raise DerViolation(
            f"BIT STRING unused-bits count {unused} exceeds 7",
            rule="bit-string-unused-count",
            offset=offset,
        )
    data = content[1:]
    if unused and data and data[-1] & ((1 << unused) - 1):
        raise DerViolation(
            "BIT STRING trailing bits that DER requires to be zero",
            rule="bit-string-unused-nonzero",
            offset=offset,
        )
    if unused and not data:
        raise DerViolation(
            "BIT STRING declares unused bits but carries no data",
            rule="bit-string-unused-count",
            offset=offset,
        )
    return unused, data


def check_set_of(node: Node) -> None:
    """Assert DER ordering of SET OF components by their encoded bytes.

    X.509 compares relative distinguished names byte-wise during path validation, so a
    decoder that normalises order silently makes two different names compare equal.
    """
    encodings = [child.raw for child in node.children]
    if encodings != sorted(encodings):
        raise DerViolation(
            "SET OF components are not in DER order",
            rule="set-of-unsorted",
            offset=None,
        )


# Rec. ITU-T X.680 (02/2021) §41.4 Table 10: the characters PrintableString may contain. Transcribed as data
# rather than paraphrased as prose, so that a reviewer can compare it against the table one character at a
# time, and pinned by cardinality in test_printable_string_permitted_alphabet_is_exactly_table_10: latin
# capital letters (26), latin small letters (26), digits (10), SPACE, and eleven specials - APOSTROPHE '
# LEFT PARENTHESIS ( RIGHT PARENTHESIS ) PLUS SIGN + COMMA , HYPHEN-MINUS - FULL STOP . SOLIDUS / COLON :
# EQUALS SIGN = QUESTION MARK ? - which is 74 characters in total.
PRINTABLE_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?"
)


def check_printable_string(content: bytes, *, offset: int | None = None) -> bytes:
    """Return the content, having asserted that every character is one Table 10 permits.

    This check differs in kind from the others in this module, and the difference is the reason the row in
    ``VECTORS.md`` stayed open for so long. A non-minimal INTEGER is *legal BER with a forbidden spelling*:
    the value exists, another implementation reads it the same way, and only DER refuses. A PrintableString
    carrying a character outside its alphabet is not an unusual spelling of a value, it is **no value of that
    type at all** (X.680 §41.4 defines the type by its permitted characters). So the tolerant path keeps the
    octets and reports nothing, while the strict path refuses.

    Enforcing it on the DER path is only safe because it was measured first: 520 of 520 PrintableString
    attribute values across 75 certificates shipped by an operating system fall inside Table 10
    (2026-11-07, the same store ``tools/crosscheck_store.py`` reads). The values that would have tripped it —
    Entrust's ``www.entrust.net/CPS_2048 incorp. by ref. (limits liab.)``, with its underscore — arrive under
    tag 20, TeletexString, which is what made the tag numbering in ``name.py`` part of the same question.
    """
    text = content.decode("latin-1")
    bad = sorted({character for character in text if character not in PRINTABLE_ALPHABET})
    if bad:
        spelled = " ".join(f"{ord(character):02X}" for character in bad)
        raise DerViolation(
            f"PrintableString carries {len(bad)} character(s) outside X.680 Table 10: {spelled}",
            rule="printable-charset",
            offset=offset,
        )
    return content
