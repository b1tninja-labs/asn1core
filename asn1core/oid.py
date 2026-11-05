"""Object identifiers: X.690 8.19, and the two ways it is easy to get wrong.

An OID's content octets begin with **the first two arcs folded into one number**, `40a + b`,
and only after that come ordinary base-128 subidentifiers. Both halves have traps.

**The first pair.** Values 0-39 are `0.b`, 40-79 are `1.(b-40)` and **80-127 are `2.(b-80)`**;
at 128 the pair switches to the base-128 form. The 80-127 range is the trap. It looks like a
violated "first arc is at most 2" rule and is not: it *is* arc 2, with a second component of
40 to 47. This repository had a corpus row demanding `06 02 7F 01` be refused on exactly that
misreading, and implementing it would have rejected every `2.5.29.x` extension and `2.5.4.x`
attribute in X.509 - the evidence being 61 real certificates that encode `2.5.29.19` as
`06 03 55 1D 13`, where `0x55 = 85 = 40*2 + 5`. See `PLAN.md`.

**Subidentifiers.** Base-128 with bit 8 as the continuation flag, most significant group first,
minimal form required by DER. A first octet with bit 8 set *promises* another octet: snmpy's own
test suite encodes `2.100.3` as `B4 03`, and because `0xB4` promises a continuation that never
comes as a separate arc, a conforming decoder reads `2.6579` instead. Encoder and decoder in
that library agree with each other and disagree with everyone else, which is how its test
passes.

Nothing here uses `assert`. Validation of this type is precisely where an `assert` becomes a
silent rewrite of an identifier under `python -O`, and defect 7 in `PLAN.md` is that story.
"""

from __future__ import annotations

from .errors import DecodeError, DerViolation, TruncatedError

__all__ = [
    "MAX_ARC_VALUE",
    "MAX_OID_ARCS",
    "check_oid",
    "decode_oid",
    "encode_oid",
    "parse_oid_string",
]

# An arc that needs more than 2**32 is not an identifier anyone intended; capping the
# accumulator is what stops a buffer of continuation octets becoming an arbitrary-precision
# multiplication exercise. Same reasoning as tag.MAX_TAG_NUMBER.
MAX_ARC_VALUE = 2**32

# Certificates carry OIDs of a few arcs; 64 is generous and keeps a hostile buffer bounded.
MAX_OID_ARCS = 64


def parse_oid_string(text: str) -> tuple[int, ...]:
    """Turn a dotted OID into arcs, refusing what cannot be encoded.

    Raises:
        ValueError: empty input, a non-numeric or negative component, fewer than two arcs, a
            first arc above 2, or a second arc above 39 when the first is 0 or 1.

    The refusals are the point. snmpy validates with `assert`, so under `python -O` "3.0"
    survives validation and the `min(2, value // 40)` fallback hands back `2.40` - a legal
    identifier that means something else.
    """
    if not isinstance(text, str):
        raise TypeError(f"OID must be a dotted string, got {type(text).__name__}")
    if not text or text.startswith(".") or text.endswith(".") or ".." in text:
        raise ValueError(f"OID {text!r} is not a dot-separated list of non-negative integers")

    arcs: list[int] = []
    for part in text.split("."):
        if not part.isdigit():
            raise ValueError(f"OID {text!r} has a non-numeric component {part!r}")
        arcs.append(int(part))

    if len(arcs) < 2:
        raise ValueError(f"OID {text!r} needs at least two arcs, has {len(arcs)}")
    if len(arcs) > MAX_OID_ARCS:
        raise ValueError(f"OID {text!r} exceeds the limit of {MAX_OID_ARCS} arcs")
    _validate_first_pair(arcs[0], arcs[1], context=text)
    for arc in arcs[2:]:
        if arc > MAX_ARC_VALUE:
            raise ValueError(f"OID {text!r} has an arc above the ceiling {MAX_ARC_VALUE}")
    return tuple(arcs)


def _validate_first_pair(first: int, second: int, *, context: object) -> None:
    """A first arc of 0 or 1 caps the second at 39; only arc 2 may exceed it.

    Written as raises, never as asserts. This is the exact check `python -O` removes from snmpy,
    and what replaces it there is not a crash but a plausible identifier with different meaning.
    """
    if first > 2:
        raise ValueError(f"OID {context!r}: first arc must be 0, 1 or 2, got {first}")
    if first < 2 and second > 39:
        raise ValueError(
            f"OID {context!r}: second arc must be at most 39 when the first is {first}, got {second}"
        )


def _base128(value: int) -> bytes:
    """Minimal base-128: most significant group first, bit 8 set on all but the last."""
    groups = [value & 0x7F]
    rest = value >> 7
    while rest:
        groups.append(0x80 | (rest & 0x7F))
        rest >>= 7
    groups.reverse()
    return bytes(groups)


def encode_oid(arcs: tuple[int, ...] | list[int]) -> bytes:
    """Encode arcs as OID content octets, always in the minimal form DER requires.

    There is deliberately no flag for the non-minimal spellings that BER tolerates on input.
    An encoder has no reason to emit them: it would write documents its own decoder reports as
    canonical while every other implementation reads different identifiers out of them.
    """
    sequence = tuple(arcs)
    if len(sequence) < 2:
        raise ValueError(f"an OID needs at least two arcs, got {len(sequence)}")
    for arc in sequence:
        if not isinstance(arc, int) or isinstance(arc, bool):
            raise TypeError(f"OID arcs must be int, got {type(arc).__name__}")
        if arc < 0:
            raise ValueError(f"OID arcs must be non-negative, got {arc}")
        if arc > MAX_ARC_VALUE:
            raise ValueError(f"OID arc above the ceiling {MAX_ARC_VALUE}: {arc}")
    _validate_first_pair(sequence[0], sequence[1], context=sequence)

    pair = 40 * sequence[0] + sequence[1]
    out = bytearray(pair.to_bytes(1, "big") if pair < 0x80 else _base128(pair))
    for arc in sequence[2:]:
        out += _base128(arc)
    return bytes(out)


def decode_oid(content: bytes, *, offset: int | None = None) -> tuple[int, ...]:
    """Decode OID content octets as BER: tolerant of non-minimal forms, strict about framing.

    The first two arcs are folded into one value, so they are read by the same base-128 loop as
    every later arc and then split at 40 and 80. **80-127 is arc 2**, not a violation - reading
    it as one is the mistake `PLAN.md` records as retracted, and acting on it would reject every
    `2.5.x` OID in X.509.

    Raises:
        TruncatedError: a continuation bit with no octet after it.
        DecodeError: empty content, too many arcs, or a value above ``MAX_ARC_VALUE``.
    """
    if not content:
        raise DecodeError("OID content is empty", offset=offset)

    arcs: list[int] = []
    position = 0

    def _next_value(where: str) -> int:
        nonlocal position
        value = 0
        while True:
            if position >= len(content):
                raise TruncatedError(
                    f"OID {where} promises a continuation octet and does not deliver one",
                    offset=None if offset is None else offset + position,
                )
            octet = int(content[position])
            position += 1
            value = (value << 7) | int(octet & 0x7F)
            if value > MAX_ARC_VALUE:
                raise DecodeError(
                    f"OID {where} exceeds the arc ceiling {MAX_ARC_VALUE}",
                    offset=None if offset is None else offset + position,
                )
            if not octet & 0x80:
                return value

    pair = _next_value("first pair")
    if pair < 40:
        arcs += [0, pair]
    elif pair < 80:
        arcs += [1, pair - 40]
    else:
        arcs += [2, pair - 80]

    while position < len(content):
        arcs.append(_next_value("subidentifier"))
        if len(arcs) > MAX_OID_ARCS:
            raise DecodeError(f"OID exceeds the limit of {MAX_OID_ARCS} arcs", offset=offset)
    return tuple(arcs)


def check_oid(content: bytes, *, offset: int | None = None) -> tuple[int, ...]:
    """Decode and assert canonicality by requiring the bytes to be the ones we would write.

    Re-encoding and comparing octets catches every non-minimal spelling at once - a first pair
    in continuation form while still under 128, a subidentifier with a leading zero group, and
    anything of the same kind. It deliberately does not catch *semantic* disagreement: snmpy's
    `B4 03` is valid DER for 2.6579, and refusing it here would be inventing a rule. That defect
    belongs to snmpy's encoder, and `PLAN.md` says so instead of smuggling it in here.
    """
    arcs = decode_oid(content, offset=offset)
    canonical = encode_oid(arcs)
    if content != canonical:
        raise DerViolation(
            f"OID is not canonical: {content.hex()} would be written as {canonical.hex()}",
            rule="oid-arc-nonminimal",
            offset=offset,
        )
    return arcs
