"""Tag numbers: the identifier octets, and the boundary that snmpy gets wrong.

X.690 8.1.2 packs an identifier into one octet as ``class(2) | constructed(1) | number(5)``.
When the number reaches 31, those five bits mean "the real number follows in base-128", and
the continuation octets put their **payload in bits 0-6 with bit 7 as a continuation flag**.

Two consequences, both learned the hard way upstream:

* A tag number above 30 always has ``11111`` in the low five bits of the first octet, so
  bit 5 is the only place constructed-ness can live. Application *primitive* is ``5F`` and
  application *constructed* is ``7F``; they are not interchangeable, and snmpy's decoder
  cannot tell them apart because it never isolates bit 5 on that path.
* The accumulation is ``value = (value << 7) | payload``, evaluated **before** the next
  octet is read, with the final octet contributing once. snmpy shifts after the OR and then
  ORs the terminal octet a second time inside a ``while ... else`` whose ``else`` always
  runs, which turns 31 into 3999 and 128 into 508032. The tests in ``tests/`` pin those
  exact wrong values as regression witnesses.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from .errors import DecodeError, DerViolation, TruncatedError

__all__ = ["MAX_TAG_NUMBER", "Tag", "TagClass", "decode_tag", "encode_tag"]


class TagClass(IntEnum):
    """The two high bits of the first identifier octet."""

    universal = 0
    application = 1
    context = 2
    private = 3

    # snmpy calls the context class `context_specific`, and its 47 call sites use that
    # spelling. An alias costs nothing and makes the migration a rename rather than a
    # audit of every construction site.
    context_specific = 2


# X.690 places no ceiling on a tag number; this one exists so a hostile identifier cannot
# make the decoder allocate an arbitrary-precision integer forever. 2**32 is far above every
# tag number in use (RFC 5280 tops out at 31) and far below anything that could matter.
MAX_TAG_NUMBER = 2**32


@dataclass(frozen=True, slots=True)
class Tag:
    """A tag number, its class, and whether it is constructed."""

    number: int
    constructed: bool = False
    tag_class: TagClass = TagClass.universal

    def __post_init__(self) -> None:
        # Real checks, not asserts: `python -O` strips asserts, and CI runs the suite with
        # assertions off precisely to catch a parser that leaned on them.
        if not isinstance(self.number, int) or isinstance(self.number, bool):
            raise TypeError(f"tag number must be int, got {type(self.number).__name__}")
        if self.number < 0:
            raise ValueError(f"tag number must be non-negative, got {self.number}")
        if self.number > MAX_TAG_NUMBER:
            raise ValueError(f"tag number above the {MAX_TAG_NUMBER} ceiling: {self.number}")
        if not isinstance(self.constructed, bool):
            raise TypeError("constructed must be bool")

    def to_bytes(self) -> bytes:
        """Encode in DER form: the minimal identifier that names this tag."""
        return encode_tag(self)

    def is_universal(self) -> bool:
        return self.tag_class is TagClass.universal

    def is_context(self, number: int) -> bool:
        """True for the context-specific tag with this number - the shape `[0]` takes.

        Structure work needs this constantly: an X.509 version is `[0] EXPLICIT`, an issuer
        unique id is `[1]`, extensions are `[3]`. Comparing whole `Tag` values would also pin
        the constructed bit, which for an EXPLICIT tag is part of the grammar but for an IMPLICIT
        one is a modelling choice, so the class and number are the useful question.
        """
        return self.tag_class is TagClass.context and self.number == number


def encode_tag(tag: Tag) -> bytes:
    """DER identifier octets for ``tag``.

    Numbers 0-30 take one octet. 31 and above take the ``11111`` first octet plus base-128
    continuation octets, most significant group first, with no leading zero group - a
    continuation sequence beginning ``80`` encodes a value that had a shorter form, which DER
    forbids and BER tolerates.
    """
    lead = (int(tag.tag_class) << 6) | (0b0010_0000 if tag.constructed else 0)
    if tag.number < 0b0001_1111:
        return bytes([lead | tag.number])

    groups = [tag.number & 0x7F]
    rest = tag.number >> 7
    while rest:
        groups.append(0x80 | (rest & 0x7F))
        rest >>= 7
    groups.reverse()
    return bytes([lead | 0b0001_1111, *groups])


def decode_tag(buffer: bytes, offset: int = 0, *, der: bool = False) -> tuple[Tag, int]:
    """Read one identifier, returning it and the offset of the length octet.

    The accumulation is ``number = (number << 7) | payload``, evaluated before the next octet
    is read, and the terminal octet contributes exactly once. The reference implementation
    shifted after the OR and then OR-ed the last octet again inside a ``while ... else`` whose
    ``else`` always runs, producing 3999 for 31 and 508032 for 128.

    Args:
        buffer: the bytes to read from.
        offset: where the identifier starts.
        der: refuse a non-minimal high-tag-number form instead of tolerating it.

    Raises:
        TruncatedError: the buffer ends inside the identifier, including a continuation
            octet that is promised but not delivered (``9F`` alone, or ``9F 81``).
        DecodeError: the accumulated number exceeds ``MAX_TAG_NUMBER``.
        DerViolation: the continuation form encodes a number that had a shorter one,
            with ``der=True``.
    """
    if offset >= len(buffer):
        raise TruncatedError("buffer ends before the identifier", offset=offset)

    first = buffer[offset]
    tag_class = TagClass(first >> 6)
    constructed = bool(first & 0b0010_0000)
    low = first & 0b0001_1111
    position = offset + 1

    if low != 0b0001_1111:
        return Tag(int(low), constructed, tag_class), position

    number = 0
    while True:
        if position >= len(buffer):
            raise TruncatedError(
                "high-tag-number form promises a continuation octet and does not deliver one",
                offset=position,
            )
        octet = buffer[position]
        position += 1
        number = (number << 7) | int(octet & 0x7F)
        if number > MAX_TAG_NUMBER:
            raise DecodeError(
                f"tag number above the {MAX_TAG_NUMBER} ceiling",
                offset=offset,
            )
        if not octet & 0x80:
            break

    if number < 0b0001_1111 and der:
        raise DerViolation(
            f"tag number {number} is spelled with continuation octets it does not need",
            rule="tag-number-not-minimal",
            offset=offset,
        )
    return Tag(number, constructed, tag_class), position
