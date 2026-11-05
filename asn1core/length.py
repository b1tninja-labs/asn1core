"""Length octets: the part of BER where an untrusted number becomes a size.

X.690 8.1.3 gives three shapes. ``00``-7F is the length itself. ``80`` means indefinite,
closed by an end-of-contents marker. ``81``-``FE`` says how many following octets hold the
length, big-endian. ``FF`` is reserved.

The two defects this module exists to not repeat:

* **snmpy's encoder uses floating point to size an integer.** ``ceil(log2(n) / 8)`` returns
  ``k`` at exactly ``256**k``, so 256, 65536 and 16777216 all raise ``OverflowError`` while
  255 and 65535 work. A 256-byte OCTET STRING is enough to hit it. The fix is bit_length(),
  which is exact and has no boundary at a power of two.
* **snmpy's decoder trusts a length from the wire as a size.** An eight-octet length of all
  FF is a request to allocate 1.8e19 bytes. Here the declared length is compared against the
  bytes actually present before anything is sized from it, so the reserved and absurd forms
  fail with a named error rather than a ``MemoryError``.

Indefinite length is where snmpy's framing is worst: it locates the terminator with
``buffer.index(b"\\0\\0")``, which stops at the first pair of zero bytes **inside the content**
- and two consecutive zeros are everywhere (zero-padded integers, zero OID arcs, addresses).
The terminator is only a terminator at an object boundary, so finding it requires walking the
contained objects, not scanning for a byte pair.
"""

from __future__ import annotations

from .errors import DecodeError, DerViolation, TruncatedError

__all__ = ["INDEFINITE", "MAX_CONTENT_BYTES", "decode_length", "encode_length"]

# Sentinel returned by decode_length for the indefinite form. None is not used, because
# "no length octets" and "length present but indefinite" must stay distinguishable.
INDEFINITE = -1

# A cap on any single object's declared content, checked before the buffer is consulted.
# 64 MiB is above every real certificate, CRL or OCSP response by orders of magnitude and
# below anything that could be mistaken for a legitimate request.
MAX_CONTENT_BYTES = 64 * 1024 * 1024


def encode_length(length: int) -> bytes:
    """Encode a length in DER form: the fewest octets that can carry it.

    Short form below 128, otherwise ``0x80 | count`` followed by ``count`` big-endian octets.
    Never indefinite, never with a leading zero octet - both are BER tolerations that DER
    refuses, and an encoder that produced them would make its own output fail ``validate_der``.
    """
    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError(f"length must be int, got {type(length).__name__}")
    if length < 0:
        raise ValueError(f"length must be non-negative, got {length}")
    if length < 0x80:
        return bytes([length])
    # bit_length is exact. The reference implementation used ceil(log2(n) / 8), which returns
    # k rather than k+1 at every 256**k, so 256, 65536 and 16777216 raised OverflowError while
    # 255 and 65535 encoded happily - a 256-byte string was enough to find it.
    count = (length.bit_length() + 7) // 8
    return bytes([0x80 | count]) + length.to_bytes(count, "big")


def decode_length(buffer: bytes, offset: int = 0) -> tuple[int, int]:
    """Read the length octets, returning (length, offset_of_content).

    ``INDEFINITE`` comes back for form ``0x80``; the caller must then find the terminator by
    parsing objects, never by searching for a zero pair.

    Raises:
        TruncatedError: the buffer ends inside the length octets.
        DecodeError: ``0xFF`` (reserved), a count above 8, or a declared length above
            ``MAX_CONTENT_BYTES``.
    """
    if offset >= len(buffer):
        raise TruncatedError("buffer ends before the length octet", offset=offset)

    first = buffer[offset]
    if first < 0x80:
        return int(first), offset + 1
    if first == 0x80:
        return INDEFINITE, offset + 1
    if first == 0xFF:
        raise DecodeError("length form 0xFF is reserved by X.690", offset=offset)

    count = first & 0x7F
    if count > 8:
        # Covers the corpus row 04 8F 01: fifteen length octets is not a size anyone meant
        # to declare, and reading it as one turns a typo into a desynchronised parse.
        raise DecodeError(
            f"length form declares {count} octets, above the 8-octet limit", offset=offset
        )

    body = offset + 1
    if body + count > len(buffer):
        raise TruncatedError(
            f"length form declares {count} octets, {len(buffer) - body} present",
            offset=body,
        )

    length = int.from_bytes(buffer[body : body + count], "big")
    if length > MAX_CONTENT_BYTES:
        # The whole point of the ceiling: this number arrives from the network, and comparing
        # it against the buffer is the only thing standing between it and an allocation.
        raise DecodeError(
            f"declared length {length} exceeds the {MAX_CONTENT_BYTES} byte ceiling",
            offset=body,
        )
    return length, body + count


def check_length_canonical(octets: bytes, length: int, *, offset: int | None = None) -> None:
    """Reject a length whose encoding is not the minimal one DER requires.

    ``04 81 7F`` (127 in long form) and ``04 82 00 7F`` (a leading zero octet) are both legal
    BER and illegal DER. They matter beyond tidiness: two encodings of one object mean two
    hashes, two database rows, and a published count that is wrong.
    """
    if octets != encode_length(length):
        raise DerViolation(
            f"length {length} encoded in {len(octets)} octets, not the minimal form",
            rule="length-not-minimal",
            offset=offset,
        )
