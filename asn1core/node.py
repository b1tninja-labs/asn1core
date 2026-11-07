"""The node: tag, content, and **the octets it came from**.

This module owns the one property that makes the package worth having. ``Node.raw`` holds the
exact TLV bytes that were parsed, so a signature can be verified over the bytes it was made
over, which is what RFC 5280 section 4.1.3.2 requires of a TBSCertificate and what snmpy's
codec cannot do: decoding ``02 81 01 00`` and re-encoding gives ``02 01 00``, four octets
become three, and the original is gone.

The rest is discipline about framing:

* a declared length is checked against the bytes present before anything is sliced, because
  Python slicing truncates silently and a decoder that relies on it returns a short value
  *and* an offset past the end of the buffer - the reference implementation does exactly this,
  answering ``6`` for a 4-byte input;
* length 0 parses as empty, never as absent, which are different answers;
* a constructed object's children must tile its content exactly, so an inner length that
  overruns its parent is an error rather than a coincidence;
* identical children stay distinct objects, because aliasing here produces wrong certificates.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import DecodeError, DepthExceeded, DerViolation, TruncatedError
from .length import INDEFINITE, check_length_canonical, decode_length, encode_length
from .oid import check_oid
from .tag import Tag, decode_tag, encode_tag
from .time import check_generalized_time, check_utc_time

__all__ = ["MAX_DEPTH", "Node", "decode", "encode_der"]

# Nesting limit. 10,000 levels is the corpus case, and CPython's own recursion limit is the
# wrong place to discover it, so the decoder counts depth and raises DepthExceeded.
MAX_DEPTH = 64


@dataclass(slots=True)
class Node:
    """One TLV object.

    ``raw`` is the original bytes of this object including its own tag and length octets.
    ``payload`` and ``children`` are mutually exclusive: primitive nodes carry content bytes,
    constructed nodes carry child nodes. Neither is derived from re-encoding anything.
    """

    tag: Tag
    raw: bytes
    payload: bytes | None = None
    children: tuple[Node, ...] = ()

    @property
    def constructed(self) -> bool:
        return self.tag.constructed

    def content(self) -> bytes:
        """The content octets as they appeared in the input, never a re-encoding."""
        if self.payload is not None:
            return self.payload
        return b"".join(child.raw for child in self.children)


def decode(
    buffer: bytes,
    offset: int = 0,
    *,
    der: bool = False,
    max_depth: int = MAX_DEPTH,
) -> tuple[Node, int]:
    """Parse one object, returning it and the offset just past its last octet.

    With ``der=True`` every BER toleration becomes a ``DerViolation``. With ``der=False`` the
    encoding is accepted but still fully framed: tolerance is about canonicality, never about
    whether the bytes make sense, and a truncated buffer raises TruncatedError either way.

    Raises:
        TruncatedError: the buffer ends inside the object, at any depth.
        DecodeError: the encoding violates X.690 (reserved length form, non-minimal tag
            number, indefinite length with no terminator).
        DerViolation: legal BER on the DER path.
        DepthExceeded: nesting passed ``max_depth``.
    """
    if offset >= len(buffer):
        raise TruncatedError("buffer is empty at the requested offset", offset=offset)
    return _parse(buffer, offset, der=der, depth=1, max_depth=max_depth, limit=None)


def _parse(
    buffer: bytes,
    offset: int,
    *,
    der: bool,
    depth: int,
    max_depth: int,
    limit: int | None,
) -> tuple[Node, int]:
    """Parse one object, bounded by ``limit`` when it is a child.

    ``limit`` is what keeps a nested object from reading past its parent. Without it the
    reference behaviour is reproduced exactly: ``30 04 01 02`` reports success and hands back
    an offset of 6 for a 4-byte buffer, because slicing in Python is patient and lies about it.
    """
    if depth > max_depth:
        raise DepthExceeded(f"nesting exceeds the limit of {max_depth}", offset=offset)

    tag, after_tag = decode_tag(buffer, offset, der=der)
    length, content_start = decode_length(buffer, after_tag)
    length_octets = buffer[after_tag:content_start]

    if length == INDEFINITE:
        if der:
            raise DerViolation(
                "indefinite length is not permitted by DER",
                rule="indefinite-length",
                offset=after_tag,
            )
        if not tag.constructed:
            # X.690 (02/2021) 8.1.3.2 a) requires a sender to use the definite form when the
            # encoding is primitive, and 7.1 dynamic conformance gives a receiver no licence to
            # accept what no conforming sender may emit. Refusing is therefore a cited answer,
            # not a defensive guess: the earlier text here called the corpus row "unresolved",
            # which stopped being true when the clause was read on 2026-11-07 and left the
            # error message arguing with VECTORS.md.
            raise DecodeError(
                "indefinite length on a primitive encoding is never conforming (X.690 8.1.3.2 a)",
                offset=after_tag,
            )
        children, end = _children_indefinite(
            buffer, content_start, der=der, depth=depth, max_depth=max_depth, limit=limit
        )
        return Node(tag=tag, raw=buffer[offset:end], children=children), end

    content_end = content_start + length
    if content_end > len(buffer):
        raise TruncatedError(
            f"object declares {length} content octets, {len(buffer) - content_start} present",
            offset=content_start,
        )
    if limit is not None and content_end > limit:
        raise DecodeError(
            f"object ending at {content_end} overruns its parent, which ends at {limit}",
            offset=content_start,
        )
    if der:
        check_length_canonical(length_octets, length, offset=after_tag)

    if tag.constructed:
        children, cursor = _children_definite(
            buffer, content_start, content_end, der=der, depth=depth, max_depth=max_depth
        )
        if cursor != content_end:
            # Unreachable while _parse honours limit, and a real check rather than an assert:
            # under python -O an assert here would delete the guarantee this function exists for.
            raise DecodeError("constructed children do not tile the parent exactly", offset=cursor)
        node = Node(tag=tag, raw=buffer[offset:content_end], children=children)
        if der:
            # SET OF ordering is a constructed-level rule, so it has to be reachable from
            # here. Checking only the primitive branch - as the first draft of this function
            # did - silently leaves the one DER restriction that X.509 name comparison
            # depends on unenforced.
            _der_value_check(tag, b"", node, offset=content_start)
        return node, content_end

    payload = buffer[content_start:content_end]
    node = Node(tag=tag, raw=buffer[offset:content_end], payload=payload)
    if der:
        _der_value_check(tag, payload, node, offset=content_start)
    return node, content_end


def encode_der(node: Node) -> bytes:
    """Re-serialise a node in canonical DER.

    For a node that was parsed from canonical input this must reproduce ``node.raw`` byte for
    byte - the ``rt-idempotent`` corpus row. Where it does not, either the encoder and the
    decoder disagree about the rules or the input was not canonical, and the third case has to
    surface as an error rather than as a quiet normalisation.
    """
    if node.payload is not None:
        content = node.payload
    else:
        content = b"".join(encode_der(child) for child in node.children)
    return encode_tag(node.tag) + encode_length(len(content)) + content


def _children_definite(
    buffer: bytes,
    start: int,
    end: int,
    *,
    der: bool,
    depth: int,
    max_depth: int,
) -> tuple[tuple[Node, ...], int]:
    """Parse children until the parent's content is exactly consumed.

    Each child is bounded by ``end``, so the cursor can never leave the parent and the tiling
    is exact by construction rather than by luck.
    """
    children: list[Node] = []
    cursor = start
    while cursor < end:
        child, cursor = _parse(
            buffer, cursor, der=der, depth=depth + 1, max_depth=max_depth, limit=end
        )
        children.append(child)
    return tuple(children), cursor


def _children_indefinite(
    buffer: bytes,
    start: int,
    *,
    der: bool,
    depth: int,
    max_depth: int,
    limit: int | None,
) -> tuple[tuple[Node, ...], int]:
    """Parse children until an end-of-contents marker **at an object boundary**.

    This is the fix for the worst framing defect in the reference codec, which located the
    terminator with ``buffer.index(b"\\0\\0")`` and so reported the first pair of zero bytes
    anywhere ahead of the cursor - including inside an OCTET STRING, a zero-padded INTEGER or
    an address. Walking the contained objects is the only way to know that a pair of NULs is a
    terminator rather than data.
    """
    children: list[Node] = []
    cursor = start
    while True:
        if cursor + 1 >= len(buffer):
            raise TruncatedError(
                "indefinite length is never closed by an end-of-contents marker", offset=cursor
            )
        if buffer[cursor] == 0x00 and buffer[cursor + 1] == 0x00:
            return tuple(children), cursor + 2
        child, cursor = _parse(
            buffer, cursor, der=der, depth=depth + 1, max_depth=max_depth, limit=limit
        )
        children.append(child)


def _der_value_check(tag: Tag, payload: bytes, node: Node, *, offset: int) -> None:
    """Apply the value-level DER restrictions assertable without a schema.

    Imported lazily because der.py imports this module: a top-level import here would be a
    cycle. The dependency stays one-way at call time, which keeps the parser free of policy
    and the policy free of the parser.
    """
    if not tag.is_universal():
        return
    from .der import (
        check_bit_string,
        check_boolean,
        check_integer,
        check_printable_string,
        check_set_of,
    )

    if tag.number == 1:
        check_boolean(payload, offset=offset)
    elif tag.number == 2:
        check_integer(payload, offset=offset)
    elif tag.number == 3:
        check_bit_string(payload, offset=offset)
    elif tag.number == 6:
        # oid-canonical-form. This check carries more weight than the others: identifiers carry
        # meaning, and a spelling a peer reads as a different OID is an identity substitution
        # rather than a formatting difference.
        check_oid(payload, offset=offset)
    elif tag.number == 23:
        # utc-time-canonical. Value-level and DER-path only: the 11-octet minute-precision form
        # is legal BER and legal ASN.1, and a tolerant decode must keep those octets rather than
        # decide what year they mean.
        check_utc_time(payload, offset=offset)
    elif tag.number == 24:
        # general-time-canonical: century present, seconds present, no fractional part.
        check_generalized_time(payload, offset=offset)
    elif tag.number == 17:
        check_set_of(node)
    elif tag.number == 19:
        # printable-charset. Tag 19 is PrintableString (X.680 Table 1 puts character string types in
        # 18-22 and 25-30; 13 is Relative-OID and 14 is the TIME type). Unlike every other check here this
        # one refuses a *value*, not a spelling, so it is deliberately absent from the tolerant path: a
        # certificate that shipped a `&` in a PrintableString must stay inspectable.
        check_printable_string(payload, offset=offset)
