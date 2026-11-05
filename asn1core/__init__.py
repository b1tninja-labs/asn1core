"""asn1core - an ASN.1 BER/DER codec that never loses the bytes it parsed.

The public surface is deliberately small: parse, re-serialise canonically, and assert
canonicality. Everything else in the package is internal detail.

    >>> from asn1core import decode, encode_der
    >>> node, end = decode(bytes.fromhex("3000"))
    >>> node.tag.number, node.constructed, end
    (16, True, 2)

Status is pre-alpha and the exit test is VECTORS.md; where a test fails, the behaviour is
missing rather than subtly wrong. See PLAN.md for what is inherited from snmpy's ber package
and, more importantly, what is not.
"""

from __future__ import annotations

from .der import check_bit_string, check_boolean, check_integer, check_set_of, validate_der
from .errors import Asn1Error, DecodeError, DepthExceeded, DerViolation, TruncatedError
from .length import INDEFINITE, MAX_CONTENT_BYTES, decode_length, encode_length
from .node import MAX_DEPTH, Node, decode, encode_der
from .tag import MAX_TAG_NUMBER, Tag, TagClass, decode_tag, encode_tag

__version__ = "0.0.1"

__all__ = [
    "INDEFINITE",
    "MAX_CONTENT_BYTES",
    "MAX_DEPTH",
    "MAX_TAG_NUMBER",
    "Asn1Error",
    "DecodeError",
    "DepthExceeded",
    "DerViolation",
    "Node",
    "Tag",
    "TagClass",
    "TruncatedError",
    "__version__",
    "check_bit_string",
    "check_boolean",
    "check_integer",
    "check_set_of",
    "decode",
    "decode_length",
    "decode_tag",
    "encode_der",
    "encode_length",
    "encode_tag",
    "validate_der",
]
