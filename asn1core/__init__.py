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
from .errors import (
    Asn1Error,
    CertificateError,
    DecodeError,
    DepthExceeded,
    DerViolation,
    TruncatedError,
)
from .length import INDEFINITE, MAX_CONTENT_BYTES, decode_length, encode_length
from .node import MAX_DEPTH, Node, decode, encode_der
from .oid import MAX_ARC_VALUE, MAX_OID_ARCS, check_oid, decode_oid, encode_oid, parse_oid_string
from .tag import MAX_TAG_NUMBER, Tag, TagClass, decode_tag, encode_tag
from .x509 import (
    CertificateParts,
    certificate_parts,
    signature_algorithm,
    spki_sha256,
    subject_public_key_info,
    tbs_certificate,
)

__version__ = "0.0.1"

__all__ = [
    "INDEFINITE",
    "MAX_ARC_VALUE",
    "MAX_CONTENT_BYTES",
    "MAX_DEPTH",
    "MAX_OID_ARCS",
    "MAX_TAG_NUMBER",
    "Asn1Error",
    "CertificateError",
    "CertificateParts",
    "DecodeError",
    "DepthExceeded",
    "DerViolation",
    "Node",
    "Tag",
    "TagClass",
    "TruncatedError",
    "__version__",
    "certificate_parts",
    "check_bit_string",
    "check_boolean",
    "check_integer",
    "check_oid",
    "check_set_of",
    "decode",
    "decode_length",
    "decode_oid",
    "decode_tag",
    "encode_der",
    "encode_length",
    "encode_oid",
    "encode_tag",
    "parse_oid_string",
    "signature_algorithm",
    "spki_sha256",
    "subject_public_key_info",
    "tbs_certificate",
    "validate_der",
]
