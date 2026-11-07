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

from .cert import Certificate, Extension, parse_certificate, parse_extensions
from .crl import Crl, Revoked, parse_crl
from .der import (
    PRINTABLE_ALPHABET,
    check_bit_string,
    check_boolean,
    check_integer,
    check_printable_string,
    check_set_of,
    validate_der,
)
from .errors import (
    ArmourError,
    Asn1Error,
    CertificateError,
    DecodeError,
    DepthExceeded,
    DerViolation,
    StringPrepError,
    TruncatedError,
)
from .length import INDEFINITE, MAX_CONTENT_BYTES, decode_length, encode_length
from .name import (
    SHORT_NAMES,
    Attribute,
    Name,
    names_equal,
    normalize_value,
    parse_name,
    within,
)
from .node import MAX_DEPTH, Node, decode, encode_der
from .oid import MAX_ARC_VALUE, MAX_OID_ARCS, check_oid, decode_oid, encode_oid, parse_oid_string
from .stringprep import (
    insignificant_space,
    map_characters,
    preparation_issues,
    prepare_value,
    prohibited_characters,
)
from .tag import MAX_TAG_NUMBER, Tag, TagClass, decode_tag, encode_tag
from .time import (
    NO_EXPIRATION,
    UTC_TIME_CEILING_YEAR,
    UTC_TIME_FLOOR_YEAR,
    check_generalized_time,
    check_utc_time,
    encode_generalized_time,
    encode_utc_time,
    time_tag_for,
)
from .x509 import (
    CertificateParts,
    SignedDocument,
    Validity,
    certificate_parts,
    issuer,
    signature_algorithm,
    signed_document_parts,
    spki_sha256,
    subject,
    subject_public_key_info,
    tbs_certificate,
    validity,
    validity_encoding_issue,
)

__version__ = "0.0.1"

__all__ = [
    "INDEFINITE",
    "MAX_ARC_VALUE",
    "MAX_CONTENT_BYTES",
    "MAX_DEPTH",
    "MAX_OID_ARCS",
    "MAX_TAG_NUMBER",
    "NO_EXPIRATION",
    "PRINTABLE_ALPHABET",
    "SHORT_NAMES",
    "UTC_TIME_CEILING_YEAR",
    "UTC_TIME_FLOOR_YEAR",
    "ArmourError",
    "Asn1Error",
    "Attribute",
    "Certificate",
    "CertificateError",
    "CertificateParts",
    "Crl",
    "DecodeError",
    "DepthExceeded",
    "DerViolation",
    "Extension",
    "Name",
    "Node",
    "Revoked",
    "SignedDocument",
    "StringPrepError",
    "Tag",
    "TagClass",
    "TruncatedError",
    "Validity",
    "__version__",
    "certificate_parts",
    "check_bit_string",
    "check_boolean",
    "check_generalized_time",
    "check_integer",
    "check_oid",
    "check_printable_string",
    "check_set_of",
    "check_utc_time",
    "decode",
    "decode_length",
    "decode_oid",
    "decode_tag",
    "encode_der",
    "encode_generalized_time",
    "encode_length",
    "encode_oid",
    "encode_tag",
    "encode_utc_time",
    "insignificant_space",
    "issuer",
    "map_characters",
    "names_equal",
    "normalize_value",
    "parse_certificate",
    "parse_crl",
    "parse_extensions",
    "parse_name",
    "parse_oid_string",
    "preparation_issues",
    "prepare_value",
    "prohibited_characters",
    "signature_algorithm",
    "signed_document_parts",
    "spki_sha256",
    "subject",
    "subject_public_key_info",
    "tbs_certificate",
    "time_tag_for",
    "validate_der",
    "validity",
    "validity_encoding_issue",
    "within",
]
