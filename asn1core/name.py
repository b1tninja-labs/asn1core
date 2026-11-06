"""Distinguished names: the structure RFC 5280 §4.1.2.4 defines, and the comparison §7.1 requires.

A `Name` is a `SEQUENCE OF RelativeDistinguishedName`, and an RDN is a `SET OF`
attribute-type-and-value pairs - so a name is a sequence of *sets*, and two names being equal is
not a byte comparison. Two independent things can go wrong: reading the structure in the wrong
shape, and comparing two spellings of the same name as if they differed.

**On structure.** An RDN may hold several attributes, which RFC 4514 renders with `+` and which
path validation must match as a set rather than by position. No certificate in the local trust
store contains one - 577 RDNs measured, all single-valued - so `tests/fixtures/multivalue-rdn.der`
is generated for that case and labelled as a synthetic document rather than passed off as
something a CA issued.

**On comparison.** §7.1: "Conforming implementations MUST use the LDAP StringPrep profile
(including insignificant space handling), as specified in [RFC4518], as the basis for comparison of
distinguished name attributes encoded in either PrintableString or UTF8String", MUST support
`caseIgnoreMatch`, and before comparing MUST perform the six-step string preparation with case
folding and the white space compression of RFC 4518 §2.6.1 - a pointer printed as "RFC 4158" and
corrected by verified erratum 7658. Two attributes match when the types are the same and the
prepared values are equal; two RDNs match when they hold the same number of attributes and pair
off; two names match when they have the same number of RDNs, pair off, **and appear in the same
order**.

What `normalize_value` implements is named in its docstring, and it is not the whole profile: the
RFC 4518 mapping tables in Appendix A and the prohibited-character and bidirectional checks are
not here. Those gaps are recorded in `PLAN.md` as their own open obligation rather than left for a
reader to discover.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from .errors import CertificateError
from .node import Node
from .oid import decode_oid
from .tag import Tag, TagClass

__all__ = [
    "SHORT_NAMES",
    "Attribute",
    "Name",
    "names_equal",
    "normalize_value",
    "parse_name",
    "within",
]

_SEQUENCE = Tag(16, True, TagClass.universal)
_SET = Tag(17, True, TagClass.universal)
_OID = Tag(6, False, TagClass.universal)


# AttributeValue is a CHOICE of string types, and the codec each one carries is part of the
# definition: BMPString is UTF-16BE, UniversalString is UTF-32BE. §7.1 makes support for
# TeletexString, BMPString and UniversalString optional; UTF8String and PrintableString are the
# two a conforming implementation MUST support. The ASCII-restricted types are read as Latin-1 so
# that decoding never rejects a byte - whether the characters are legal for the type is a separate
# question, left open in PLAN.md rather than guessed at here. A codec of None means the ambiguous
# ones: try UTF-8, then fall back to Latin-1.
_CODECS: dict[int, tuple[str, str | None]] = {
    12: ("utf8String", "utf-8"),
    13: ("numericString", "latin-1"),
    14: ("printableString", "latin-1"),
    19: ("teletexString", None),
    20: ("videotexString", None),
    22: ("ia5String", "latin-1"),
    26: ("visibleString", "latin-1"),
    27: ("generalString", "latin-1"),
    28: ("universalString", "utf-32-be"),
    30: ("bmpString", "utf-16-be"),
}

# RFC 4514 §3's descriptor table. Types outside it render as dotted OIDs: cryptography does the
# same, including for emailAddress, and inventing a short name would make two renderings of one
# name disagree.
SHORT_NAMES: dict[tuple[int, ...], str] = {
    (2, 5, 4, 3): "CN",
    (2, 5, 4, 6): "C",
    (2, 5, 4, 7): "L",
    (2, 5, 4, 8): "ST",
    (2, 5, 4, 9): "STREET",
    (2, 5, 4, 10): "O",
    (2, 5, 4, 11): "OU",
    (2, 5, 4, 12): "TITLE",
    (0, 9, 2342, 19200300, 100, 1, 25): "DC",
    (0, 9, 2342, 19200300, 100, 1, 1): "UID",
}


@dataclass(frozen=True, slots=True)
class Attribute:
    """One attribute type and value, with the string type that carried it.

    ``kind`` is kept because it is not incidental: a value that arrives as TeletexString is
    decoded by a rule §7.1 makes optional, and a caller deciding whether two names match needs to
    know which side leaned on that rule.
    """

    oid: tuple[int, ...]
    value: str
    kind: str

    @property
    def dotted_oid(self) -> str:
        return ".".join(str(part) for part in self.oid)

    @property
    def short_name(self) -> str:
        return SHORT_NAMES.get(self.oid, self.dotted_oid)


@dataclass(frozen=True, slots=True, eq=False)
class Name:
    """A distinguished name: a sequence of RDNs, each an unordered set of attributes.

    The sequence is held in **encoding order**, which is most general first - a root's ``C=`` sits
    at index 0 and a leaf's ``CN=`` last. RFC 4514 strings are the other way round, so `rfc4514`
    reverses on the way out. Getting this backwards inverts every subtree test, which is the
    difference between "this certificate was issued by Example" and "anyone can claim Example".

    Equality is §7.1's match, not the dataclass comparison: neither ``raw`` nor the string type
    that carried a value takes part in it, because one name legitimately appears as ``C=US`` in
    PrintableString in one document and ``C=us`` in UTF8String in another. Comparing the bytes
    would call those two different names - and would agree that a self-signed certificate's issuer
    and subject match only because their TLVs happen to be identical, which is the right answer for
    the wrong reason.
    """

    rdnsets: tuple[tuple[Attribute, ...], ...]
    raw: bytes

    def values(self, dotted_oid: str) -> tuple[str, ...]:
        """Every value carried for this attribute type, in encoding order."""
        target = tuple(int(part) for part in dotted_oid.split("."))
        return tuple(attr.value for rdn in self.rdnsets for attr in rdn if attr.oid == target)

    def first(self, dotted_oid: str) -> str | None:
        found = self.values(dotted_oid)
        return found[0] if found else None

    @property
    def common_name(self) -> str | None:
        return self.first("2.5.4.3")

    def rfc4514(self) -> str:
        """The RFC 4514 string form: most specific RDN first, attributes of one RDN joined by `+`."""
        return ",".join("+".join(_pair(attr) for attr in rdn) for rdn in reversed(self.rdnsets))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Name):
            return NotImplemented
        return names_equal(self, other)

    def __hash__(self) -> int:
        # Consistent with __eq__ in both directions: RDN order is significant and attribute order
        # inside an RDN is not, so the attributes are sorted before hashing.
        return hash(
            tuple(
                tuple(sorted((attr.oid, normalize_value(attr.value)) for attr in rdn))
                for rdn in self.rdnsets
            )
        )

    def __str__(self) -> str:
        return self.rfc4514()


def parse_name(node: Node) -> Name:
    """Read a `Name` from a parsed node, refusing anything shaped differently.

    Raises:
        CertificateError: the node is not `SEQUENCE OF SET OF SEQUENCE (OID, string)`; an RDN is
            empty; an attribute value carries a tag that is not one of the string types; or a
            string cannot be decoded in the codec its type declares.
    """
    if node.tag != _SEQUENCE:
        raise CertificateError(f"a Name is a SEQUENCE OF RDN, found tag {node.tag!r}")

    rdnsets: list[tuple[Attribute, ...]] = []
    for rdn in node.children:
        if rdn.tag != _SET:
            raise CertificateError(f"an RDN is a SET OF attributes, found tag {rdn.tag!r}")
        if not rdn.children:
            raise CertificateError("an RDN holds at least one attribute")
        attributes: list[Attribute] = []
        for ava in rdn.children:
            if ava.tag != _SEQUENCE:
                raise CertificateError(
                    f"an AttributeTypeAndValue is a SEQUENCE, found tag {ava.tag!r}"
                )
            if len(ava.children) != 2:
                raise CertificateError(
                    f"an AttributeTypeAndValue has two fields, found {len(ava.children)}"
                )
            oid_node, value_node = ava.children
            if oid_node.tag != _OID or oid_node.payload is None:
                raise CertificateError(f"an attribute type is an OID, found tag {oid_node.tag!r}")
            kind, value = _attribute(value_node)
            attributes.append(Attribute(oid=decode_oid(oid_node.payload), value=value, kind=kind))
        rdnsets.append(tuple(attributes))
    return Name(rdnsets=tuple(rdnsets), raw=node.raw)


def _attribute(node: Node) -> tuple[str, str]:
    """Validate the string type before decoding it, so a bad tag says so rather than missing.

    The order matters: looking the tag up first means an unrecognised type is reported as the
    shape problem it is instead of surfacing as a ``KeyError`` from inside the decoder.
    """
    if node.tag.tag_class is not TagClass.universal or node.tag.constructed:
        raise CertificateError(f"an attribute value is a universal string type, found {node.tag!r}")
    entry = _CODECS.get(node.tag.number)
    if entry is None:
        raise CertificateError(f"attribute value tag {node.tag.number} is not a string type")
    kind, codec = entry
    content = node.payload
    if content is None:
        raise CertificateError(f"{kind} carries no content octets")
    if codec is None:
        try:
            return kind, content.decode("utf-8")
        except UnicodeDecodeError:
            return kind, content.decode("latin-1")
    try:
        return kind, content.decode(codec)
    except UnicodeDecodeError as exc:
        raise CertificateError(f"{kind} content is not valid {codec}: {exc}") from exc


def normalize_value(text: str) -> str:
    """Prepare one attribute value for comparison, per RFC 5280 §7.1 and RFC 4518 §2.6.1.

    Implemented: non-ASCII spaces (Unicode class Zs) mapped to SPACE, soft hyphen removed, NFC
    normalisation (RFC 4518 §2.3), case folding (§7.1's clarification, pointing at RFC 3454
    Appendix B.2 - Python's ``casefold`` performs full folding), and the insignificant space
    handling of §2.6.1 for stored values. That last rule surprises people and is stated exactly: a
    value with at least one non-space character comes back with **exactly one SPACE at each end**,
    and **every inner run of spaces, however long, replaced by exactly two**; a value with no
    non-space character comes back as exactly two SPACEs. So ``"Paris"``, ``" paris "`` and
    ``"Paris\u00a0\u00a0 "`` all prepare to ``" paris "``, while the RFC's own worked example maps
    ``"foo bar  "`` to ``" foo  bar "``.

    Not implemented: the rest of RFC 4518's Appendix A mapping tables, the prohibited-character
    test in §2.2 and the bidirectional checks in §2.4. Those can decide equality for exotic input,
    so this is a strong subset rather than a full StringPrep, and ``PLAN.md`` tracks the gap.
    """
    mapped = "".join(" " if ch != " " and unicodedata.category(ch) == "Zs" else ch for ch in text)
    mapped = mapped.replace("\u00ad", "")
    return _insignificant_space(unicodedata.normalize("NFC", mapped).casefold())


def _insignificant_space(text: str) -> str:
    """RFC 4518 §2.6.1, attribute-value branch. SPACE here means U+0020 and nothing else."""
    if not any(ch != " " for ch in text):
        return "  "
    built: list[str] = []
    run = 0
    for ch in text:
        if ch == " ":
            run += 1
            continue
        if built and run:
            built.append("  ")
        built.append(ch)
        run = 0
    return " " + "".join(built) + " "


def names_equal(left: Name, right: Name) -> bool:
    """§7.1's DN match: same number of RDNs, pairing in the same order, attributes pairing within."""
    if len(left.rdnsets) != len(right.rdnsets):
        return False
    return all(_rdns_match(a, b) for a, b in zip(left.rdnsets, right.rdnsets, strict=True))


def within(child: Name, anchor: Name) -> bool:
    """§7.1's subtree rule: ``child`` has at least as many RDNs as ``anchor``, and the anchor's
    RDNs match ``child``'s first ones.

    "Trailing RDNs in DN1 are ignored" is read in encoding order, where the root comes first, so
    what gets ignored is the child's own tail at the leaf end. Reading it off the wrong end accepts
    any certificate whose leaf happens to match a trust anchor, which is a trust decision made
    backwards.
    """
    if len(child.rdnsets) < len(anchor.rdnsets):
        return False
    if not anchor.rdnsets:
        return True
    head = Name(rdnsets=child.rdnsets[: len(anchor.rdnsets)], raw=b"")
    return names_equal(head, anchor)


def _rdns_match(left: tuple[Attribute, ...], right: tuple[Attribute, ...]) -> bool:
    """An RDN is a set: pair the attributes off without reusing one."""
    if len(left) != len(right):
        return False
    pool = list(right)
    for attr in left:
        prepared = normalize_value(attr.value)
        for index, candidate in enumerate(pool):
            if attr.oid == candidate.oid and prepared == normalize_value(candidate.value):
                pool.pop(index)
                break
        else:
            return False
    return True


# RFC 4514 §3: these need escaping wherever they appear. SPACE and SHARP are special at the start,
# and SPACE again at the end - the grammar's leadchar and trailchar ranges say exactly which.
_ESCAPE_ANYWHERE = frozenset('"+,;<>\\')


def _pair(attr: Attribute) -> str:
    return f"{attr.short_name}={_escape(attr.value)}"


def _escape(value: str) -> str:
    last = len(value) - 1
    out: list[str] = []
    for index, ch in enumerate(value):
        code = ord(ch)
        if ch in _ESCAPE_ANYWHERE or (index == 0 and ch in " #") or (index == last and ch == " "):
            out.append("\\" + ch)
        elif code < 0x20 or code == 0x7F:
            out.append(f"\\{code:02x}")
        else:
            out.append(ch)
    return "".join(out)
