"""RFC 4518, the LDAP StringPrep profile RFC 5280 §7.1 requires for comparing DN values.

RFC 4518 §2 lists the steps, and this module implements them in the order the document gives:

- **2.1 Transcode** - done by `name.py`, which decodes each string type by its own codec.
- **2.2 Map** - characters that comparison ignores removed, spaces unified, case folded.
- **2.3 Normalize** - NFC.
- **2.4 Prohibit** - refuse a small set of code points.
- **2.5 Check bidi** - *nothing*: §2.5 says "Bidirectional characters are ignored".
- **2.6.1** - insignificant space handling, the attribute-value branch.

The bidi step is worth stating because it is the opposite of what the name "StringPrep" suggests.
RFC 3454 StringPrep checks bidirectional categories; RFC 4518 explicitly does not. An earlier note
in this repository listed "the bidirectional checks" as work left undone, which was a misreading of
§2.4 and §2.5 - there is no bidi rule in this profile to implement.

**Erratum 860 changes the mapping.** §2.2 as published maps "VARIATION SELECTORs (U+180B-180D,
FF00-FE0F)" to nothing. That second range is printed backwards, and the verified erratum says
FE00-FE0F was meant. Implemented as printed, the range would also swallow U+FF01 to U+FF60 - every
fullwidth Latin and katakana character, which is how CJK names are often spelled - and each would
be silently deleted from a name before comparison. `test_fullwidth_forms_survive_the_map` holds the
corrected reading, and asserts the printed reading would have differed, so the mistake cannot be
reintroduced by someone re-reading the RFC text without its errata.

**§2.4 pins the character repertoire to Unicode 3.2** ("The character repertoire of this process is
Unicode 3.2", §2), via Table A.1 of RFC 3454. That table calls 59,842 code points unassigned which
Unicode has assigned since - including U+0237, LATIN SMALL LETTER DOTLESS J, an ordinary letter in
several orthographies. So the unassigned test is offered two ways: `unassigned="current"` (the
default, `unicodedata` category Cn) and `unassigned="pinned"` (the literal RFC 3454 table). Nothing
in the local trust store distinguishes them today - 0 of 577 attribute values either way, measured -
so the default is a judgement about names this store has not met rather than a workaround for names
it has, and `preparation_issues` reports what each choice would have refused.
"""

from __future__ import annotations

import stringprep
import unicodedata

from .errors import StringPrepError

__all__ = [
    "insignificant_space",
    "map_characters",
    "normalize",
    "preparation_issues",
    "prepare_value",
    "prohibited_characters",
]

_MARK_CATEGORIES = frozenset({"Mn", "Mc", "Me"})  # §1.6: "combining mark" means Mn, Mc or Me
_SEPARATOR_CATEGORIES = frozenset({"Zs", "Zl", "Zp"})  # §2.2 maps all of these to SPACE


def _ranges(*pairs: tuple[int, int]) -> frozenset[int]:
    return frozenset(cp for start, end in pairs for cp in range(start, end + 1))


def _is_mark(char: str) -> bool:
    """§1.6: a "combining mark" is any code point with the Mn, Mc or Me category."""
    return unicodedata.category(char) in _MARK_CATEGORIES


# §2.2 paragraph 3: the complete list of Cc/Cf code points mapped to nothing, plus paragraph 1's
# explicit ones. U+0085 is deliberately absent from the control runs: paragraph 2 maps it to SPACE
# rather than to nothing, which is why the ranges are split around it instead of written as one.
_MAPPED_TO_NOTHING = _ranges(
    (0x00AD, 0x00AD),  # SOFT HYPHEN
    (0x1806, 0x1806),  # MONGOLIAN TODO SOFT HYPHEN
    (0x034F, 0x034F),  # COMBINING GRAPHEME JOINER
    (0x180B, 0x180D),  # MONGOLIAN VARIATION SELECTORS
    (0xFE00, 0xFE0F),  # VARIATION SELECTORS - erratum 860, not the printed FF00-FE0F
    (0xFFFC, 0xFFFC),  # OBJECT REPLACEMENT CHARACTER
    (0x200B, 0x200B),  # ZERO WIDTH SPACE, called out separately in paragraph 4
    (0xFEFF, 0xFEFF),  # ZERO WIDTH NO-BREAK SPACE
    (0x0000, 0x0008),
    (0x000E, 0x001F),
    (0x007F, 0x0084),
    (0x0086, 0x009F),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x180E, 0x180E),
    (0x200C, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2063),
    (0x206A, 0x206F),
    (0xFFF9, 0xFFFB),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
)

# §2.2 paragraph 2, verbatim: these control characters become SPACE rather than disappearing.
_MAPPED_TO_SPACE = _ranges((0x0009, 0x000D), (0x0085, 0x0085))


def map_characters(text: str, *, fold: bool = True) -> str:
    """RFC 4518 §2.2: remove what comparison ignores, unify spaces, fold case.

    The map-to-nothing list is consulted **before** the separator rule, because U+200B ZERO WIDTH
    SPACE carries a separator category in some Unicode versions while §2.2 paragraph 4 maps it to
    nothing rather than to a space. The order is the specification's, not a preference.

    ``fold`` applies the case folding of paragraph 5 (RFC 3454 B.2, which Python's ``casefold``
    performs in full). Folding is the last thing the Map step does, so it happens *before* NFC. The
    reverse order is what this package did before this module existed; it agrees on all 577
    attribute values in the local store, but the document's order is the one implemented.
    """
    mapped = []
    for char in text:
        if ord(char) in _MAPPED_TO_NOTHING:
            continue
        if ord(char) in _MAPPED_TO_SPACE or unicodedata.category(char) in _SEPARATOR_CATEGORIES:
            mapped.append(" ")
            continue
        mapped.append(char)
    joined = "".join(mapped)
    return joined.casefold() if fold else joined


def normalize(text: str) -> str:
    """RFC 4518 §2.3: Unicode Normalization Form NFC."""
    return unicodedata.normalize("NFC", text)


def prepare_mapped(text: str, *, fold: bool = True) -> str:
    """§2.2 and §2.3 together: Map, then Normalize. No gate, no space handling."""
    return normalize(map_characters(text, fold=fold))


def prohibited_characters(text: str, *, unassigned: str = "current") -> tuple[str, ...]:
    """RFC 4518 §2.4: the code points the profile refuses, one description each.

    An empty tuple means the string passes. The step is a gate, and the caller decides what a
    failing gate means: `prepare_value` raises, `preparation_issues` reports, and
    `name.normalize_value` does neither, so a name carrying something odd still matches its own
    identical spelling.

    ``unassigned`` chooses between the Unicode 3.2 table the profile pins and current data; see the
    module docstring. The other sets use the pinned tables, because no movement there has ever
    changed an answer.

    One §2.4 rule cannot fire on input that has been through §2.3, and it is worth knowing which:
    Table C.8 holds characters that change display properties or are deprecated, and once §2.2 has
    removed every Cc and Cf code point exactly two members remain reachable - U+0340 and U+0341 -
    both of which have *canonical* decompositions, so NFC has rewritten them to U+0300 and U+0301
    before the prohibit step runs. (The bidi controls are in C.8 too - U+200F and U+202E were
    checked - but they are Cf, so Map deletes them first, which is part of why §2.5 can afford to
    ignore bidi entirely.) It is implemented anyway, because it is callable directly.
    """
    if unassigned not in ("current", "pinned"):
        raise ValueError(f"unassigned must be 'current' or 'pinned', not {unassigned!r}")
    out: list[str] = []
    for char in text:
        name = f"U+{ord(char):04X} {unicodedata.name(char, '<unnamed>')}"
        if char == "\ufffd":
            out.append(f"{name}: the REPLACEMENT CHARACTER is prohibited (2.4)")
        elif stringprep.in_table_c3(char):
            out.append(f"{name}: private use is prohibited (2.4, Table C.3)")
        elif stringprep.in_table_c4(char):
            out.append(f"{name}: non-character is prohibited (2.4, Table C.4)")
        elif stringprep.in_table_c5(char):
            out.append(f"{name}: surrogate is prohibited (2.4, Table C.5)")
        elif stringprep.in_table_c8(char):
            out.append(f"{name}: changes display properties or is deprecated (2.4, Table C.8)")
        elif unassigned == "pinned" and stringprep.in_table_a1(char):
            out.append(f"{name}: unassigned in Unicode 3.2 (2.4, Table A.1 of RFC 3454)")
        elif unassigned == "current" and unicodedata.category(char) == "Cn":
            out.append(f"{name}: unassigned in this Unicode version (2.4)")
    return tuple(out)


def insignificant_space(text: str) -> str:
    """RFC 4518 §2.6.1, the attribute-value branch.

    A *space* here is "the SPACE code point followed by no combining marks" (§2.6.1 ¶1), so a SPACE
    with a mark after it is content: it neither joins a run nor counts toward the "contains no
    non-space character" test. Then a value with no non-space character becomes exactly two SPACEs,
    and any other value comes back starting with exactly one SPACE, ending with exactly one SPACE,
    and with **every inner run - even a single space - replaced by two**. That last part is the
    surprise, and it is the RFC's own worked example: ``"foo bar  "`` prepares to ``" foo  bar "``,
    not to ``" foo bar "``.

    The substring branches of ¶4 to ¶9 are not implemented. Distinguished names are compared as
    whole attribute values, and silently applying the whole-value rule where a substring rule was
    asked for would be worse than an explicit absence.
    """

    def is_space(index: int) -> bool:
        return text[index] == " " and not (index + 1 < len(text) and _is_mark(text[index + 1]))

    if all(is_space(index) for index in range(len(text))):
        return "  "

    built: list[str] = []
    run = 0
    for index, char in enumerate(text):
        if is_space(index):
            run += 1
            continue
        if built and run:
            built.append("  ")
        built.append(char)
        run = 0
    return " " + "".join(built) + " "


def preparation_issues(
    text: str, *, fold: bool = True, unassigned: str = "current"
) -> tuple[str, ...]:
    """What the profile would refuse about ``text``, without refusing it.

    The gate runs on the mapped and normalised string, because that is the string §2.4 sees: a code
    point §2.2 maps away is gone before the gate, which is why no Cc or Cf character is ever
    reported here - they are mapped, not prohibited, and the difference matters to anyone trying to
    work out why a name they expected to be refused was accepted.
    """
    return prohibited_characters(prepare_mapped(text, fold=fold), unassigned=unassigned)


def prepare_value(text: str, *, fold: bool = True, unassigned: str = "current") -> str:
    """The whole profile, end to end. Raises `StringPrepError` if §2.4 refuses the input.

    This is the strict reading, for a caller that wants RFC 5280 §7.1 enforced: under the profile a
    value that fails preparation matches nothing, so refusing to return a prepared string is the
    faithful answer. `name.normalize_value` is the tolerant sibling, and keeps a certificate already
    in circulation comparable against its own spelling.
    """
    issues = preparation_issues(text, fold=fold, unassigned=unassigned)
    if issues:
        raise StringPrepError(f"{text!r} cannot be prepared: {issues[0]}", issues=issues)
    return insignificant_space(prepare_mapped(text, fold=fold))
