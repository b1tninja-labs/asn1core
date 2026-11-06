"""RFC 4518 string preparation: `dk.stringprep`, with every expectation taken from the document.

Nothing here is derived from what the code does. Each expectation is quoted or worked through from
the RFC text in a comment, and the errata that change behaviour - 860, which fixes a mapping range
printed backwards, and 7658, which fixes the RFC 5280 pointer to §2.6.1 - are asserted explicitly,
because a reader working from the published text alone would get both wrong.

The one place this file argues rather than quotes is the ordering of Map and Normalize, which §2
settles by listing Map first: `map_characters` alone turns U+2126 OHM SIGN into U+03C9 (case fold),
while `normalize` alone turns it into U+03A9 GREEK CAPITAL LETTER OMEGA. Both answers come out the
same at the end of the pipeline for most input - measured as identical on all 577 attribute values
in the local trust store - but the intermediate is the specification's, and the test says so.
"""

from __future__ import annotations

import pytest

from asn1core import (
    StringPrepError,
    insignificant_space,
    map_characters,
    normalize_value,
    preparation_issues,
    prepare_value,
    prohibited_characters,
)
from asn1core.stringprep import normalize

# --- 2.6.1 insignificant space handling, the rule everyone gets wrong ----------------------


def test_the_rfc_worked_example() -> None:
    """2.6.1: "foo<SPACE>bar<SPACE><SPACE>" gives "<SPACE>foo<SPACE><SPACE>bar<SPACE>"."""
    assert prepare_value("foo bar  ") == " foo  bar "


def test_a_single_inner_space_becomes_two() -> None:
    """Not a typo in the test: an inner run of one becomes two, because the rule is "two"."""
    assert prepare_value("foo bar") == " foo  bar "


def test_a_value_with_no_nonspace_character_is_exactly_two_spaces() -> None:
    assert insignificant_space("") == "  "
    assert insignificant_space("     ") == "  "
    # NO-BREAK SPACE is a separator, so 2.2 has already mapped it to SPACE by this point.
    assert prepare_value("\u00a0\u00a0") == "  "


def test_leading_and_trailing_runs_collapse_to_one_each() -> None:
    assert prepare_value("   Paris   ") == " paris "
    assert prepare_value("Paris") == " paris "


def test_a_space_followed_by_a_combining_mark_is_content_not_space() -> None:
    """2.6.1 ¶1: "a space is SPACE followed by no combining marks".

    So a marked space is ordinary content: it does not join a run, and it does not count toward the
    "contains no non-space character" test. A string of nothing but a marked space therefore takes
    the second branch, and ¶3 still adds exactly one SPACE at each end - which is why the result has
    two spaces at the front: the inserted one, then the content one that carries the mark.
    """
    assert insignificant_space("a\u0301") == " a\u0301 "
    assert insignificant_space(" \u0300") == "  \u0300 "
    assert insignificant_space("a \u0300") == " a \u0300 "


# --- 2.2 Map -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "\u00ad",  # SOFT HYPHEN (2.2 ¶1)
        "\u1806",  # MONGOLIAN TODO SOFT HYPHEN (¶1)
        "\u034f",  # COMBINING GRAPHEME JOINER (¶1)
        "\u180b",  # MONGOLIAN VARIATION SELECTOR ONE (¶1)
        "\ufe0f",  # VARIATION SELECTOR-16 (¶1 as corrected by erratum 860)
        "\ufffc",  # OBJECT REPLACEMENT CHARACTER (¶1)
        "\u200b",  # ZERO WIDTH SPACE (¶4: to nothing, and pointedly not to SPACE)
        "\ufeff",  # ZERO WIDTH NO-BREAK SPACE (¶3)
        "\u0000",  # C0 control (¶3)
        "\u001f",  # last of the second C0 run (¶3)
        "\u007f",  # DEL (¶3)
        "\u0086",  # first of the C1 run that resumes after NEL (¶3)
        "\u06dd",  # ARABIC KASRATAN THREE DOT POINTS ABOVE (¶3)
        "\u202e",  # RIGHT-TO-LEFT OVERRIDE: a bidi control, mapped away rather than prohibited
        "\u2060",  # WORD JOINER (¶3)
        "\ufff9",  # INTERLINEAR ANNOTATION ANCHOR (¶3)
        "\U0001d173",  # MUSICAL SYSTEM BEGIN BAR LINE (¶3)
        "\U000e0020",  # LANGUAGE TAG (¶3)
    ],
)
def test_mapped_to_nothing_disappears(text: str) -> None:
    assert map_characters(f"a{text}b") == "ab"


@pytest.mark.parametrize(
    "text",
    [
        "\u0009",  # CHARACTER TABULATION (¶2: to SPACE, not to nothing)
        "\u000a",  # LINE FEED (¶2)
        "\u000b",  # LINE TABULATION (¶2)
        "\u000c",  # FORM FEED (¶2)
        "\u000d",  # CARRIAGE RETURN (¶2)
        "\u0085",  # NEXT LINE (¶2, inside the control ranges that go to nothing)
        "\u00a0",  # NO-BREAK SPACE (¶4: Zs to SPACE)
        "\u1680",  # OGHAM SPACE MARK (¶4)
        "\u2000",  # EN QUAD, first of the U+2000-200A run (¶4)
        "\u2028",  # LINE SEPARATOR, class Zl (¶4)
        "\u2029",  # PARAGRAPH SEPARATOR, class Zp (¶4)
        "\u3000",  # IDEOGRAPHIC SPACE (¶4)
    ],
)
def test_mapped_to_space_becomes_a_space(text: str) -> None:
    assert map_characters(f"a{text}b") == "a b"


def test_nel_is_a_space_and_its_neighbours_are_nothing() -> None:
    """¶2 pulls U+0085 out of the ¶3 control run; U+0084 and U+0086 stay inside it."""
    assert map_characters("a\u0085b") == "a b"
    assert map_characters("a\u0084b") == "ab"
    assert map_characters("a\u0086b") == "ab"


def test_case_folding_is_full_and_happens_inside_the_map_step() -> None:
    """¶5 folds per RFC 3454 B.2, which is full folding: sharp s becomes two s."""
    assert map_characters("STRASSE") == "strasse"
    assert map_characters("Stra\u00dfe") == "strasse"


def test_the_map_step_runs_before_normalisation() -> None:
    """§2 orders Map (2.2) before Normalize (2.3), and the OHM SIGN shows the difference."""
    assert map_characters("\u2126") == "\u03c9"  # folded: Greek small letter omega
    assert normalize("\u2126") == "\u03a9"  # normalised on its own, it is the capital


def test_fullwidth_forms_survive_the_map_where_the_printed_text_would_have_deleted_them() -> None:
    """Erratum 860: §2.2 prints "FF00-FE0F"; the verified correction is FE00-FE0F.

    Read upward, the printed range covers U+FF00 to U+FF60 - every fullwidth Latin letter and
    halfwidth katakana - so a name spelled in fullwidth, which is how CJK DirectoryString values are
    often written, would quietly lose its characters in the Map step with nothing raised anywhere.
    That is the same class of damage as the retracted OID first-arc rule: a table copied wrongly,
    rejecting the bulk of real input. U+FF21 is assigned in Unicode 3.2 too, so no other step would
    have caught it either.
    """
    assert map_characters("\uff21\uff22", fold=False) == "\uff21\uff22"
    assert map_characters("\uff21\uff22") == "\uff41\uff42"
    assert prepare_value("\uff21\uff22") == " \uff41\uff42 "
    assert map_characters("\ufe0f") == ""  # the range the erratum actually names


# --- 2.4 Prohibit --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "table"),
    [
        ("\ufffd", "REPLACEMENT CHARACTER"),  # 2.4 ¶6, named in the text itself
        ("\ue000", "Table C.3"),  # private use
        ("\ufdd0", "Table C.4"),  # non-character
        ("\ufffe", "Table C.4"),  # and the other end of the same rule
        ("\ud800", "Table C.5"),  # surrogate, reachable in a str only via a tolerant decoder
        ("\u0340", "Table C.8"),  # deprecated, but see the NFC test below
    ],
)
def test_prohibited_code_points_are_named_by_their_table(text: str, table: str) -> None:
    issues = prohibited_characters(text)
    assert len(issues) == 1
    assert table in issues[0]


def test_prepare_value_refuses_what_the_profile_refuses() -> None:
    with pytest.raises(StringPrepError, match="private use"):
        prepare_value("Exam\ue000ple")
    with pytest.raises(StringPrepError) as caught:
        prepare_value("\ufffd\ufffd")
    assert len(caught.value.issues) == 2, "every refused code point, not just the first"


def test_the_unassigned_test_differs_by_unicode_version_and_says_so() -> None:
    """U+0237 DOTLESS J is assigned today and unassigned in the pinned Unicode 3.2 table.

    §2 says the repertoire is Unicode 3.2, which read literally prohibits 59,842 code points that
    Unicode has assigned since, ordinary letters among them. The default follows current data; the
    pinned behaviour is available and reports which table it used.
    """
    assert prepare_value("\u0237") == " \u0237 "
    with pytest.raises(StringPrepError, match=r"Unicode 3\.2"):
        prepare_value("\u0237", unassigned="pinned")
    # Unassigned in both, so neither choice rescues it.
    with pytest.raises(StringPrepError):
        prepare_value("\u0378")
    with pytest.raises(StringPrepError):
        prepare_value("\u0378", unassigned="pinned")


def test_an_invalid_repertoire_choice_is_a_programming_error_not_a_profile_answer() -> None:
    with pytest.raises(ValueError, match="unassigned must be"):
        prohibited_characters("a", unassigned="whatever")


def test_table_c8_is_unreachable_through_the_pipeline_because_nfc_gets_there_first() -> None:
    """U+0340 and U+0341 are the only C.8 members §2.2 leaves alive, and both decompose canonically.

    Every other C.8 entry is Cc or Cf and is mapped to nothing in 2.2, so it never reaches the gate;
    these two have canonical decompositions, so 2.3 rewrites them to U+0300 and U+0301 before 2.4
    runs. The rule is implemented anyway - a caller can invoke `prohibited_characters` directly, as
    the test above does - but the composition cannot refuse them, and this test is the record of why.
    """
    assert normalize("\u0340") == "\u0300"
    assert prohibited_characters("\u0340") != ()  # refused when handed over directly
    assert preparation_issues("\u0340") == ()  # never seen, because NFC already replaced it
    # And NFC goes on to compose the result with the letter before it: "a" + U+0300 is U+00E0.
    assert prepare_value("a\u0340b") == " \u00e0b "


# --- 2.5 bidi, which is not a check ---------------------------------------------------------


def test_the_profile_ignores_bidi_characters_rather_than_checking_them() -> None:
    """2.5, in full: "Bidirectional characters are ignored".

    RFC 3454 StringPrep runs a bidi *check*; this profile does not, and does not need one. The
    direction controls are Cf characters that §2.2 maps to nothing - and Table C.8 lists them too,
    measured on U+200F and U+202E, so the gate would refuse them if they ever reached it, which
    Map ensures they do not. What the profile declines to reject is the Hebrew or Arabic text
    itself, which an implementation copied from RFC 3454 rather than from RFC 4518 would turn down
    on first-strong grounds.
    """
    assert prepare_value("\u05d0\u202e\u05d1") == " \u05d0\u05d1 "
    assert preparation_issues("\u202a\u05d1\u202c") == ()
    assert prohibited_characters("\u200f") != ()  # prohibited, but Map has already removed it


# --- the two entry points, and why there are two -------------------------------------------


def test_normalize_value_is_total_where_prepare_value_is_strict() -> None:
    """Comparison must not be able to fail on a certificate that is already in circulation."""
    odd = "Example \ufffd Ltd"
    assert normalize_value(odd) == " example  \ufffd  ltd "
    assert len(preparation_issues(odd)) == 1
    with pytest.raises(StringPrepError):
        prepare_value(odd)


def test_preparation_still_unifies_the_spellings_that_should_match() -> None:
    for left, right in (
        ("Paris", " PARIS "),
        ("Gro\u00dfe Stra\u00dfe", "GROSSE STRASSE"),
        ("\u00dcber\u00a0Stra\u00dfe", "\u00dcBER  STRASSE"),
        ("Soft\u00adhyphen", "SOFTHYPHEN"),
    ):
        assert normalize_value(left) == normalize_value(right), (left, right)
