# Instructions for coding agents

**This directory contains a plan, not a library.** There is no package, no `pyproject.toml`,
no test suite, and no command in this directory that will run. Do not invent one. Wave 1 of
`D:\code\PORTFOLIO.md` schedules when code appears here.

## Read in this order

1. `PLAN.md` - what is being extracted, the four defects that must be fixed rather than
   moved, and the raw-bytes retention requirement that makes this a rewrite of behaviour
   rather than a copy.
2. `VECTORS.md` - the conformance corpus. It is the exit test. Every case has an expected
   verdict derived from the encoding rule, not from observed output.
3. `D:\code\PORTFOLIO.md` section 6 - nine projects are blocked behind this one.

## Where the specification lives, and where it does not

The normative source for BER and DER is **ITU-T X.680 and X.690, which are not in the RFC
series**. `rfclib` cannot answer a question about tag-number encoding or the DER
canonicalisation rules, and inventing an RFC number for X.690 is a mistake this portfolio has
already made once in the other direction.

Use `rfclib` for the parts that genuinely are RFCs:

- `rfclib.read("RFC5280§4.1.3.2", view="normative")` - why a signature must be verified over
  the DER encoding, which is the whole reason this codec must retain original bytes.
- `rfclib.info("RFC5280")` before citing it - it is a Proposed Standard with **6 verified
  errata** and nine updating documents.
- `rfclib.grep("RFC5280", pattern="keyCompromise")` finds the reason codes in §5.3.1 rather
  than guessing a section number.
- Cite with `rfclib.cite(...)`; never paraphrase normative text into a docstring.

Rules quoted from memory in `VECTORS.md` are marked `[verify against X.690]`. Resolve those
against the ITU text or a second independent implementation **before** writing the test that
asserts them. A wrong expectation in a conformance corpus is worse than no test, because it
becomes the thing future code is bent to match.

## Invariants

1. **Retain the original bytes.** Any decode that cannot return the exact input TLV for a
   node is a defect here, not a design choice.
2. **BER tolerates, DER refuses, and the refusal is named.** Never collapse "non-canonical"
   into "accepted". Empty, absent, unknown and zero stay distinct.
3. **Bounds checks are not `assert` statements.** CI runs the suite under `python -O`, which
   strips asserts and would silently delete them.
4. **A new dependency needs a paragraph of justification.** This is a codec; the standard
   library plus OpenSSL for the optional crypto extra is the intended surface.
5. **No roadmap row moves to done without its named test passing.** The obligation table in
   `PLAN.md` is the work queue.
