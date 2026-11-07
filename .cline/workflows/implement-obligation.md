---
description: Implement one PLAN.md obligation, correctly and verifiably
---

Implement the next unchecked row of `PLAN.md` in this project. The obligation table is
`PLAN.md`; `VECTORS.md` is the conformance corpus and is the exit test, so a row and a
corpus expectation are usually the same piece of work.

This project is not an RFC project, and the runbook other repositories carry is wrong for
it in one important respect: the normative source for BER and DER is **ITU-T X.680 and
X.690, which are not in the RFC series**, so `rfclib` cannot answer a question about tag
numbers, length forms or DER canonicalisation.

1. Read the row and quote its basis and evidence cells back. Name the clause the behaviour
   comes from before writing anything.

2. Get the clause from `D:\code\itulibrary`, from its own venv, the way you would ask
   rfclib:

       python -m itulib.cli read X.690 8.19.4
       python -m itulib.cli search X.680 "PrintableString"
       python -m itulib.cli grep X.690 "indefinite length"

   **Cite the edition.** Rules move between them, and this package's citations name
   02/2021. If the clause does not state what the row claims, the row is wrong: fix the row
   and say so in the commit. Three rules in this repository turned out to be stated from
   memory before this route was used - a UTCTime bound that does not exist, an
   indefinite-length question that had in fact been settled, and a band of DN tag numbers
   four places low - so "I remember X.690 says" is the failure mode this step exists to stop.

   `rfclib` remains the authority for the parts that genuinely are RFCs, chiefly
   RFC 5280 §4.1.1.3, the reason `Node.raw` exists: `rfclib.info("RFC5280")` for status and
   errata, `rfclib.read("RFC5280§4.1.1.3", view="normative")` for the text,
   `rfclib.grep(...)` instead of guessing a section number.

3. Write the test first, against a recorded vector rather than a generated expectation, and
   run it to watch it fail. Expectations come from the encoding rule, never from what this
   codec currently does - invariant 7. Add the corresponding line to `VECTORS.md` when the
   row is a corpus row.

4. Implement the minimum that makes it pass. BER tolerates, DER refuses, and the refusal is
   named: never normalise a non-canonical document into a canonical one, because that gives
   one certificate two identities. A bound read from the wire is compared against the bytes
   present before it is used as a size. No bounds check may be an `assert`: CI runs under
   `python -O`, where library asserts vanish while test asserts survive, and
   `test_library_contains_no_assert_statements` enforces that against the AST.

5. Flip the row only when the named test exists and passes, and name the test in the row.
   A row that `[part]` says is cited-but-untested stays `[part]` until a test exists; the
   status column is a claim about evidence, not about effort.

6. Run every gate listed in `AGENTS.md`, from this directory, and fix what fails:
   `python -m pytest -q --cov`, `python -O -m pytest -q`, `python -m ruff check .`,
   `python -m ruff format --check .`, `python -m mypy asn1core tests`, and
   `python tools/crosscheck_store.py`, which is the check against real certificates rather
   than against this code. Never run a formatter from above this directory.

7. Commit with the clause citation - recommendation number, edition, clause - in the message
   body, and the `rfclib.cite` citation when an RFC was read. No `Co-Authored-By` trailer.

Two things this project keeps deliberately, so a well-meaning agent does not "fix" them:
`NOTICE` must keep carrying the MIT text it derives from snmpy (`tools/check_dist.py` fails
the build if it goes), and the two generated fixtures carry no digest on purpose, because
each run makes fresh key material.
