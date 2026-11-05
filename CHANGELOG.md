# Changelog

All notable changes to this project are documented here. The format follows
Keep a Changelog; this project does not yet claim semantic versioning, because a pre-alpha
package that has not passed its conformance corpus has no API to keep stable.

## Unreleased

Nothing published. This package exists on disk and nowhere else.

### Added

- Project scaffold: `hatchling` build, zero runtime dependencies, `ruff` and `mypy --strict`,
  CI on Linux and Windows across Python 3.12, 3.13 and 3.14, including a run with assertions
  stripped.
- `VECTORS.md` - the conformance corpus: tag boundaries at and above the single-octet limit,
  length forms including the reserved and non-minimal ones, eight truncation cases, the DER
  restrictions BER tolerates, and the round-trip properties that a defect like "discards the
  original bytes" survives untouched.
- `PLAN.md` - the decision record, including **seven defect classes measured by execution
  against the codec this design descends from** (probe: `sdk-forge/probe_ber.py`), among them
  `OverflowError` at every exact power of 256 on encode, tag numbers above 30 decoding to
  wrong values, and an indefinite-length terminator matching `00 00` inside the content.
- `NOTICE` records the MIT-derived architecture and carries the licence text through, as MIT
  requires for substantial portions.

### Pending

The corpus tests are the gate on any release. Until every named case passes, no version
number is assigned and no claim in the README should be read as an endorsement.
