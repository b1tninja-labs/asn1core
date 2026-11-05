#!/usr/bin/env python3
"""Assert the built distribution ships what the documentation promises.

Run after a wheel build (``python -m build`` then this). A docs claim about a packaged file
is a promise to the reader, and a promise nothing checks gets broken silently - which for
NOTICE is not a cosmetic problem, because MIT's only condition is that its text travels with
substantial portions of the software it covers.
"""

from __future__ import annotations

import pathlib
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
PKG = "asn1core"
REQUIRED = (
    "README.md",
    "PLAN.md",
    "VECTORS.md",
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
    "CHANGELOG.md",
)
# The architecture here is derived from snmpy's ber package, which is MIT. If the
# attribution ever stops shipping, that is a licence breach, not a packaging nit.
MUST_MENTION = ("snmpy Contributors", "MIT License")


def main() -> int:
    wheels = sorted((ROOT / "dist").glob("*.whl"))
    if not wheels:
        print("no wheel in dist/: run python -m build first")
        return 1
    with zipfile.ZipFile(wheels[-1]) as wheel:
        names = set(wheel.namelist())

    problems: list[str] = []
    if PKG + "/py.typed" not in names:
        problems.append(PKG + "/py.typed missing from the wheel")
    problems += [
        f + " missing from the repository root" for f in REQUIRED if not (ROOT / f).exists()
    ]

    notice = ROOT / "NOTICE"
    if notice.exists():
        text = notice.read_text(encoding="utf-8")
        problems += [
            f"NOTICE no longer contains {phrase!r}" for phrase in MUST_MENTION if phrase not in text
        ]

    for item in problems:
        print("problem:", item)
    print(f"{wheels[-1].name}: {len(names)} entries, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
