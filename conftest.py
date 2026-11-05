"""Make the project root importable when pytest is run from anywhere.

The package lives at the repository root, so with this file present pytest inserts that root
on sys.path and importing asn1core works however the test command was invoked - including
from a bare `python -O -m pytest` in CI, where the stripped-assertions run is the one that
matters most for a parser.
"""
