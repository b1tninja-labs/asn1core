#!/usr/bin/env python3
"""Check the certificate structure walk against an implementation nobody here authored.

`tools/crosscheck_store.py` proves the codec frames real certificates correctly. This proves the
layer above it picks the *right objects* out of them, which framing cannot show: an off-by-one
from the optional version would still parse, still round-trip, and hand back the wrong child.
The second opinion is `cryptography` (RFC-authored bindings to OpenSSL), used for three things:

- `tbsCertificate` bytes - `cert.tbs_certificate_bytes`, the stored encoding, so any difference is
  a real disagreement about where the object starts and ends;
- `signatureValue` bytes - `cert.signature`;
- the SPKI - `public_bytes(DER, SubjectPublicKeyInfo)`, which is a **re-encoding** rather than the
  stored bytes, so disagreement here is evidence to read rather than a failure: it appears exactly
  when a key cannot be re-encoded the way it was issued, which is the thing invariant I3 exists to
  survive.

Run: `python tools/crosscheck_x509.py`. Windows only; exits 0 with a notice elsewhere rather than
pretending to have checked something. `cryptography` is needed; without it the run says so.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from asn1core import (  # noqa: E402
    Asn1Error,
    Name,
    certificate_parts,
    issuer,
    subject,
    validity,
    validity_encoding_issue,
)
from asn1core.name import within  # noqa: E402

STORES = ("Cert:\\LocalMachine\\Root", "Cert:\\LocalMachine\\CA", "Cert:\\CurrentUser\\Root")

# cryptography exposes Version as a plain enum, so names are the stable way to read it.
_VERSION_BY_NAME = {"v1": 0, "v2": 1, "v3": 2}

_DUMP = """
$ErrorActionPreference = 'SilentlyContinue'
$dest = '{dest}'
foreach ($store in @({stores})) {{
    Get-ChildItem $store | ForEach-Object {{
        $file = Join-Path $dest ($_.Thumbprint + '.der')
        [IO.File]::WriteAllBytes($file, $_.RawData)
    }}
}}
"""


def collect(dest: pathlib.Path) -> list[pathlib.Path]:
    if shutil.which("powershell") is None and shutil.which("pwsh") is None:
        return []
    script = _DUMP.format(dest=str(dest), stores=", ".join(f"'{s}'" for s in STORES))
    subprocess.run(  # noqa: S603 - fixed script text, no user input
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],  # noqa: S607
        check=True,
        capture_output=True,
        timeout=120,
    )
    return sorted(dest.glob("*.der"))


def main() -> int:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError:
        print("cryptography is not installed; nothing cross-checked (this is not a pass)")
        return 0

    paths = collect(pathlib.Path(tempfile.mkdtemp(prefix="x509_cross_")))
    if not paths:
        print("no certificates exported; nothing cross-checked (this is not a pass)")
        return 0

    failures = 0
    checked = 0
    spki_agreed = 0
    spki_reencode = []
    spki_unreadable = 0
    time_agreed = 0
    time_refused = []
    profile_issues = []
    names_agreed = 0
    name_refused = []

    for path in paths:
        der = path.read_bytes()
        try:
            other = x509.load_der_x509_certificate(der)
            parts = certificate_parts(der)
        except (Asn1Error, ValueError) as exc:
            print(f"  FAIL {path.name[:24]}: {type(exc).__name__}: {exc}")
            failures += 1
            continue

        checked += 1
        if parts.tbs_certificate != other.tbs_certificate_bytes:
            print(f"  FAIL {path.name[:24]}: tbsCertificate disagrees with cryptography")
            failures += 1
        if parts.signature_value != other.signature:
            print(f"  FAIL {path.name[:24]}: signatureValue disagrees with cryptography")
            failures += 1
        if parts.raw != der or parts.tbs_certificate not in der:
            print(f"  FAIL {path.name[:24]}: a part is not the stored slice")
            failures += 1

        # An absent version field means v1, and cryptography names the same document Version.v1,
        # so the two are comparable - the check that catches a walk which skipped the version slot
        # on a document that had one, or invented one on a document that did not.
        ours_version = 0 if parts.version is None else parts.version
        theirs_version = _VERSION_BY_NAME.get(getattr(other.version, "name", ""))
        if theirs_version is None:
            print(f"  notice: {path.name[:24]}: unrecognised version spelling {other.version!r}")
        elif ours_version != theirs_version:
            print(
                f"  FAIL {path.name[:24]}: version {parts.version!r} means {ours_version}, "
                f"not {theirs_version}"
            )
            failures += 1

        # The dates. Two things are measured here, and the second one is the reason this block
        # exists: strictness that a shipped trust anchor trips would be the OID first-arc mistake
        # all over again, so a refusal on real input is reported for judgement, not celebrated.
        try:
            window = validity(der)
            issue = validity_encoding_issue(der)
        except Asn1Error as exc:
            time_refused.append((path.name[:24], f"{type(exc).__name__}: {exc}"))
        else:
            if issue is not None:
                profile_issues.append((path.name[:24], issue))
            if (
                window.not_before == other.not_valid_before_utc
                and window.not_after == other.not_valid_after_utc
            ):
                time_agreed += 1
            else:
                print(
                    f"  FAIL {path.name[:24]}: validity {window.not_before!r}..{window.not_after!r} "
                    f"vs cryptography {other.not_valid_before_utc!r}..{other.not_valid_after_utc!r}"
                )
                failures += 1

        # Distinguished names. The rendering is compared character by character against
        # cryptography's RFC 4514 output, and the equality relation is cross-checked by comparing
        # our verdict on subject==issuer with theirs for the same certificate.
        try:
            mine_subject, mine_issuer = subject(der), issuer(der)
        except Asn1Error as exc:
            name_refused.append((path.name[:24], f"{type(exc).__name__}: {exc}"))
        else:
            for label, ours, theirs in (
                ("subject", mine_subject, other.subject),
                ("issuer", mine_issuer, other.issuer),
            ):
                if ours.rfc4514() == theirs.rfc4514_string():
                    names_agreed += 1
                else:
                    print(f"  FAIL {path.name[:24]}: {label} renders differently")
                    print(f"       ours : {ours.rfc4514()}")
                    print(f"       theirs: {theirs.rfc4514_string()}")
                    failures += 1
            if (mine_subject == mine_issuer) != (other.subject == other.issuer):
                # Name.__eq__ on both sides: if we disagree about whether a root is self-signed,
                # one of the two equality relations is wrong.
                print(f"  FAIL {path.name[:24]}: self-signed verdict disagrees")
                failures += 1
            if within(mine_subject, Name(rdnsets=mine_subject.rdnsets[:1], raw=b"")) is not True:
                print(f"  FAIL {path.name[:24]}: a name is not within its own root")
                failures += 1

        try:
            theirs = other.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
        except ValueError:
            # Key material cryptography cannot re-serialise at all: explicit parameters, or a
            # curve its bindings do not cover. Nothing to compare against, and saying so is the
            # honest result - these are the certificates where stored bytes are the only truth.
            spki_unreadable += 1
            continue
        if theirs == parts.subject_public_key_info:
            spki_agreed += 1
        else:
            spki_reencode.append((path.name[:24], len(theirs), len(parts.subject_public_key_info)))

    print(
        f"certificates={checked} tbs+signature agreed, spki byte-identical={spki_agreed}, "
        f"spki re-encoded differently={len(spki_reencode)}, "
        f"spki unreadable-by-cryptography={spki_unreadable}"
    )
    print(
        f"validity dates agreed with cryptography={time_agreed}, "
        f"refused by the strict time reader={len(time_refused)}, "
        f"spelled against §4.1.2.5={len(profile_issues)}"
    )
    print(
        f"names rendered identically={names_agreed}, refused by the name parser={len(name_refused)}"
    )
    for name, why in name_refused[:10]:
        print(f"  name refused: {name} :: {why}")
    for name, ours, theirs_len in spki_reencode[:10]:
        print(f"  differs: {name} ours={theirs_len} theirs={ours}")
    for name, why in time_refused[:10]:
        print(f"  time refused: {name} :: {why}")
    for name, why in profile_issues[:10]:
        print(f"  profile: {name} :: {why}")
    print(f"failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
