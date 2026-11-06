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
    parse_certificate,
    preparation_issues,
    subject,
    validity,
    validity_encoding_issue,
)
from asn1core.crl import REASON_NAMES, parse_crl  # noqa: E402
from asn1core.name import within  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"

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


def _verify_over_stored(other, tbs: bytes, signature: bytes) -> tuple[str, str]:
    """Ask cryptography to verify a signature over the region asn1core extracted.

    This is the direct test of invariant I3. cryptography has its own view of where
    `tbsCertificate` begins and ends; if it verifies a signature over *our* slice, then our slice
    is the object the CA signed - not an equivalent we produced. It is also the only check here
    that exercises RSA-PSS, ECDSA and Ed25519 signatures rather than just their containers.

    Returns ("ok" | "skip" | "fail", reason). Skipping is honest bookkeeping for certificates this
    machine cannot verify - an MD2 signature, a key type the bindings refuse - and is never
    counted as a pass.
    """
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

    try:
        public = other.public_key()
        digest = other.signature_hash_algorithm
    except (ValueError, UnsupportedAlgorithm) as exc:
        return "skip", f"{type(exc).__name__}: {str(exc)[:50]}"
    if digest is None:
        return "skip", "the profile reports no hash for this signature algorithm"

    pss = other.signature_algorithm_oid.dotted_string.endswith(".1.10")
    try:
        # cryptography's argument order is (signature, data, ...). Passing them the other way is
        # not a type error - both are bytes - it is an InvalidSignature, which is how 73 perfectly
        # good certificates were reported as failing the first time this check ran.
        if isinstance(public, ec.EllipticCurvePublicKey):
            public.verify(signature, tbs, ec.ECDSA(digest))
        elif isinstance(public, ed25519.Ed25519PublicKey):
            public.verify(signature, tbs)
        elif isinstance(public, rsa.RSAPublicKey):
            if pss:
                auto = getattr(padding.PSS, "AUTO", None)
                scheme = padding.PSS(
                    mgf=padding.MGF1(digest),
                    salt_length=auto if auto is not None else padding.PSS.DIGEST_LENGTH,
                )
            else:
                scheme = padding.PKCS1v15()
            public.verify(signature, tbs, scheme, digest)
        else:
            return "skip", f"unhandled key type {type(public).__name__}"
    except InvalidSignature:
        return "fail", "signature does not verify over asn1core's stored tbsCertificate"
    except UnsupportedAlgorithm as exc:
        return "skip", f"{type(exc).__name__}: {str(exc)[:50]}"
    return "ok", ""


def check_fixtures() -> tuple[int, int]:
    """Run the same tests over the repo's generated fixtures, including the CRL.

    The certificate fixture is a self-signed EC document, so its signature can be verified over the
    bytes this package extracted. The CRL matters more, because nothing in a trust store exercises
    it: `cryptography` reads the same file independently, and `tbsCertList`, the entry list and the
    reason codes all have to agree before the signature check means anything.

    Returns (documents checked, failures).
    """
    from cryptography import x509

    checked = 0
    failures = 0

    cert_path = FIXTURES / "ecdsa-padded-r.der"
    crl_path = FIXTURES / "crl-keycompromise.der"
    if not cert_path.is_file() or not crl_path.is_file():
        print("notice: generated fixtures are missing; run sdk-forge/probe_sig_fixture.py")
        return 0, 0

    der = cert_path.read_bytes()
    other = x509.load_der_x509_certificate(der)
    mine = parse_certificate(der)
    checked += 1
    if (
        mine.tbs_certificate != other.tbs_certificate_bytes
        or mine.signature_value != other.signature
    ):
        print("  FAIL ecdsa-padded-r.der: a slice disagrees with cryptography")
        failures += 1
    verdict, why = _verify_over_stored(other, mine.tbs_certificate, mine.signature_value)
    if verdict != "ok":
        print(f"  FAIL ecdsa-padded-r.der: {why}")
        failures += 1

    crl_der = crl_path.read_bytes()
    other_crl = x509.load_der_x509_crl(crl_der)
    crl = parse_crl(crl_der)
    checked += 1
    if crl.tbs_cert_list != other_crl.tbs_certlist_bytes:
        print("  FAIL crl-keycompromise.der: tbsCertList disagrees with cryptography")
        failures += 1
    if crl.signature_value != other_crl.signature:
        print("  FAIL crl-keycompromise.der: signatureValue disagrees with cryptography")
        failures += 1
    # A CRL has no public key of its own - the issuer's lives in its certificate - and this fixture
    # list was issued by the same throwaway CA as the fixture certificate, so that key is the
    # verifier. What is under test is the region being signed, not the crypto.
    from types import SimpleNamespace

    as_issuer = SimpleNamespace(
        public_key=lambda: other.public_key(),
        signature_hash_algorithm=other_crl.signature_hash_algorithm,
        signature_algorithm_oid=other_crl.signature_algorithm_oid,
    )
    verdict, why = _verify_over_stored(as_issuer, crl.tbs_cert_list, crl.signature_value)
    if verdict != "ok":
        print(f"  FAIL crl-keycompromise.der: {why}")
        failures += 1

    theirs = []
    by_name = {name.lower().replace("_", ""): number for number, name in REASON_NAMES.items()}
    # This build's CRL object enumerates entries by iteration; the `revoked_certificates` property
    # that older releases exposed is gone, so the sequence protocol is the version-stable route.
    for revoked in other_crl:
        try:
            flag = revoked.extensions.get_extension_for_class(x509.CRLReason).value.reason
        except x509.ExtensionNotFound:
            reason = None
        else:
            # ReasonFlags carries the §5.3.1 *name* ("key_compromise"), not the ENUMERATED number,
            # so the two readings only agree once the RFC's own numbering arbitrates. A codec that
            # had keyCompromise at 5 would disagree here instead of agreeing twice-wrong.
            reason = by_name[flag.name.lower().replace("_", "")]
        theirs.append((revoked.serial_number, revoked.revocation_date_utc, reason))
    ours = [(entry.serial, entry.revocation_date, entry.reason) for entry in crl.revoked]
    if ours != theirs:
        print(f"  FAIL crl-keycompromise.der: entries {ours} vs cryptography {theirs}")
        failures += 1
    if crl.this_update != other_crl.last_update_utc:
        print(
            f"  FAIL crl-keycompromise.der: thisUpdate {crl.this_update} "
            f"vs cryptography {other_crl.last_update_utc}"
        )
        failures += 1
    if crl.next_update != other_crl.next_update_utc:
        print(
            f"  FAIL crl-keycompromise.der: nextUpdate {crl.next_update} "
            f"vs cryptography {other_crl.next_update_utc}"
        )
        failures += 1
    if [ext.dotted_oid for ext in crl.extensions] != [
        ext.oid.dotted_string for ext in other_crl.extensions
    ]:
        print("  FAIL crl-keycompromise.der: CRL extensions disagree")
        failures += 1

    print(
        f"fixtures cross-checked: {checked} documents, signature verified over stored bytes, "
        f"CRL entries {ours}"
    )
    return checked, failures


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
    sig_verified = 0
    sig_skipped = []
    sig_failed = []
    cert_agreed = 0
    cert_refused = []
    prep_checked = 0
    prep_refused = []

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
            mine_subject = mine_issuer = None
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

            # RFC 4518 preparation over every attribute value in circulation. Two repertoires are
            # asked about, because §2 pins Unicode 3.2 and that differs from current data on
            # 59,842 code points; what matters here is whether shipped names land in the gap.
            for prepared_name in (mine_subject, mine_issuer):
                for rdn in prepared_name.rdnsets:
                    for attr in rdn:
                        prep_checked += 1
                        for flavour in ("current", "pinned"):
                            issues = preparation_issues(attr.value, unassigned=flavour)
                            if issues:
                                prep_refused.append(
                                    (path.name[:24], flavour, attr.value[:24], issues[0][:60])
                                )

        # The signature itself, over the bytes this package extracted. Only self-issued documents
        # can be checked this way: six entries in the machine's Root store are cross-certificates,
        # issued by a different CA than the one whose key they carry, and verifying those against
        # their own subject key fails for a reason that has nothing to do with the codec.
        if mine_issuer is not None and mine_subject is not None and mine_issuer == mine_subject:
            verdict, why = _verify_over_stored(other, parts.tbs_certificate, parts.signature_value)
        else:
            verdict, why = "skip", "cross-certificate: not self-issued"
        if verdict == "ok":
            sig_verified += 1
        elif verdict == "skip":
            sig_skipped.append((path.name[:24], why))
        else:
            print(f"  FAIL {path.name[:24]}: {why}")
            sig_failed.append((path.name[:24], why))
            failures += 1

        # The certificate's contents - serial, version, signature algorithm and the extension list
        # with its critical flags - against cryptography's reading of the same document. This is
        # where a slot found at the wrong index shows up: the extension list in particular, since a
        # unique identifier ahead of it shifts every position.
        try:
            mine_cert = parse_certificate(der)
        except Asn1Error as exc:
            cert_refused.append((path.name[:24], f"{type(exc).__name__}: {exc}"))
        else:
            mine_exts = [(ext.dotted_oid, ext.critical) for ext in mine_cert.extensions]
            theirs_exts = [(ext.oid.dotted_string, ext.critical) for ext in other.extensions]
            if (
                mine_cert.serial != other.serial_number
                or mine_cert.version != other.version.value
                or ".".join(map(str, mine_cert.signature_algorithm))
                != other.signature_algorithm_oid.dotted_string
                or mine_exts != theirs_exts
            ):
                print(
                    f"  FAIL {path.name[:24]}: certificate contents disagree "
                    f"(serial {mine_cert.serial == other.serial_number}, "
                    f"version {mine_cert.version} vs {other.version.value}, "
                    f"extensions {len(mine_exts)} vs {len(theirs_exts)})"
                )
                failures += 1
            else:
                cert_agreed += 1

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
    print(
        f"signatures verified over asn1core's stored tbsCertificate={sig_verified}, "
        f"skipped={len(sig_skipped)}, failed={len(sig_failed)}"
    )
    print(
        f"certificate contents (serial, version, algorithm, extensions) agreed={cert_agreed}, "
        f"refused={len(cert_refused)}"
    )
    print(
        f"attribute values prepared={prep_checked}, refused by RFC 4518 2.4={len(prep_refused)} "
        "(both repertoires)"
    )
    for name, flavour, value, why in prep_refused[:10]:
        print(f"  preparation refuses: {name} [{flavour}] {value!r} :: {why}")
    for name, why in cert_refused[:10]:
        print(f"  certificate refused: {name} :: {why}")
    for name, why in sig_skipped[:10]:
        print(f"  signature not verifiable here: {name} :: {why}")
    for name, why in name_refused[:10]:
        print(f"  name refused: {name} :: {why}")
    for name, ours, theirs_len in spki_reencode[:10]:
        print(f"  differs: {name} ours={theirs_len} theirs={ours}")
    for name, why in time_refused[:10]:
        print(f"  time refused: {name} :: {why}")
    for name, why in profile_issues[:10]:
        print(f"  profile: {name} :: {why}")

    fixture_checked, fixture_failures = check_fixtures()
    failures += fixture_failures
    print(f"fixtures checked={fixture_checked}")
    print(f"failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
