#!/usr/bin/env python3
"""Verify an AI Safety Compliance Lab evidence file offline.

    python verify_evidence.py ai-safety-run-xxxxxxxx.json
    python verify_evidence.py ai-safety-run-xxxxxxxx.json --key <public_key_b64>

Checks, in order:
  1. The SHA-256 of the record the server hashed equals the file's artifact_hash
     (the record has not been edited since the run).
  2. The Ed25519 signature over that hash is valid for the PUBLISHED public key
     (the record came from the AI Safety Compliance Lab server).
  3. If the file carries an RFC 3161 timestamp from a public Time Stamp Authority, the token is
     saved next to the file (.tsr) and, when OpenSSL is installed, checked with it: this shows the
     record existed at that time, independently of this server.

The public key is fetched from https://projectaisafety.com/api/v1/signing-key unless you pass
--key, for example a copy of the key you saved earlier, so you can verify with no network at all.
Never trust the key inside the evidence file on its own: anyone editing the file could replace it.

Requires Python 3.9+ and the 'cryptography' package (pip install cryptography).
"""
import argparse
import base64
import hashlib
import json
import re
import os
import shutil
import subprocess
import sys
import urllib.request

KEY_URL = "https://projectaisafety.com/api/v1/signing-key"
PREFIX = "ai-safety-compliance-lab:run-record:v1:"
SELFHOSTED_PREFIX = "ai-safety-compliance-lab:selfhosted-record:v1:"   # self-hosted edition runs


def fail(msg: str) -> None:
    print(f"FAILED: {msg}")
    sys.exit(1)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("evidence", help="evidence JSON file downloaded from the dashboard")
    ap.add_argument("--key", help="published public key (base64); fetched from the site if omitted")
    args = ap.parse_args()

    with open(args.evidence, "r", encoding="utf-8") as f:
        doc = json.load(f)
    run = doc.get("data", doc)
    artifact_hash = run.get("artifact_hash", "")

    canonical = run.get("hashed_record_json")
    if canonical is None:
        fail("this evidence file has no hashed_record_json (an older, unsigned format).")
    if hashlib.sha256(canonical.encode("utf-8")).hexdigest() != artifact_hash:
        fail("the hashed record does not match artifact_hash: the record was changed after the run.")
    print(f"OK  record hash matches artifact_hash {artifact_hash}")

    sig = run.get("signature")
    if not sig:
        fail("the evidence is not signed (the server had signing switched off for this run).")
    msg = str(sig.get("signed_message") or "")
    m = re.fullmatch(re.escape(SELFHOSTED_PREFIX + artifact_hash) + r":([A-Za-z0-9_-]{12})", msg)
    if msg != PREFIX + artifact_hash and not m:
        fail("the signed message does not refer to this record's hash.")
    if m:
        claimed = (json.loads(canonical).get("edition") or {}).get("licensee")
        print(f"--  self-hosted run under licence {m.group(1)} (signed)"
              + (f"; the record names the licensee as {claimed}" if claimed else "")
              + ". It was executed on the licensee's own infrastructure: the signature shows the record existed "
              "when signed and is unchanged, not how the run was carried out.")

    if args.key:
        published = args.key.strip()
    else:
        with urllib.request.urlopen(KEY_URL, timeout=15) as r:
            info = json.load(r)
        if not info.get("enabled"):
            fail("the server reports that signing is not enabled.")
        published = info["public_key_b64"]
        print(f"OK  fetched published key {info['key_id']} from {KEY_URL}")
    if sig.get("public_key_b64") != published:
        fail("the evidence was signed with a different key from the published one.")

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(published)).verify(
            base64.b64decode(sig["signature_b64"]), sig["signed_message"].encode("utf-8"))
    except InvalidSignature:
        fail("the signature is not valid.")
    print(f"OK  Ed25519 signature valid (key {sig.get('key_id')})")

    check_timestamp(run, artifact_hash, args.evidence)

    rec = json.loads(canonical)
    print(f"\nVERIFIED. Run {rec.get('run_id')} at {rec.get('timestamp')}: model {rec.get('target_model')}, "
          f"suite {rec.get('suite_id')}, status {rec.get('status')}, {len(rec.get('vectors', []))} tests.")
    suite = rec.get("suite") if isinstance(rec.get("suite"), dict) else {}
    if suite.get("sha256"):
        origin = suite.get("origin", "unknown")
        if origin == "generated":
            origin = "generated for this app" + (f" by {suite['generator_model']}" if suite.get("generator_model") else "") \
                + (", edited before running" if suite.get("edited_after_draft") else "")
        print(f"    Suite: {origin}; SHA-256 {suite['sha256']}")


def check_timestamp(run: dict, artifact_hash: str, evidence_path: str) -> None:
    ts = run.get("trusted_timestamp")
    if not ts:
        return
    if ts.get("status") != "timestamped" or ts.get("message_imprint") != artifact_hash or not ts.get("token_b64"):
        print(f"--  not independently timestamped ({ts.get('reason') or 'no token for this hash'})")
        return
    tsr = os.path.splitext(evidence_path)[0] + ".tsr"
    with open(tsr, "wb") as f:
        f.write(base64.b64decode(ts["token_b64"]))
    # The time and authority written beside the token in the file are not signed with the record, so
    # they are only reported as the file's claim; OpenSSL reads the real time from the token itself.
    print(f"--  RFC 3161 timestamp token saved as {tsr} (the file states {ts.get('gen_time')} from "
          f"{ts.get('authority')}; not checked yet)")
    openssl = shutil.which("openssl")
    if not openssl:
        print(f"    To check it, install OpenSSL and run: openssl ts -verify -digest {artifact_hash} -in {tsr} "
              f"-CAfile <the authority's root certificate>")
        return
    certs = ""
    try:
        out = subprocess.run([openssl, "version", "-d"], capture_output=True, text=True, timeout=10).stdout
        certs = os.path.join(out.split('"')[1], "certs") if '"' in out else ""
    except Exception:  # noqa: BLE001
        pass
    cmd = [openssl, "ts", "-verify", "-digest", artifact_hash, "-in", tsr] + (["-CApath", certs] if certs else [])
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if r.returncode == 0 and "Verification: OK" in r.stdout:
        print("OK  timestamp token verified by OpenSSL against this computer's trusted certificates")
        try:
            text = subprocess.run([openssl, "ts", "-reply", "-in", tsr, "-text"], capture_output=True, text=True,
                                  timeout=30).stdout
            when = next((l.split(":", 1)[1].strip() for l in text.splitlines() if l.strip().startswith("Time stamp:")), "")
            if when:
                print(f"    Time inside the verified token: {when}")
        except Exception:  # noqa: BLE001 - the verification result above stands on its own
            pass
    else:
        print("--  OpenSSL could not confirm the timestamp with this computer's certificates. Run it yourself with "
              f"the authority's root certificate: {' '.join(cmd[:7])} -CAfile <root certificate>")


if __name__ == "__main__":
    main()
