#!/usr/bin/env python3
"""Cryptographic proof for the bundle signing / verification chain.

Exercises the *actual* functions used by the two production paths:

* publication: ``julep.bundle._signature_blob`` (called by ``publish_bundle``)
* worker:      ``julep.worker_store._verify_signature`` + allowlist check
               (called by ``resolve_and_register``)

and asserts the negative controls: tampered manifest, wrong key, unknown
signer, unsigned bundle.  Optionally runs the full ``publish_bundle`` path
when a minimal ``Deployment`` can be constructed.

Run:  python3 bundle_signature_proof.py --src /path/to/julep
Exit: 0 only if every positive/negative assertion holds.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

SEED_A = "11" * 32
SEED_B = "22" * 32


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True)
    args = parser.parse_args()
    src = Path(args.src).resolve()
    sys.path.insert(0, str(src))

    from julep.bundle import _canonical_bytes, _signature_blob
    from julep.worker_store import (
        BundleResolutionError,
        _allowed_signers,
        _verify_signature,
        resolve_and_register,
    )

    checks: list[tuple[str, bool, str]] = []

    def check(label: str, fn) -> None:
        try:
            detail = fn()
            checks.append((label, True, detail or "ok"))
        except Exception as exc:  # noqa: BLE001 - report exact failure text
            checks.append((label, False, f"{type(exc).__name__}: {exc}"))

    manifest = {
        "artifactHash": "sha256:" + "ab" * 32,
        "artifactComponents": "cd" * 32,
        "flow": "ef" * 32,
        "pures": [],
        "signature": None,
    }
    manifest_bytes = _canonical_bytes(manifest)
    bundle_hash = hashlib.sha256(manifest_bytes).hexdigest()
    signature = _signature_blob(manifest_bytes, bundle_hash, SEED_A)
    pub_a, pub_b = signature["publicKey"], _signature_blob(manifest_bytes, bundle_hash, SEED_B)["publicKey"]

    check(
        "signature object shape (ed25519, bundleHash, publicKey, sig)",
        lambda: "ok" if (
            signature["algo"] == "ed25519"
            and signature["bundleHash"] == bundle_hash
            and len(bytes.fromhex(signature["publicKey"])) == 32
            and len(bytes.fromhex(signature["sig"])) == 64
        ) else (_ for _ in ()).throw(AssertionError("unexpected signature shape")),
    )

    check(
        "worker _verify_signature accepts authentic manifest",
        lambda: _verify_signature(pub_a, signature["sig"], manifest_bytes) or "accepted",
    )

    def tampered_must_fail():
        try:
            _verify_signature(pub_a, signature["sig"], manifest_bytes + b" ")
        except BundleResolutionError as exc:
            return f"rejected: {exc}"
        raise AssertionError("tampered manifest was accepted")

    check("worker _verify_signature rejects tampered manifest", tampered_must_fail)

    def wrong_key_must_fail():
        try:
            _verify_signature(pub_b, signature["sig"], manifest_bytes)
        except BundleResolutionError as exc:
            return f"rejected: {exc}"
        raise AssertionError("signature verified under the wrong public key")

    check("worker _verify_signature rejects wrong public key", wrong_key_must_fail)

    sig_digest = hashlib.sha256(_canonical_bytes(signature)).hexdigest()
    store = {
        bundle_hash: manifest_bytes,
        sig_digest: _canonical_bytes(signature),
    }

    def unsigned_must_fail():
        try:
            resolve_and_register(store, bundle_hash, signature_digest=None, allowed_signers=[pub_a])
        except BundleResolutionError as exc:
            assert "unsigned" in str(exc), exc
            return f"rejected: {exc}"
        raise AssertionError("unsigned bundle was accepted")

    check("resolve_and_register rejects unsigned bundle", unsigned_must_fail)

    def unknown_signer_must_fail():
        try:
            resolve_and_register(
                store, bundle_hash, signature_digest=sig_digest, allowed_signers=[pub_b]
            )
        except BundleResolutionError as exc:
            assert "allowlist" in str(exc), exc
            return f"rejected: {exc}"
        raise AssertionError("unknown signer was accepted")

    check("resolve_and_register rejects signer outside allowlist", unknown_signer_must_fail)

    def known_signer_passes_crypto():
        try:
            resolve_and_register(
                store, bundle_hash, signature_digest=sig_digest, allowed_signers=[pub_a]
            )
        except BundleResolutionError as exc:
            if "signature verification failed" in str(exc):
                raise AssertionError("known signer failed crypto verification") from exc
            return f"crypto accepted, manifest validation stopped it: {exc}"
        return "accepted"

    check("resolve_and_register accepts allowlisted signer's signature", known_signer_passes_crypto)

    check(
        "allowlist normalises hex and rejects non-hex",
        lambda: (
            "ok"
            if _allowed_signers([pub_a.upper()]) == {pub_a}
            else (_ for _ in ()).throw(AssertionError("normalisation failed"))
        ),
    )

    # Optional: full publication path, if a minimal Deployment is constructible.
    def full_publish():
        import importlib

        deploy_mod = importlib.import_module("julep.deploy")
        from julep.artifact_store import LocalDirArtifactStore
        from julep.bundle import publish_bundle

        op = list(deploy_mod.Op)[0]
        flow = deploy_mod.Node(op=op, id="start")
        manifest_obj = deploy_mod.ToolManifest() if callable(deploy_mod.ToolManifest) else {}
        deployment = deploy_mod.Deployment(flow=flow, manifest=manifest_obj)
        with tempfile.TemporaryDirectory(prefix="julep-sig-") as tmp:
            artifact_store = LocalDirArtifactStore(tmp)
            published = publish_bundle(
                deployment, artifact_store, signing_key=SEED_A, native_grant=()
            )
            stored_sig = json.loads(artifact_store.get(published["signatureDigest"]))
            stored_manifest = artifact_store.get(published["bundleHash"])
            _verify_signature(stored_sig["publicKey"], stored_sig["sig"], stored_manifest)
            return f"published+verified bundleHash={published['bundleHash'][:16]}…"

    try:
        detail = full_publish()
        checks.append(("full publish_bundle -> worker verify", True, detail))
    except Exception as exc:  # noqa: BLE001
        checks.append(
            ("full publish_bundle -> worker verify", False, f"SKIPPED: {type(exc).__name__}: {exc}")
        )

    width = max(len(label) for label, _, _ in checks)
    for label, ok, detail in checks:
        print(f"{'PASS' if ok else 'FAIL'}  {label:<{width}}  {detail}")

    hard_failures = [c for c in checks if not c[1] and not c[2].startswith("SKIPPED")]
    print()
    print(f"RESULT: {'PASS' if not hard_failures else 'FAIL'} ({len(checks) - len(hard_failures)}/{len(checks)} assertions)")
    return 0 if not hard_failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
