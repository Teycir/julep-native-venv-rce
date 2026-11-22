#!/usr/bin/env python3
"""Test whether the native grant is bound to bundle *content* or only to the
pure *name* across independent workers.

The native grant (``JULEP_PURE_NATIVE_DEPS`` / ``native_grant``) is a list of
pure names.  ``worker_store.resolve_and_register`` checks ``verified_pure.name
in native_grants`` — never the source hash or signer identity.  On a *warm*
worker the registry pins name->source_hash and rejects disagreeing content,
but on a *fresh* worker (new process, new Registry, empty store) nothing ties
the granted name to previously-seen content.

Scenario modeled: an operator grants ``acme.geo.v1`` native tier for a
legitimate dependency-bearing pure.  Two fresh workers receive two different,
both-validly-signed bundles that claim the same pure name.

  1. Worker A resolves bundle X (source A) -> accepted.
  2. Worker B (fresh) resolves bundle Y (source B, same name, same grant,
     valid signature) -> accepted: different content under the granted name.
  3. Worker A, now warm, attempts bundle Y -> rejected by the name->hash pin.
  4. Worker B attempts an UNSIGNED bundle Z with the same name -> rejected:
     the grant does not bypass signature verification.

Assertions 1-3 demonstrate the grant is name-scoped, not content-scoped,
across the fleet; assertion 4 confirms the signature gate still applies.

Run:  python3 native_grant_scoping.py --src /path/to/julep
Exit 0 only if all cases behave as asserted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

PURE_NAME = "acme.geo.v1"
SEED_A = bytes.fromhex("42" * 32)

SOURCE_A = f'''# /// script
# dependencies = ["packaging==24.2"]
# requires-python = ">=3.14"
# ///
import json

@pure("{PURE_NAME}")
def probe(value, **kwargs):
    return {{"variant": "A", "value": value}}
'''

SOURCE_B = f'''# /// script
# dependencies = ["packaging==24.2"]
# requires-python = ">=3.14"
# ///
import json

@pure("{PURE_NAME}")
def probe(value, **kwargs):
    return {{"variant": "B", "value": value}}
'''

SOURCE_Z = f'''# /// script
# dependencies = ["packaging==24.2"]
# requires-python = ">=3.14"
# ///
import json

@pure("{PURE_NAME}")
def probe(value, **kwargs):
    return {{"variant": "Z", "value": value}}
'''


class DictStore:
    """Minimal ArtifactStore: resolve_and_register only calls .get()."""

    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}

    def put(self, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        self.blobs[digest] = data
        return digest

    def get(self, digest: str) -> bytes:
        return self.blobs[digest]


def _pub(priv) -> str:
    from cryptography.hazmat.primitives import serialization

    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def build_bundle(store: DictStore, source: str, *, sign: bool = True):
    """Return (bundle_hash, signature_digest|None)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from julep.bundle import ABI_PYTHON_SOURCE_JSON_V1
    from julep.ir import canonical_json
    from julep.registry import _text_hash

    source_digest = store.put(source.encode("utf-8"))
    source_hash = _text_hash(source)
    flow_digest = store.put(canonical_json({"poc": "flow"}).encode("utf-8"))
    components_digest = store.put(
        canonical_json({"pureSourceHashes": {PURE_NAME: source_hash}}).encode("utf-8")
    )

    pure_record = {
        "abi": ABI_PYTHON_SOURCE_JSON_V1,
        "name": PURE_NAME,
        "source": source_digest,
        "sourceHash": source_hash,
        "deps": ["packaging==24.2"],
        "requiresPython": ">=3.14",
        "executorTier": "native",
    }

    manifest = {
        "artifactHash": f"sha256:{components_digest}",
        "artifactComponents": components_digest,
        "flow": flow_digest,
        "pures": [pure_record],
        "signature": None,
    }
    manifest_bytes = canonical_json(manifest).encode("utf-8")
    bundle_hash = store.put(manifest_bytes)

    pub = _pub(Ed25519PrivateKey.from_private_bytes(SEED_A))
    if not sign:
        return bundle_hash, None

    priv = Ed25519PrivateKey.from_private_bytes(SEED_A)
    signature = {
        "algo": "ed25519",
        "bundleHash": bundle_hash,
        "publicKey": pub,
        "sig": priv.sign(manifest_bytes).hex(),
    }
    signature_digest = store.put(canonical_json(signature).encode("utf-8"))
    return bundle_hash, signature_digest


def resolve(store, bundle_hash, signature_digest, registry):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from julep.registry import Registry  # noqa: F401  (documents the type)
    from julep.worker_store import resolve_and_register

    pub_a = _pub(Ed25519PrivateKey.from_private_bytes(SEED_A))
    return resolve_and_register(
        store,
        bundle_hash,
        signature_digest=signature_digest,
        allowed_signers=[pub_a],
        native_grant=[PURE_NAME],
        registry=registry,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True)
    args = parser.parse_args()
    src = Path(args.src).resolve()
    sys.path.insert(0, str(src))

    from julep.registry import Registry
    from julep.worker_store import BundleResolutionError

    checks: list[tuple[str, bool, str]] = []

    def check(label: str, ok: bool, detail: str) -> None:
        checks.append((label, ok, detail))
        print(f"{'PASS' if ok else 'FAIL'}  {label:<64}  {detail}")

    # Shared artifact store (as in a real deployment: one store, many workers).
    store = DictStore()
    bh_x, sd_x = build_bundle(store, SOURCE_A)
    bh_y, sd_y = build_bundle(store, SOURCE_B)
    bh_z, sd_z = build_bundle(store, SOURCE_Z, sign=False)

    # 1. Worker A (fresh) resolves bundle X.
    reg_a = Registry()
    try:
        result = resolve(store, bh_x, sd_x, reg_a)
        check("1. worker A accepts bundle X under granted name",
              PURE_NAME in result["registered"], f"registered={sorted(result['registered'])}")
    except Exception as exc:  # noqa: BLE001
        check("1. worker A accepts bundle X under granted name", False,
              f"{type(exc).__name__}: {exc}")

    # 2. Worker B (fresh registry, same grant) resolves bundle Y — DIFFERENT
    #    signed content under the same granted pure name.
    reg_b = Registry()
    try:
        result = resolve(store, bh_y, sd_y, reg_b)
        check("2. fresh worker B accepts bundle Y (same name, diff content)",
              PURE_NAME in result["registered"], f"registered={sorted(result['registered'])}")
    except Exception as exc:  # noqa: BLE001
        check("2. fresh worker B accepts bundle Y (same name, diff content)", False,
              f"{type(exc).__name__}: {exc}")

    # 3. Worker A is now warm: name->hash pinned to X. Bundle Y must be
    #    rejected even though it is validly signed and the grant covers the name.
    try:
        resolve(store, bh_y, sd_y, reg_a)
        check("3. warm worker A rejects bundle Y (hash pin)", False, "was accepted")
    except BundleResolutionError as exc:
        check("3. warm worker A rejects bundle Y (hash pin)",
              "already baked" in str(exc) or "disagrees" in str(exc), str(exc))
    except Exception as exc:  # noqa: BLE001
        check("3. warm worker A rejects bundle Y (hash pin)", False,
              f"{type(exc).__name__}: {exc}")

    # 4. Worker B attempts unsigned bundle Z with the same granted name.
    try:
        resolve(store, bh_z, sd_z, reg_b)
        check("4. unsigned bundle Z rejected despite grant", False, "was accepted")
    except BundleResolutionError as exc:
        check("4. unsigned bundle Z rejected despite grant", "unsigned" in str(exc), str(exc))
    except Exception as exc:  # noqa: BLE001
        check("4. unsigned bundle Z rejected despite grant", False,
              f"{type(exc).__name__}: {exc}")

    print()
    print("Structural result: the native grant binds a pure NAME, not a source")
    print("hash or signer. Fresh workers accept any allowlisted-signer bundle")
    print("claiming the granted name; warm workers pin name->hash per process.")
    print("A fleet with mixed worker ages can run different code for the same")
    print("granted pure name until every worker has resolved the same bundle.")
    failed = [c for c in checks if not c[1]]
    print()
    print(f"RESULT: {'PASS' if not failed else 'FAIL'} ({len(checks) - len(failed)}/{len(checks)} assertions)")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
