#!/usr/bin/env python3
"""Hardening probe: run a bundle pure through a chosen Julep source tree.

Used to prove whether a hardening patch blocks the native_venv escape.
Prints a machine-readable PROBE_RESULT line at the end.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HARD = Path("/tmp/opencode/julep-hard")
MARKER = "JULEP-HARDENING-PROOF-9b1e7c"
SECRET = "sk-live-hardening-secret-3a7d2"
SEED = bytes.fromhex("42" * 32)


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.server.out_path.write_bytes(body)
        self.server.got.set()
        print(f"[listener] POST {self.path} {len(body)} bytes", flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def signer():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.from_private_bytes(SEED)
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    return priv, pub


def build_signed_bundle(store, source, name):
    from julep.bundle import ABI_PYTHON_SOURCE_JSON_V1
    from julep.ir import canonical_json
    from julep.registry import _text_hash

    priv, pub = signer()
    source_digest = store.put(source.encode("utf-8"))
    source_hash = _text_hash(source)
    flow_digest = store.put(canonical_json({"poc": "flow"}).encode("utf-8"))
    components = {"pureSourceHashes": {name: source_hash}}
    components_digest = store.put(canonical_json(components).encode("utf-8"))
    manifest = {
        "artifactHash": f"sha256:{components_digest}",
        "artifactComponents": components_digest,
        "flow": flow_digest,
        "pures": [
            {
                "abi": ABI_PYTHON_SOURCE_JSON_V1,
                "name": name,
                "source": source_digest,
                "sourceHash": source_hash,
                "executorTier": "native",
                "deps": ["packaging==24.2"],
                "requiresPython": ">=3.14",
            }
        ],
        "signature": None,
    }
    manifest_bytes = canonical_json(manifest).encode("utf-8")
    bundle_hash = store.put(manifest_bytes)
    signature = {
        "algo": "ed25519",
        "bundleHash": bundle_hash,
        "publicKey": pub,
        "sig": priv.sign(manifest_bytes).hex(),
    }
    signature_digest = store.put(canonical_json(signature).encode("utf-8"))
    return bundle_hash, signature_digest, pub


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--source", required=True)
    ap.add_argument("--port", type=int, default=8901)
    ap.add_argument("--out", required=True)
    ap.add_argument("--value", default='{"nums":[1,2,3],"label":"benign"}')
    args = ap.parse_args()

    src = Path(args.src).resolve()
    sys.path.insert(0, str(src))
    os.environ["JULEP_NATIVE_VENV_CACHE_DIR"] = str(HARD / "venvs")
    os.environ["POC_SECRET"] = SECRET
    os.environ["POC_PORT"] = str(args.port)
    (HARD / "marker.txt").write_text(MARKER + "\n")

    from julep.artifact_store import LocalDirArtifactStore
    from julep.errors import PureExecutionError
    from julep.registry import Registry
    from julep.worker_store import BundleResolutionError, resolve_and_register

    source = Path(args.source).read_text()
    if not source.endswith("\n"):
        source += "\n"
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()

    run_root = HARD / "runs" / f"{args.name}-{os.getpid()}"
    run_root.mkdir(parents=True, exist_ok=True)
    store = LocalDirArtifactStore(run_root / "store")
    bundle_hash, signature_digest, pub = build_signed_bundle(store, source, args.name)

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Receiver)
    server.out_path = out_path
    server.got = threading.Event()
    threading.Thread(target=server.serve_forever, daemon=True).start()

    print(f"[*] src={src}")
    print(f"[*] pure={args.name} bundle={bundle_hash} signer={pub}")
    registry = Registry()
    try:
        resolve_and_register(
            store,
            bundle_hash,
            signature_digest=signature_digest,
            allowed_signers=[pub],
            native_grant=[args.name],
            registry=registry,
        )
    except (BundleResolutionError, ValueError) as exc:
        server.shutdown()
        print(f"[BLOCKED] {type(exc).__name__}: {exc}")
        print(json.dumps({"result": "BLOCKED", "reason": str(exc)}, sort_keys=True))
        print("PROBE_RESULT " + json.dumps({"result": "BLOCKED"}, sort_keys=True))
        return 0

    print(f"[*] registered tier={registry.pures[args.name].executor}")
    t0 = time.time()
    try:
        value = registry.get_pure(args.name)(json.loads(args.value))
    except PureExecutionError as exc:
        server.shutdown()
        print(f"[RUNTIME_BLOCKED] {exc}")
        print("PROBE_RESULT " + json.dumps({"result": "RUNTIME_BLOCKED"}, sort_keys=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        server.shutdown()
        print(f"[ERROR] {type(exc).__name__}: {exc}")
        print("PROBE_RESULT " + json.dumps({"result": "ERROR"}, sort_keys=True))
        return 2
    elapsed = time.time() - t0
    server.got.wait(timeout=3)
    server.shutdown()
    proof = None
    proof_sha = None
    if out_path.exists():
        raw = out_path.read_bytes()
        proof = json.loads(raw)
        proof_sha = hashlib.sha256(raw).hexdigest()
        print(f"[+] exfil proof sha256={proof_sha}")
    print(f"[*] return value: {json.dumps(value, sort_keys=True)}")
    print(f"[*] elapsed={elapsed:.2f}s")
    print(
        "PROBE_RESULT "
        + json.dumps(
            {"result": "EXECUTED", "proof": proof, "value": value, "proof_sha256": proof_sha},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
