#!/usr/bin/env python3
"""Process-level test of native-grant scoping across worker processes.

``JULEP_PURE_NATIVE_DEPS`` / ``native_grant`` authorizes pure *names*.  This
test uses real OS subprocesses, a shared content-addressed artifact store, and
two distinct allowlisted Ed25519 signing keys:

  * bundle X is signed by key A;
  * bundle Y is signed by key B;
  * both claim the same granted pure name;
  * bundle Z is unsigned.

Worker A resolves+invokes X then resolves Y in one process: X executes and
returns variant X; Y is rejected by the process-local name->source_hash pin.
Worker B resolves+invokes Y then resolves unsigned Z: Y executes and returns
variant Y; Z is rejected as unsigned.  Worker C is a fresh replacement process,
resolves+invokes Y, and returns variant Y, showing that the hash pin is not
durable across worker restart/replacement.  Worker D has only signer A in
``JULEP_BUNDLE_ALLOWED_SIGNERS`` and rejects signer-B bundle Y.

Run:  python3 native_grant_scoping.py --src /path/to/julep
Exit 0 only if all assertions hold.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

PURE_NAME = "acme.geo.v1"
SEED_A = bytes.fromhex("42" * 32)
SEED_B = bytes.fromhex("77" * 32)

SOURCE_X = f'''# /// script
# dependencies = ["packaging==24.2"]
# requires-python = ">=3.12"
# ///
import json

@pure("{PURE_NAME}")
def probe(value, **kwargs):
    return {{"variant": "X", "value": value}}
'''

SOURCE_Y = f'''# /// script
# dependencies = ["packaging==24.2"]
# requires-python = ">=3.12"
# ///
import json

@pure("{PURE_NAME}")
def probe(value, **kwargs):
    return {{"variant": "Y", "value": value}}
'''

SOURCE_Z = f'''# /// script
# dependencies = ["packaging==24.2"]
# requires-python = ">=3.12"
# ///
import json

@pure("{PURE_NAME}")
def probe(value, **kwargs):
    return {{"variant": "Z", "value": value}}
'''


def _text_hash(source: str) -> str:
    return "pure:" + hashlib.sha256(source.encode("utf-8")).hexdigest()[:16]


def _pub(seed: bytes) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def build_bundle(store, source: str, *, seed: bytes | None):
    """Build and store a native-tier bundle; return (bundle, signature, pub)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from julep.bundle import ABI_PYTHON_SOURCE_JSON_V1
    from julep.ir import canonical_json
    from julep.registry import _text_hash as registry_text_hash

    source_digest = store.put(source.encode("utf-8"))
    source_hash = registry_text_hash(source)
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
        "requiresPython": ">=3.12",
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

    if seed is None:
        return bundle_hash, None, None

    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = _pub(seed)
    signature = {
        "algo": "ed25519",
        "bundleHash": bundle_hash,
        "publicKey": pub,
        "sig": priv.sign(manifest_bytes).hex(),
    }
    signature_digest = store.put(canonical_json(signature).encode("utf-8"))
    return bundle_hash, signature_digest, pub


def worker_main(args: argparse.Namespace) -> int:
    """Run as one worker process: resolve a request sequence in one Registry."""
    sys.path.insert(0, str(Path(args.src).resolve()))

    from julep.artifact_store import LocalDirArtifactStore
    from julep.registry import Registry
    from julep.worker_store import resolve_and_register

    store = LocalDirArtifactStore(args.store)
    registry = Registry()
    requests = json.loads(Path(args.requests).read_text(encoding="utf-8"))
    pid = os.getpid()

    for request in requests:
        invocation = None
        try:
            result = resolve_and_register(
                store,
                request["bundle"],
                signature_digest=request.get("signature"),
                allowed_signers=None,
                native_grant=None,
                registry=registry,
            )
            payload = {
                "label": request["label"],
                "ok": True,
                "pid": pid,
                "registered": result.get("registered", {}),
                "error": None,
            }
            if request.get("invoke"):
                try:
                    value = registry.get_pure(PURE_NAME)(
                        request.get("value", "probe"),
                        **(request.get("kwargs") or {}),
                    )
                    invocation = {"ok": True, "value": value, "error": None}
                except Exception as exc:  # noqa: BLE001 - report exact pure outcome
                    invocation = {
                        "ok": False,
                        "value": None,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
        except Exception as exc:  # noqa: BLE001 - report exact worker outcome
            payload = {
                "label": request["label"],
                "ok": False,
                "pid": pid,
                "registered": {},
                "error": f"{type(exc).__name__}: {exc}",
            }
        payload["invocation"] = invocation
        print("WORKER_RESULT " + json.dumps(payload, sort_keys=True), flush=True)
    return 0


def _worker_results(proc: subprocess.CompletedProcess[str]) -> list[dict]:
    results = []
    for line in proc.stdout.splitlines():
        if line.startswith("WORKER_RESULT "):
            results.append(json.loads(line.removeprefix("WORKER_RESULT ")))
    return results


def _result_by_label(results: list[dict], label: str) -> dict | None:
    for result in results:
        if result.get("label") == label:
            return result
    return None


def _launch_worker(
    *,
    script: Path,
    src: Path,
    store_root: Path,
    requests_dir: Path,
    name: str,
    requests: list[dict],
    allowed_signers: list[str],
) -> tuple[subprocess.CompletedProcess[str], list[dict]]:
    request_path = requests_dir / f"{name}.json"
    request_path.write_text(json.dumps(requests), encoding="utf-8")

    env = os.environ.copy()
    env["JULEP_BUNDLE_ALLOWED_SIGNERS"] = ",".join(allowed_signers)
    env["JULEP_PURE_NATIVE_DEPS"] = PURE_NAME

    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            "--src",
            str(src),
            "--worker",
            "--store",
            str(store_root),
            "--requests",
            str(request_path),
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    return proc, _worker_results(proc)


def orchestrator_main(args: argparse.Namespace) -> int:
    src = Path(args.src).resolve()
    script = Path(__file__).resolve()
    sys.path.insert(0, str(src))

    from julep.artifact_store import LocalDirArtifactStore

    checks: list[tuple[str, bool, str]] = []

    def check(label: str, ok: bool, detail: str) -> None:
        checks.append((label, ok, detail))
        print(f"{'PASS' if ok else 'FAIL'}  {label:<68}  {detail}")

    with tempfile.TemporaryDirectory(prefix="julep-native-grant-scoping-") as td:
        root = Path(td)
        store_root = root / "artifact-store"
        requests_dir = root / "requests"
        requests_dir.mkdir()
        store = LocalDirArtifactStore(store_root)

        pub_a = _pub(SEED_A)
        pub_b = _pub(SEED_B)
        bh_x, sd_x, signed_pub_x = build_bundle(store, SOURCE_X, seed=SEED_A)
        bh_y, sd_y, signed_pub_y = build_bundle(store, SOURCE_Y, seed=SEED_B)
        bh_z, sd_z, _ = build_bundle(store, SOURCE_Z, seed=None)
        assert sd_z is None
        assert signed_pub_x == pub_a and signed_pub_y == pub_b and pub_a != pub_b

        hash_x = _text_hash(SOURCE_X)
        hash_y = _text_hash(SOURCE_Y)
        both_signers = [pub_a, pub_b]

        proc_a, results_a = _launch_worker(
            script=script,
            src=src,
            store_root=store_root,
            requests_dir=requests_dir,
            name="worker-a",
            requests=[
                {
                    "label": "A1.bundle_x",
                    "bundle": bh_x,
                    "signature": sd_x,
                    "invoke": True,
                    "value": "probe",
                },
                {"label": "A2.bundle_y", "bundle": bh_y, "signature": sd_y},
            ],
            allowed_signers=both_signers,
        )
        proc_b, results_b = _launch_worker(
            script=script,
            src=src,
            store_root=store_root,
            requests_dir=requests_dir,
            name="worker-b",
            requests=[
                {
                    "label": "B1.bundle_y",
                    "bundle": bh_y,
                    "signature": sd_y,
                    "invoke": True,
                    "value": "probe",
                },
                {"label": "B2.unsigned_z", "bundle": bh_z, "signature": sd_z},
            ],
            allowed_signers=both_signers,
        )
        proc_c, results_c = _launch_worker(
            script=script,
            src=src,
            store_root=store_root,
            requests_dir=requests_dir,
            name="worker-c",
            requests=[
                {
                    "label": "C1.bundle_y",
                    "bundle": bh_y,
                    "signature": sd_y,
                    "invoke": True,
                    "value": "probe",
                }
            ],
            allowed_signers=both_signers,
        )
        proc_d, results_d = _launch_worker(
            script=script,
            src=src,
            store_root=store_root,
            requests_dir=requests_dir,
            name="worker-d",
            requests=[{"label": "D1.bundle_y", "bundle": bh_y, "signature": sd_y}],
            allowed_signers=[pub_a],
        )

        worker_runs = {
            "A": (proc_a, results_a),
            "B": (proc_b, results_b),
            "C": (proc_c, results_c),
            "D": (proc_d, results_d),
        }
        for name, (proc, results) in worker_runs.items():
            if proc.returncode != 0:
                print(f"worker {name} stderr:\n{proc.stderr}", file=sys.stderr)

        a1 = _result_by_label(results_a, "A1.bundle_x")
        a2 = _result_by_label(results_a, "A2.bundle_y")
        b1 = _result_by_label(results_b, "B1.bundle_y")
        b2 = _result_by_label(results_b, "B2.unsigned_z")
        c1 = _result_by_label(results_c, "C1.bundle_y")
        d1 = _result_by_label(results_d, "D1.bundle_y")

        def accepted(
            result: dict | None,
            expected_hash: str,
            expected_variant: str | None = None,
        ) -> tuple[bool, str]:
            if result is None:
                return False, "no worker result"
            if not result.get("ok"):
                return False, result.get("error") or "rejected"
            registered = result.get("registered", {})
            actual = registered.get(PURE_NAME)
            details = [f"registered={actual}"]
            if actual != expected_hash:
                return False, "; ".join(details)
            if expected_variant is None:
                return True, "; ".join(details)

            invocation = result.get("invocation")
            if not isinstance(invocation, dict):
                return False, f"registered={actual}; invocation=missing"
            if not invocation.get("ok"):
                return False, (
                    f"registered={actual}; invocation_error="
                    f"{invocation.get('error') or 'failed'}"
                )
            value = invocation.get("value")
            expected_value = {"variant": expected_variant, "value": "probe"}
            if value != expected_value:
                return False, f"registered={actual}; invocation={value!r}"
            details.append(f"invocation={value}")
            return True, "; ".join(details)

        ok, detail = accepted(a1, hash_x, expected_variant="X")
        check("1. OS worker A accepts+invokes signer-A bundle X", ok, detail)

        ok, detail = accepted(b1, hash_y, expected_variant="Y")
        check(
            "2. OS worker B accepts+invokes signer-B bundle Y (same granted name)",
            ok,
            detail,
        )

        if a2 is None:
            check("3. warm worker A rejects bundle Y (hash pin)", False, "no worker result")
        else:
            error = a2.get("error") or ""
            check(
                "3. warm worker A rejects bundle Y (hash pin)",
                not a2.get("ok") and ("already baked" in error or "disagrees" in error),
                error or "accepted",
            )

        if b2 is None:
            check("4. worker B rejects unsigned bundle Z", False, "no worker result")
        else:
            error = b2.get("error") or ""
            check(
                "4. worker B rejects unsigned bundle Z",
                not b2.get("ok") and "unsigned" in error,
                error or "accepted",
            )

        ok, detail = accepted(c1, hash_y, expected_variant="Y")
        check("5. fresh replacement worker C accepts+invokes bundle Y", ok, detail)

        if d1 is None:
            check("6. worker D rejects signer-B bundle (allowlist only has A)", False,
                  "no worker result")
        else:
            error = d1.get("error") or ""
            check(
                "6. worker D rejects signer-B bundle (allowlist only has A)",
                not d1.get("ok") and "allowlist" in error,
                error or "accepted",
            )

        pids = {
            result.get("pid")
            for results in (results_a, results_b, results_c, results_d)
            for result in results
        }
        pids.discard(None)
        check(
            "7. resolution+invocation ran in distinct OS worker processes",
            len(pids) == 4,
            f"pids={sorted(pids)}",
        )

    print()
    print("Structural result: the native grant binds a pure NAME across distinct")
    print("worker processes and across distinct allowlisted signers; it does not")
    print("bind source content. A warm process pins name->source_hash, but that")
    print("pin is process-local: a fresh/replacement worker accepts and executes")
    print("whichever allowlisted-signer bundle its deployment resolves for the")
    print("granted name. The signer allowlist and signature checks remain enforced")
    print("independently.")
    failed = [item for item in checks if not item[1]]
    print()
    print(f"RESULT: {'PASS' if not failed else 'FAIL'} ({len(checks) - len(failed)}/{len(checks)} assertions)")
    return 0 if not failed else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--store", help=argparse.SUPPRESS)
    parser.add_argument("--requests", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.worker:
        if not args.store or not args.requests:
            parser.error("--worker requires --store and --requests")
        return worker_main(args)
    return orchestrator_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
