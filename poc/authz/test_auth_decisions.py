#!/usr/bin/env python3
"""Exercise the real Julep authorization gates with admin/client/worker keys.

Two layers:
  1. direct calls to require_admin / require_client / require_worker
  2. an isolated FastAPI ASGI app using those same dependencies (if fastapi+httpx
     are installed), proving header parsing + keyring + role decision end-to-end.

This does not boot the full control plane (DB/store dependencies are out of
scope); it proves the gate decision itself.

Usage: JULEP_SRC=/path/to/julep python3 test_auth_decisions.py
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

SRC = Path(os.environ.get("JULEP_SRC", "")).resolve()
if not (SRC / "julep" / "server" / "auth.py").is_file():
    print("error: set JULEP_SRC to a Julep source tree", file=sys.stderr)
    raise SystemExit(2)
sys.path.insert(0, str(SRC))

from julep.server.auth import ApiKey, KeyRing, require_admin, require_client, require_worker  # noqa: E402


class _State:
    pass


class _App:
    def __init__(self, keyring: KeyRing) -> None:
        self.state = _State()
        self.state.keyring = keyring


class _Req:
    def __init__(self, app: _App, token: str | None) -> None:
        self.app = app
        self.headers = {} if token is None else {"Authorization": f"Bearer {token}"}


ADMIN = ApiKey(name="poc-admin", token="tok-admin", role="admin")
CLIENT = ApiKey(name="poc-client", token="tok-client", role="client")
WORKER = ApiKey(name="poc-worker", token="tok-worker", role="worker")
RING = KeyRing([ADMIN, CLIENT, WORKER])
APP = _App(RING)

TOKENS = {"admin": "tok-admin", "client": "tok-client", "worker": "tok-worker", "missing": None, "bad": "tok-nope"}

DIRECT_CASES = [
    (require_admin, "admin", 200),
    (require_admin, "client", 403),
    (require_admin, "worker", 403),
    (require_admin, "missing", 401),
    (require_admin, "bad", 401),
    (require_client, "client", 200),
    (require_client, "admin", 200),
    (require_client, "worker", 403),
    (require_client, "missing", 401),
    (require_worker, "worker", 200),
    (require_worker, "client", 403),
    (require_worker, "admin", 403),
]

results: list[dict] = []


def status_of(fn, token: str | None) -> int:
    try:
        fn(_Req(APP, token))
        return 200
    except Exception as exc:  # HTTPException carries status_code
        return int(getattr(exc, "status_code", 500))


for fn, identity, expected in DIRECT_CASES:
    got = status_of(fn, TOKENS[identity])
    results.append(
        {
            "layer": "direct",
            "gate": fn.__name__,
            "identity": identity,
            "expected": expected,
            "got": got,
            "pass": got == expected,
        }
    )

http_layer = "skipped"
try:
    from fastapi import Depends, FastAPI  # noqa: E402
    from fastapi.testclient import TestClient  # noqa: E402

    app = FastAPI()
    app.state.keyring = RING

    @app.get("/gate/admin")
    def _admin_gate(_key: ApiKey = Depends(require_admin)):
        return {"role": _key.role}

    @app.get("/gate/client")
    def _client_gate(_key: ApiKey = Depends(require_client)):
        return {"role": _key.role}

    @app.get("/gate/worker")
    def _worker_gate(_key: ApiKey = Depends(require_worker)):
        return {"role": _key.role}

    http_layer = "fastapi.TestClient"
    client = TestClient(app)
    HTTP_CASES = [
        ("/gate/admin", "admin", 200),
        ("/gate/admin", "client", 403),
        ("/gate/admin", "worker", 403),
        ("/gate/admin", "missing", 401),
        ("/gate/admin", "bad", 401),
        ("/gate/client", "client", 200),
        ("/gate/client", "admin", 200),
        ("/gate/client", "worker", 403),
        ("/gate/worker", "worker", 200),
        ("/gate/worker", "client", 403),
        ("/gate/worker", "admin", 403),
    ]
    for path, identity, expected in HTTP_CASES:
        token = TOKENS[identity]
        headers = {} if token is None else {"Authorization": f"Bearer {token}"}
        got = client.get(path, headers=headers).status_code
        results.append(
            {
                "layer": "http",
                "gate": path,
                "identity": identity,
                "expected": expected,
                "got": got,
                "pass": got == expected,
            }
        )
except ImportError as exc:
    http_layer = f"skipped: {exc}"

for row in results:
    print(
        f"{'PASS' if row['pass'] else 'FAIL'}  {row['layer']:<6} {row['gate']:<16} "
        f"{row['identity']:<8} expected={row['expected']} got={row['got']}"
    )

failed = [row for row in results if not row["pass"]]
print(f"http_layer: {http_layer}")
print(f"cases: {len(results)} passed: {len(results) - len(failed)} failed: {len(failed)}")
print(json.dumps({"http_layer": http_layer, "failed": failed}, indent=2))
raise SystemExit(0 if not failed else 1)
