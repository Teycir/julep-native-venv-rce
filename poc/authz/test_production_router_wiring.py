#!/usr/bin/env python3
"""Exercise the *production* FastAPI routers, not a reimplementation.

For every mutating route registered by ``julep.server.routes.*`` this test:

1. walks the real ``APIRoute.dependant`` tree and asserts an auth gate
   (``require_admin`` / ``require_client`` / ``require_worker``) is wired in;
2. sends an unauthenticated request through ``TestClient`` and asserts the
   gate rejects it with 401/403 before any handler or store access.

Run:  python3 test_production_router_wiring.py --src /path/to/julep
Exit: 0 only if every mutating route is both wired and rejecting.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

GATES = {"require_admin", "require_client", "require_worker"}
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
PARAMS = {
    "{sha256}": "0" * 64,
    "{name}": "poc",
    "{run_id}": "00000000-0000-0000-0000-000000000000",
}


def gate_names(dependant, seen=None) -> set[str]:
    """Collect gate callables from a Starlette/FastAPI Dependant tree."""
    if seen is None:
        seen = set()
    if id(dependant) in seen:
        return set()
    seen.add(id(dependant))
    names: set[str] = set()
    call = getattr(dependant, "call", None)
    if call is not None and getattr(call, "__name__", "") in GATES:
        names.add(call.__name__)
    for child in getattr(dependant, "dependencies", []) or []:
        names |= gate_names(child, seen)
    return names


def materialize(path: str) -> str:
    for placeholder, value in PARAMS.items():
        path = path.replace(placeholder, value)
    return path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True)
    args = parser.parse_args()

    src = Path(args.src).resolve()
    sys.path.insert(0, str(src))

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from julep.server.routes import (
        artifacts,
        deployments,
        health,
        releases,
        runs,
        secrets,
    )

    modules = (health, artifacts, releases, deployments, runs, secrets)
    app = FastAPI()
    for module in modules:
        app.include_router(module.router, prefix="/v1")

    routes = []
    for module in modules:
        for route in module.router.routes:
            methods = set(getattr(route, "methods", set()) or set())
            if methods & MUTATING:
                routes.append((route, sorted(methods & MUTATING)))

    print(f"fastapi: {__import__('fastapi').__version__}")
    print(f"mutating routes discovered: {len(routes)}")
    print(f"{'METHOD':<7} {'PATH':<34} {'GATE':<16} {'UNAUTH':<7} RESULT")

    failures = 0
    with TestClient(app) as client:
        for route, methods in sorted(routes, key=lambda item: (item[0].path, item[1])):
            method = methods[0]
            gates = gate_names(route.dependant)
            url = "/v1" + materialize(route.path)
            kwargs = {}
            if method in {"POST", "PUT", "PATCH"}:
                kwargs["json"] = {}
            response = client.request(method, url, **kwargs)
            wired = bool(gates)
            rejected = response.status_code in {401, 403}
            ok = wired and rejected
            failures += 0 if ok else 1
            gate = ",".join(sorted(gates)) or "-"
            print(
                f"{method:<7} {route.path:<34} {gate:<16} "
                f"{response.status_code:<7} {'PASS' if ok else 'FAIL'}"
            )

    print()
    print(f"RESULT: {'PASS' if failures == 0 else 'FAIL'} ({len(routes) - failures}/{len(routes)} wired+rejecting)")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
