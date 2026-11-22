#!/usr/bin/env python3
"""Authorization test against the REAL Julep control-plane application.

Unlike ``test_production_router_wiring.py`` (which mounts the route modules
into a freshly assembled ``FastAPI()``), this builds the application through
the production factory ``julep.server.app.create_app`` — the same function
``julep.server.local`` uses to serve — with the real ``ServerSettings``,
``KeyRing``, middleware/lifespan wiring, and all six routers.

For every route it:

1. walks the real ``APIRoute.dependant`` tree and asserts the gate set equals
   the EXPECTED gate for that method+path (exact match, not "any gate");
2. sends unauthenticated / wrong-role / right-role requests through
   ``TestClient`` and asserts 401/403/pass respectively.

Run:  python3 test_production_app_authz.py --src /path/to/julep
Exit 0 only if every route's gate matches EXPECTED and every HTTP check passes.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

GATES = {"require_admin", "require_client", "require_worker"}

# (method, path-without-/v1-prefix) -> expected gate callable name, or None.
EXPECTED: dict[tuple[str, str], str | None] = {
    ("PUT", "/artifacts/{sha256}"): "require_admin",
    ("HEAD", "/artifacts/{sha256}"): "require_client",
    ("POST", "/deployments"): "require_admin",
    ("GET", "/deployments"): "require_client",
    ("GET", "/health"): None,
    ("GET", "/health/ready"): None,
    ("GET", "/ready"): "require_client",
    ("POST", "/releases"): "require_admin",
    ("GET", "/releases"): "require_client",
    ("GET", "/releases/{release_hash}"): "require_client",
    ("POST", "/runs"): "require_client",
    ("GET", "/runs"): "require_client",
    ("GET", "/runs/{run_id}"): "require_client",
    ("POST", "/runs/{run_id}/cancel"): "require_client",
    ("POST", "/runs/{run_id}/terminate"): "require_client",
    ("GET", "/runs/{run_id}/events"): "require_client",
    ("GET", "/runs/{run_id}/result"): "require_client",
    ("GET", "/runs/{run_id}/values/{value_ref}"): "require_client",
    ("GET", "/runs/{run_id}/gates"): "require_client",
    ("POST", "/runs/{run_id}/signals/human"): "require_client",
    ("PUT", "/secrets/{name}"): "require_admin",
    ("GET", "/secrets"): "require_admin",
    ("GET", "/secrets/{name}/value"): "require_worker",
    ("POST", "/secrets/{name}/archive"): "require_admin",
    ("DELETE", "/secrets/{name}"): "require_admin",
}

PARAMS = {
    "{sha256}": "0" * 64,
    "{release_hash}": "0" * 64,
    "{run_id}": "00000000-0000-0000-0000-000000000000",
    "{value_ref}": "0" * 64,
    "{name}": "poc",
}

TOKENS = {
    "admin": "admin-token",
    "client": "client-token",
    "worker": "worker-token",
    "missing": None,
    "bad": "no-such-token",
}

# Which roles each gate admits (require_client also admits admin).
ALLOWED = {
    "require_admin": {"admin"},
    "require_client": {"admin", "client"},
    "require_worker": {"worker"},
}


def gate_names(dependant, seen=None) -> set[str]:
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


class FakeTemporalGateway:
    """Minimal stand-in; the real gateway is injected, never contacted."""

    is_ready = True

    async def ready(self) -> bool:
        return self.is_ready

    async def start_flow(self, *a, **k):  # pragma: no cover - never reached
        raise RuntimeError("fake gateway must not start flows")

    async def cancel(self, *a, **k):
        pass

    async def terminate(self, *a, **k):
        pass

    async def describe(self, *a, **k):
        return "running"

    async def signal(self, *a, **k):
        pass

    async def query(self, *a, **k):
        return []

    async def close(self):
        pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True)
    args = parser.parse_args()
    src = Path(args.src).resolve()
    sys.path.insert(0, str(src))

    from fastapi.testclient import TestClient

    from julep.artifact_store import LocalDirArtifactStore
    from julep.execution.projection_store import InMemoryExecutionStore
    from julep.server.app import create_app
    from julep.server.auth import ApiKey
    from julep.server.settings import ServerSettings

    tmp_path = Path(tempfile.mkdtemp(prefix="julep-app-authz-"))
    settings = ServerSettings(
        api_keys=(
            ApiKey("admin", "admin-token", admin=True),
            ApiKey("client", "client-token"),
            ApiKey("worker", "worker-token", role="worker"),
        ),
        vault_keys="vault=" + "11" * 32,
        vault_key_id="vault",
        worker_secret_allowlist=frozenset({"poc"}),  # PARAMS["{name}"]
        queue_by_lane={},
        payload_encryption_required=True,
        unauthenticated_ready=False,
        config_root=tmp_path,
    )
    app = create_app(
        settings=settings,
        store=InMemoryExecutionStore(),
        gateway=FakeTemporalGateway(),
        artifacts=LocalDirArtifactStore(tmp_path / "artifacts"),
        enable_reconciler=False,
        reconcile_interval_s=0,
    )

    assert app.title == "Julep Control Plane", app.title

    # FastAPI >=0.138 keeps included routers lazy as _IncludedRouter wrappers;
    # the real APIRoute objects (with dependant trees) live on .original_router.
    def iter_api_routes(app):
        for entry in app.routes:
            if type(entry).__name__ == "_IncludedRouter":
                prefix = entry.include_context.prefix or ""
                for route in entry.original_router.routes:
                    yield prefix, route
            elif hasattr(entry, "dependant"):
                yield "", entry

    # --- Layer 1: exact gate identity per route -------------------------------
    failures = 0
    route_rows = []
    seen_rel: set[tuple[str, str]] = set()
    for prefix, route in iter_api_routes(app):
        methods = set(getattr(route, "methods", set()) or set())
        if not methods:
            continue
        path = prefix + route.path
        if not path.startswith("/v1"):
            continue  # openapi/docs/docs-oauth redirect routes are not API surface
        rel = path[len("/v1"):]
        gates = gate_names(route.dependant)
        for method in sorted(methods):
            seen_rel.add((method, rel))
            expected = EXPECTED.get((method, rel), "<unexpected>")
            expected_set = set() if expected in (None, "<unexpected>") else {expected}
            ok = gates == expected_set
            failures += 0 if ok else 1
            route_rows.append((method, rel, ",".join(sorted(gates)) or "-", expected or "-", ok))

    # Every EXPECTED entry must correspond to a real route.
    for key in EXPECTED:
        if key not in seen_rel:
            failures += 1
            route_rows.append((key[0], key[1], "-", EXPECTED[key] or "-", False))

    print(f"{'METHOD':<7} {'PATH':<40} {'GATES':<16} {'EXPECTED':<16} RESULT")
    for method, path, gates, expected, ok in sorted(route_rows):
        print(f"{method:<7} {path:<40} {gates:<16} {expected:<16} {'PASS' if ok else 'FAIL'}")

    # --- Layer 2: HTTP behaviour through the production app -------------------
    http_failures = 0
    http_rows = []
    with TestClient(app) as client:
        identities = ["missing", "bad", "worker", "client", "admin"]
        for prefix, route in iter_api_routes(app):
            methods = set(getattr(route, "methods", set()) or set())
            if not methods:
                continue
            full_path = prefix + route.path
            if not full_path.startswith("/v1"):
                continue
            rel = full_path[len("/v1"):]
            for method in sorted(methods):
                expected = EXPECTED.get((method, rel))
                url = "/v1" + materialize(rel)
                kwargs = {"json": {}} if method in {"POST", "PUT", "PATCH"} else {}
                for identity in identities:
                    token = TOKENS[identity]
                    headers = {} if token is None else {"Authorization": f"Bearer {token}"}
                    status = client.request(method, url, headers=headers, **kwargs).status_code
                    if expected is None:
                        ok = status not in {401, 403}
                    elif identity in {"missing", "bad"}:
                        ok = status == 401
                    elif identity in ALLOWED[expected]:
                        ok = status not in {401, 403}
                    else:
                        ok = status == 403
                    http_failures += 0 if ok else 1
                    http_rows.append((method, rel, identity, status, ok))

    print()
    print(f"{'METHOD':<7} {'PATH':<40} {'IDENTITY':<8} {'STATUS':<7} RESULT")
    for method, path, identity, status, ok in http_rows:
        print(f"{method:<7} {path:<40} {identity:<8} {status:<7} {'PASS' if ok else 'FAIL'}")

    total_fail = failures + http_failures
    print()
    print(
        f"RESULT: {'PASS' if total_fail == 0 else 'FAIL'} "
        f"(gate mismatches={failures}, http failures={http_failures}, "
        f"http checks={len(http_rows)})"
    )
    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
