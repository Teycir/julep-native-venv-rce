# Authorization and Exploitability Assessment — Supporting Technical Appendix

**Status:** supporting appendix to RT-01/RT-02/RT-03/RT-04. Not a separate
vulnerability; no standalone severity is claimed.

- Target: `julep-ai/julep` `3.0.0rc6`
- Commit pinned: `fc74d079a18c8124b2627ca4717f5a9c269267db` (upstream `main`)
- Source tree at test time: clean (`git status --porcelain` empty)
- Generated (UTC): 2026-11-22T15:50:36Z
- Environment: Python 3, FastAPI 0.138.1, httpx 0.28.1, cryptography 49.0.0

## Question

Does the `native_venv` escape chain (RT-01) require more than ordinary
authenticated access, and what stops a non-admin from introducing an executable
bundle? The answer determines whether RT-01 is "admin-only expected behaviour"
or a privilege-boundary failure.

## Method

1. **Structural AST inventory** (`route_authz_check.py`) — recursively walks
   `julep/server/routes/**/*.py`, extracts every `APIRouter` (including
   non-`router` variable names and their `prefix`/`dependencies`), every route
   decorator, and resolves `Depends(...)` transitively through parameter
   annotations and handler bodies.
2. **Collision-safe resolution** — functions are indexed as `module:name`; bare
   names are only accepted when exactly one definition exists, so same-named
   helpers in different modules cannot silently resolve to the wrong file.
3. **Inherited router dependencies** — `app.include_router(..., dependencies=[])`
   is parsed and merged into each route's dependency set. Result for this
   revision: **none** — authorization is attached per-router or per-handler,
   not at mount time.
4. **Structural gate verification** — a gate counts as verified only when the
   AST contains an `if <...>.role <op> "<role>":` guard whose body raises with
   `status_code=403`. String presence alone is not accepted.
5. **Live production wiring** (`test_production_router_wiring.py`) — imports the
   real `julep.server.app`, walks the mounted `APIRoute.dependant` trees, and
   issues unauthenticated requests through `TestClient`. FastAPI 0.138 defers
   `include_router` expansion into `_IncludedRouter` placeholders, so routes are
   introspected from each module's `router.routes` and the app is exercised
   inside the `TestClient` context.
6. **Cryptographic signature proof** (`bundle_signature_proof.py`) — exercises
   `_signature_blob`, worker `_verify_signature`, `_allowed_signers`, and
   `resolve_and_register`, plus a full `publish_bundle` → `LocalDirArtifactStore`
   → worker verification round trip with a temporary Ed25519 key.

## Results

### Route inventory — 25 routes, 10 mutating, 0 ungated

| Method | Path | Handler | Gate |
|---|---|---|---|
| PUT | `/artifacts/{sha256}` | `put_blob` | `require_admin` |
| POST | `/releases` | `publish_release` | `require_admin` |
| POST | `/deployments` | `activate_deployment` | `require_admin` |
| POST | `/runs` | `start_run` | `require_client` |
| POST | `/runs/{run_id}/cancel` | `cancel_run` | `require_client` |
| POST | `/runs/{run_id}/terminate` | `terminate_run` | `require_client` |
| POST | `/runs/{run_id}/signals/human` | `signal_human_gate` | `require_client` |
| PUT | `/secrets/{name}` | `put_secret` | `require_admin` |
| POST | `/secrets/{name}/archive` | `archive_secret` | `require_admin` |
| DELETE | `/secrets/{name}` | `delete_secret` | `require_admin` |

Unauthenticated GETs are limited to `/health` and `/health/ready` (liveness
probes, no state). All ten mutating routes returned **401** without credentials
in the live wiring test (10/10).

### Gate semantics (verified structurally)

- `require_key` — requires `Authorization: Bearer`, delegates to
  `KeyRing.authenticate`; `hmac.compare_digest` confirmed.
- `require_admin` — `if key.role != "admin": raise ...403`.
- `require_worker` — `if key.role != "worker": raise ...403`.
- `require_client` — `if key.role == "worker": raise ...403` (admin and client
  pass; worker excluded).

### Signature chain (9/9 assertions)

- Signature object is `{algo: "ed25519", bundleHash, publicKey, sig}`.
- Worker `_verify_signature` accepts an authentic manifest and rejects a
  tampered manifest and a wrong public key.
- `resolve_and_register` rejects an unsigned bundle and a signer outside the
  allowlist; it accepts an allowlisted signer's signature (crypto accepted;
  manifest validation then stops a synthetic manifest).
- Allowlist parsing normalises hex and rejects non-hex.
- Full `publish_bundle` → store → worker verification succeeds
  (`bundleHash=f214e6c3981fe576…`).
- `POST /releases` accepts a prebuilt `ApplicationRelease` and does **not**
  sign (`signs_bundle=False`); signing requires the operator-held
  `JULEP_BUNDLE_SIGNING_KEY`.

## Limitations (explicit)

- The route matrix is **static analysis plus a live wiring check**, not a formal
  proof of the deployed service. Runtime middleware, reverse proxies, and
  deployment-specific key distribution are out of scope.
- The live wiring test asserts authentication rejection (401) and gate
  presence; it does not exercise authorization success paths against a real
  database-backed control plane.
- Signature tests use synthetic manifests and temporary keys; they prove the
  verification logic, not any particular deployment's allowlist contents.
- FastAPI 0.138's lazy `_IncludedRouter` means `app.routes` is not a complete
  inventory before startup; the test accounts for this by using module routers
  plus a `TestClient` context.

## Conclusion

Ordinary authenticated clients cannot reach the mutating administrative surface
(artifacts, releases, deployments, secrets) or publish a bundle: those paths
require an admin key, and native execution additionally requires a signature
from an allowlisted operator key. RT-01 therefore remains **High (7.2)** with
`PR:H`, not Critical: exploitation requires either admin credentials or
compromise of the operator signing key. If a deployment issues admin keys to
tenants, or exposes the signing key, RT-01 escalates to Critical.

## Addendum (2026-11-22, second pass)

Two gaps in the first pass were closed:

1. **Production application, not assembled routers.** `test_production_app_authz.py`
   builds the app via the real factory `julep.server.app.create_app` with real
   `ServerSettings`/`KeyRing`/lifespan and asserts the *exact* expected gate per
   route (no "any gate" acceptance), then runs 125 HTTP checks across
   missing/bad/admin/client/worker identities. Result: PASS — see
   `production_app_authz.stdout`.
2. **Native-grant signature binding.** `native_grant_binding.py` exercises
   `resolve_and_register` on manifests that actually declare
   `executorTier:"native"`: valid signature+grant resolves (including via
   `JULEP_PURE_NATIVE_DEPS`); unsigned, tampered-manifest, empty/wrong grant,
   and non-allowlisted-signer variants are all rejected. Result: 7/7 — see
   `native_grant_binding.stdout`.

Structural consequence: `executorTier` is inside the signed manifest bytes —
the tier claim cannot be modified without invalidating the Ed25519 signature.
The `native_grant` itself is worker-side operator configuration
(`JULEP_PURE_NATIVE_DEPS`), not part of the signed bundle.
