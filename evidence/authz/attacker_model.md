# Attacker-model analysis — can a non-privileged actor reach `native_venv`?

**Question (triage-critical):** can someone who does not control Julep's
signing infrastructure introduce executable code that reaches a `native_venv`
worker? This document enumerates every code path by which pure source can
enter a worker registry and identifies who controls each gate.

Source tree: `julep-ai/julep` @ `fc74d079a18c8124b2627ca4717f5a9c269267db`
(`3.0.0rc6`). Analysis date: 2026-11-22.

## 1. Every path that registers pure source

| # | Path | Entry point | Who controls it |
|---|------|-------------|-----------------|
| 1 | `publish_bundle()` → `Deployment.publish()` | `julep` CLI (`deploy`/`application` commands), `cli/_resolve_child.py` | Operator holding `JULEP_BUNDLE_SIGNING_KEY` (private Ed25519 seed, env or file) |
| 2 | `resolve_and_register()` via `resolve_entries()` | Worker activation: `bundle` refs inside `FlowInput` | Refs originate from `pipeline.bundle_ref`, written at publish time (path 1) |
| 3 | `resolve_and_register()` via `verifyPures` effect | Same `FlowInput.bundle` channel | Same as 2 |
| 4 | `load_bundles_from_env()` (`JULEP_BUNDLES`) | Worker startup | Operator env var |
| 5 | `register_pure_from_source()` (`julep/purity.py`) | In-process authoring API | Whoever already executes Python in the authoring process — not network-reachable |

The FastAPI control plane **never signs bundles**. `POST /deployments` and
`POST /releases` are `require_admin`, but they only *activate* releases that
were already published out-of-band by the CLI. There is no tenant-facing
"submit code → get it signed" endpoint in this revision.

## 2. Client-reachable input audit

- `POST /runs` (`RunRequest`, `extra="forbid"`): fields are `release`,
  `pipeline`, `input`, `sessionId`, `principal`, `queueLanes`, `runId`,
  `secrets`, `mcpPreflight`. **No `bundle` field** — bundle pointers cannot be
  injected through run input; `FlowInput.bundle` is populated server-side from
  `pipeline.bundle_ref` (`julep/server/temporal.py:120`,
  `julep/server/local.py:679,703`).
- `PUT /artifacts/{sha256}`: `require_admin` — artifact store writes are
  admin-only, so an attacker cannot plant manifest/signature blobs even if
  they learned a valid hash.
- `PUT/DELETE/POST /secrets/*`: `require_admin`.
- `GET /secrets/{name}/value`: `require_worker` + `worker_secret_allowlist`.

## 3. Signature custody

- Production path (`julep application` env commands,
  `cli/application.py:217-239`): validates that the
  `JULEP_BUNDLE_SIGNING_KEY` public key is present in the worker's
  `JULEP_BUNDLE_ALLOWED_SIGNERS` — the tool *enforces* signer∈allowlist.
- `cli/keygen.py`: generates the keypair; operator distributes the public key
  to workers and keeps the seed secret.
- **Local/dev caveat:** `cli/_resolve_child.py:27` defaults
  `JULEP_BUNDLE_SIGNING_KEY` to `"0"*64` (all-zero seed) when the artifact
  store is local (non-`s3://`). The corresponding public key is therefore
  *public knowledge*. This only affects the local CLI publishing path; the
  local control plane binds loopback-only by default and requires explicitly
  configured API keys for non-loopback binds (`server/local.py:994-999`).
  A deployment that exposes a dev-mode stack *and* allowlists the zero-key
  pubkey would let anyone sign bundles — but that is a misconfiguration of an
  explicitly-local development mode, not a production path.

## 4. Grant scoping observation

`native_grant` / `JULEP_PURE_NATIVE_DEPS` authorizes pure **names**, not
content hashes (`worker_store.py:334-339` checks
`verified_pure.name not in native_grants`). Mitigating factor: after first
registration the registry pins `name → source_hash` and rejects drift
(`worker_store.py:306-313`), so a granted name cannot silently change source
on an already-initialized worker. On a *fresh* worker, whichever validly
signed bundle resolves first claims the name — still gated by the signature.

## 5. Verdict

**No path was found for an ordinary tenant, client-role API key, or
unauthenticated attacker to introduce executable source onto a `native_venv`
worker.** Every route to `resolve_and_register`/`register_pure_from_source`
terminates at either (a) an admin API call plus an operator-held signing key,
or (b) operator-controlled worker env vars.

The vulnerability is therefore best characterized as a **sandbox-boundary
failure**, not an unauthenticated RCE:

- The `native_venv` tier's *purpose* is running dependency-bearing pures; its
  *actual* capability is unrestricted host `exec()`. Nothing in the tier
  confines execution to the declared PEP 723 dependency set — `import os`
  passes `_validate_portable_source` (RT-01).
- Any principal able to get *any* bundle signed for a granted pure name
  obtains full host RCE as the worker OS user — a much larger capability than
  "install declared dependencies" implies. This includes a compromised
  release pipeline, a delegated/tenant signing workflow (if a deployment
  offers one — none exists in this revision), or an operator tricked into
  publishing attacker-influenced source.
- The documented alpha runbook (`docs/ops/wasm-tier-runbook.md`) states
  "Third-party dependencies and the native dependency fallback are not
  supported" — i.e. the native tier is an explicit opt-in escape hatch, which
  strengthens the "trusted-only" reading but does not change the fact that
  the tier provides no isolation when enabled.

**Honest severity statement:** in the default supported configuration,
exploitation requires operator-level publication capability (`PR:H`, CVSS
7.2). The finding's value is that the tier boundary is broken by design —
recommendation stands: execute native pures under real OS isolation
(container/namespace/seccomp/non-root/ro-fs/egress allowlist) rather than
in-process Python restrictions.
