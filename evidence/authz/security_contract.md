# Security-contract analysis — what does Julep actually promise?

**Question:** is `native_venv` execution of bundle source "expected trusted
behaviour" or a broken boundary? This document quotes the vendor's own spec
and docs, then states the defensible vulnerability claim.

Sources (all at `fc74d079a18c8124b2627ca4717f5a9c269267db`):

- `docs-site/content/docs/deploy/wasm-tier.md` — "Execution tiers and trust
  boundaries"
- `docs-site/content/docs/internals/specification.md` — §6.5, §6.6
- `docs/plans/2026-06-11-code-as-data-distribution.md` — design doc
- `julep/registry.py::_WASM_GUEST_STDLIB_MODULES`,
  `_validate_portable_source`

## 1. The documented trust boundary

`wasm-tier.md` is explicit:

> The **wasm tier** is the default for bundle pures. … Treat this as the
> **untrusted-code-safe tier** for deterministic pure compute.
>
> The **native tier** exists only for bundle pures whose declared dependencies
> are off the curated WASI-wheel set. The worker executes the bundle-shipped
> source as a real OS subprocess in a `uv`-managed venv … This is outside the
> wasm sandbox. `JULEP_PURE_NATIVE_DEPS` is therefore **the operator trust
> boundary: adding a pure name to that allowlist means trusting that bundle's
> source to run as native code on the worker**.

SPEC §6.5 adds that the grant must be present "at BOTH deploy and worker
resolution" and that a `native`-tier ref "carries no `envHash` (the venv is
built from the pure's declared deps at the worker…)".

**Reading:** the vendor documents the grant as a *trust decision*, not a
sandbox. Under this contract, an operator who grants a pure name has been told
"this bundle's source will run as native code."

## 2. What the signature does and does not mean

SPEC §6.6: signatures are DETACHED; "bundle identity MUST NOT depend on who
signed"; workers verify the signature against a key allowlist and verify every
content hash. The signature establishes **provenance and integrity** — which
operator key signed these exact bytes — it makes **no claim that the content
is safe to execute**. Safety is delegated entirely to the execution tier
(wasm sandbox vs. native subprocess).

## 3. The gap the finding actually demonstrates

The grant's *documented purpose* is narrow: run a pure whose **declared
dependencies** don't fit the WASI wheel set. The implementation delivers
something broader:

- `_validate_portable_source` is applied to native-tier source, but its import
  allowlist is `_WASM_GUEST_STDLIB_MODULES` — the **wasm guest's** stdlib
  list. That list includes `os`, `subprocess`, `socket`, `ctypes`,
  `multiprocessing`, `signal`, `pty`, `fcntl`, etc., because inside the wasm
  component those modules are neutered stubs.
- On the native tier the same names are **fully capable host modules**.
  `import os` / `import subprocess` therefore pass validation and execute with
  host privileges (RT-01, verified with live exfiltration).
- The validator's existence proves the authors *intended* a restriction on
  bundle source; applying the wasm guest list to the native tier is the
  defect — the check answers "is this importable in the wasm guest?" instead
  of "is this safe to run on the host?".

So the precise claim is **not** "Julep runs untrusted code" — the docs already
disclaim that. The claim is:

> The `native` capability grant is documented and intended as "permission to
> install/run the pure's *declared dependencies*", but the tier executes the
> bundle's *entire source* with unrestricted host imports. An operator who
> grants a pure named `acme.geo.v1` for `requests`-class deps has no way to
> know the same grant silently authorizes `os`/`subprocess`/`socket`/`ctypes`
> host access — a confused-deputy over-broad capability. The source validator
> was meant to bound this and does not.

This survives the "trusted execution" rebuttal: the vulnerability is the
distance between the *granted capability* (dependency installation for named
pures) and the *implemented capability* (arbitrary host code execution for
whatever source the signed bundle contains), plus the fact that the intended
import restriction is wired to the wrong allowlist.

## 4. Deployment scenarios where the boundary actually bites

| Scenario | Exposure |
|---|---|
| A. Operator publishes all bundles, grants native sparingly | Low — grant is an explicit trust decision; residual issue is silent capability overreach (deps → arbitrary exec) |
| B. Deployment delegates bundle signing to tenant/third-party authors (e.g. signs submitted agent code) | **High** — any tenant pure granted native tier (or name-colliding with a granted name on a fresh worker) yields host RCE; signature proves provenance, not safety |
| C. Release pipeline compromised | High — pipeline holds publish+sign capability; native grant on target worker completes the chain |
| D. Local/dev mode (`julep dev`) | Loopback-only; all-zero dev signing key is public but scope is local — not a production path |

## 5. Remediation architectures

**Architecture A — trusted native execution (documented intent).** Keep
native tier for operator-published bundles only: dedicated worker identity,
no host secrets in worker env, egress allowlist, and — critically — fix
`_validate_portable_source` to use a *native-tier* allowlist (deny
`os`/`subprocess`/`socket`/`ctypes`/etc. or require them to come from declared
deps), so the granted capability matches the implemented one.

**Architecture B — untrusted/third-party bundles.** If bundles from
non-operators are ever executed, the native tier must be a real sandbox:
container/namespace isolation, seccomp, non-root UID, read-only rootfs, no
host env inheritance, explicit egress policy, resource limits. No Python
in-process restriction (import denylists, `__builtins__` filtering, dunder
bans) is a boundary — RT-02/RT-03 demonstrate two independent bypasses and
RT-04 shows the fully layered variant breaks legitimate deps.

## 6. CVSS note

`AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = **7.2** is proposed, not definitive.
`PR:H` reflects operator-level publication+signing in the default supported
configuration. Deployment-specific alternatives:

- Scenario B/C above (delegated signing or pipeline compromise): arguable
  `PR:L` → **8.8**.
- If a reviewer reads the native grant itself as the only privilege and
  treats bundle publication as normal developer workflow: still `PR:H` for
  the signing-key requirement, but impact arguments strengthen.
