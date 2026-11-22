# Security-contract analysis — what does Julep actually promise?

**Decisive question:** does Julep guarantee that bundle-supplied source runs
fail-closed in *every* execution tier, or does the operator's native grant
explicitly waive that guarantee?

Sources (all at `fc74d079a18c8124b2627ca4717f5a9c269267db`, verified ==
`origin/main` at analysis time — no upstream fix has landed):

- `julep/registry.py::Registry.register_pure_from_source` docstring
- `docs-site/content/docs/deploy/wasm-tier.md` — "Execution tiers and trust
  boundaries"
- `docs-site/content/docs/internals/specification.md` — §6.5, §6.6
- `docs/plans/2026-06-11-code-as-data-distribution.md` — design doc
- `julep/registry.py::_WASM_GUEST_STDLIB_MODULES`,
  `_validate_portable_source`

## 1. The two pieces of vendor text that appear to conflict

**(a) Registration API contract** — `register_pure_from_source` docstring
(verbatim):

> Register a bundle-sourced pure as the wasm tier WITHOUT host execution.
> The bundle's shipped source is the body of an **untrusted (if signed)
> pure: it must run fail-closed through its selected tier**, never directly
> in the host process.

This is a statement about *all* bundle-sourced pures: the source is
untrusted, and the guarantee is that it "must run fail-closed through its
selected tier." Fail-closed here means the source-validation gate decides
what may execute — the tier is the enforcement point, and the validator is
what makes execution safe.

**(b) Tier documentation** — `wasm-tier.md` (verbatim):

> The **wasm tier** is the default for bundle pures. … Treat this as the
> **untrusted-code-safe tier** for deterministic pure compute.
>
> The **native tier** exists only for bundle pures whose declared dependencies
> are off the curated WASI-wheel set. The worker executes the bundle-shipped
> source as a real OS subprocess in a `uv`-managed venv … This is outside the
> wasm sandbox. `JULEP_PURE_NATIVE_DEPS` is therefore **the operator trust
> boundary: adding a pure name to that allowlist means trusting that bundle's
> source to run as native code on the worker**.

Read alone, (b) supports "the operator explicitly trusts native execution."

## 2. Why the conflict resolves in favour of a vulnerability

The two texts are reconciled by *what the signature and the grant each
cover*:

- The signature (SPEC §6.6) establishes **provenance and integrity only** —
  "bundle identity MUST NOT depend on who signed." It makes no claim that the
  signed content is safe to execute. Signing answers "did an allowlisted
  operator publish these exact bytes," not "is this code safe."
- The grant (`JULEP_PURE_NATIVE_DEPS`, SPEC §6.5) is a per-pure-name decision
  required "at BOTH deploy and worker resolution." The docs describe its
  *purpose* as enabling "bundle pures whose declared dependencies are off the
  curated WASI-wheel set" — i.e. permission to install/run the pure's
  declared dependencies natively.
- The docstring's "fail-closed through its selected tier" is the operative
  safety guarantee for **untrusted** source: whatever tier is selected, the
  source must pass validation that fails closed. The tier changes *where* it
  runs, not *whether* it is validated.

The defect: `_validate_portable_source` **is** the fail-closed check, and it
is applied to native-tier source — but its import allowlist is
`_WASM_GUEST_STDLIB_MODULES`, the *wasm guest's* stdlib list. That list
contains `os`, `subprocess`, `socket`, `ctypes`, `multiprocessing`, `pty`,
`fcntl`, etc. — neutered stubs inside the wasm component, **fully capable
host modules** in a native subprocess. The validator therefore answers "is
this importable in the wasm guest?" instead of "is this safe to run on the
host?" for the tier where the answer actually matters.

So the precise claim is not "Julep runs untrusted code" (the docs disclaim
that for the wasm tier) and not "the grant is meaningless" (it is a real
operator decision). The claim is:

> For `executorTier: "native"` pures, the fail-closed source validation that
> the registration API promises for untrusted bundle source is satisfied by
> an allowlist designed for the wasm guest. Imports that are inert in wasm
> (`os`, `subprocess`, `socket`, `ctypes`, …) execute with full host
> privileges. An operator granting a pure name for its *declared
> dependencies* cannot distinguish "this bundle installs `requests`" from
> "this bundle runs `os`/`subprocess`/`socket` on the worker host" — the
> granted capability silently exceeds the documented one.

## 3. Corroborating evidence — the grant is name-scoped, not content-scoped

`poc/authz/native_grant_scoping.py` (4/4 PASS,
`evidence/authz/native_grant_scoping.stdout`) demonstrates:

- Two **fresh** workers with the same `native_grant` name each accept a
  *different* validly-signed bundle claiming that name — the grant binds a
  name, not a source hash or signer.
- A **warm** worker pins name→source_hash and rejects disagreeing content.
- An unsigned bundle is still rejected — the signature gate is independent.

Consequence: in a fleet with mixed worker ages (rolling deploys, autoscaling,
restarts), the same granted pure name can execute different code on
different workers until each has resolved the same bundle. The grant does not
pin *which* signed bundle it authorizes.

## 4. Deployment scenarios where the boundary actually bites

| Scenario | Exposure |
|---|---|
| A. Operator publishes all bundles, grants native sparingly | Residual: silent capability overreach — grant for deps ⇒ arbitrary host exec for whatever the signed source contains |
| B. Deployment delegates bundle signing to tenant/third-party authors | **High** — any tenant pure granted native (or name-colliding with a granted name on a fresh worker, per §3) yields host RCE; signature proves provenance, not safety |
| C. Release pipeline compromised | High — pipeline holds publish+sign capability; native grant on target worker completes the chain |
| D. Local/dev mode (`julep dev`) | Loopback-only; all-zero dev signing key is public but scope is local — not a production path |

## 5. Remediation architectures

**Architecture A — trusted native execution (documented intent).** Keep
native tier for operator-published bundles: dedicated worker identity, no
host secrets in worker env, egress allowlist — and fix
`_validate_portable_source` to use a **native-tier** allowlist (deny
`os`/`subprocess`/`socket`/`ctypes`/etc., or require them to arrive via
declared deps), so the granted capability matches the implemented one. Also
consider binding the grant to `(name, sourceHash)` rather than name alone,
closing the §3 fresh-worker gap.

**Architecture B — untrusted/third-party bundles.** If bundles from
non-operators are ever executed, the native tier must be a real sandbox:
container/namespace isolation, seccomp, non-root UID, read-only rootfs, no
host env inheritance, explicit egress policy, resource limits. No Python
in-process restriction (import denylists, `__builtins__` filtering, dunder
bans) is a boundary — the researcher-proposed Variant A/B1/B2 mitigations in
`report-hardening-verification.md` are each bypassed or break legitimate
deps (RT-02/RT-03/RT-04).

## 6. CVSS note

`AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = **7.2 (proposed)**. `PR:H` reflects
operator-level publication+signing in the default supported configuration.
Alternatives:

- Delegated signing / pipeline compromise (scenarios B/C): arguable `PR:L`
  → **8.8**.
- If a reviewer treats publication as a *local* privileged operation rather
  than network-reachable: `AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = **6.7
  (Medium)**. `AV:N` is retained because the demonstrated trigger is a
  network-delivered workflow run invoking the registered pure, but the
  bundle-introduction step is operator-side; we flag this as the weakest
  metric and defer to the vendor's deployment model.
