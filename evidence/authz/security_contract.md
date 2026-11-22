# Security-contract analysis — what does Julep actually promise?

**Decisive question:** does Julep guarantee that bundle-supplied source runs
fail-closed in *every* execution tier, or does the operator's native grant
explicitly waive source-level restrictions for `native_venv`?

The evidence below establishes the implementation facts and the two
defensible readings of the vendor documentation. It does **not** conclusively
resolve which contract Julep intends; that is the question we ask the vendor
to confirm.

Sources (all at `fc74d079a18c8124b2627ca4717f5a9c269267db`, verified ==
`origin/main` at analysis time — no upstream fix has landed):

- `julep/registry.py::Registry.register_pure_from_source` docstring
- `docs-site/content/docs/deploy/wasm-tier.md` — "Execution tiers and trust
  boundaries"
- `docs-site/content/docs/internals/specification.md` — §6.5, §6.6
- `docs/plans/2026-06-11-code-as-data-distribution.md` — design doc
- `julep/registry.py::_WASM_GUEST_STDLIB_MODULES`,
  `_validate_portable_source`
- `julep/worker_store.py::resolve_and_register`

## 1. The vendor texts

**(a) Registration API contract** — `register_pure_from_source` docstring
(verbatim):

> Register a bundle-sourced pure as the wasm tier WITHOUT host execution.
> The bundle's shipped source is the body of an **untrusted (if signed)
> pure: it must run fail-closed through its selected tier**, never directly
> in the host process.

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

**(c) Signature semantics** — SPEC §6.6 and `wasm-tier.md` describe ed25519
signatures as detached provenance/integrity checks. They establish which
allowlisted operator signed exact manifest bytes; they do not establish that
the signed source is safe to execute.

## 2. What is established

These points are implementation facts, not interpretations:

1. `register_pure_from_source` accepts `tier="native_venv"` and calls
   `_validate_portable_source` without passing the tier.
2. `_validate_portable_source` uses `_WASM_GUEST_STDLIB_MODULES` as its import
   allowlist. That list contains `os`, `subprocess`, `socket`, `ctypes`,
   `multiprocessing`, `pty`, `fcntl`, etc. — neutered/stubbed modules in the
   wasm guest but fully capable host modules in a native subprocess.
3. `native_venv_executor._DRIVER` executes the bundle source with
   `exec(source, {"pure": pure})` in a host Python subprocess.
4. `executorTier:"native"` is inside the signed manifest bytes; the worker-side
   `native_grant` is operator configuration, not part of the signature.
5. `JULEP_PURE_NATIVE_DEPS` authorizes pure **names**, not source hashes or
   signer identities. The worker's signer allowlist remains a separate control.

## 3. The two defensible contract readings

### Reading A — native grant is the intended trust boundary

Under this reading, the wasm tier is the untrusted-code tier, while
`JULEP_PURE_NATIVE_DEPS` explicitly authorizes a bundle's source to run as
native code. The signature, grant, release authorization, and worker
configuration together form the fail-closed boundary; once granted, the
native tier is trusted execution and source restrictions are not expected to
provide OS isolation.

If this is the intended contract, RT-01 is better described as a
**dangerous-capability / hardening issue** than a contract violation: the
tier does what the grant says, but deployments may not realize that "trusted
native code" includes arbitrary host `exec()`.

### Reading B — bundle source must remain fail-closed in every tier

Under this reading, the `register_pure_from_source` docstring applies to all
bundle-sourced pures: source is "untrusted (if signed)" and "must run
fail-closed through its selected tier." `_validate_portable_source` is the
source-validation gate; using the wasm guest's allowlist for native-tier
source means the gate answers "is this importable in wasm?" rather than "is
this appropriate for host execution?".

If this is the intended contract, RT-01 is a **fail-closed validation gap**:
the implemented capability exceeds the capability implied by validation and
the API wording.

### Why we do not claim the question is resolved

The tier documentation explicitly says the native tier is outside the wasm
sandbox and that the grant is the operator trust boundary. That is strong
evidence for Reading A. The API docstring's "untrusted … fail-closed through
its selected tier" language and the presence of `_validate_portable_source`
are strong evidence for Reading B. The public docs do not state whether the
native grant waives source-level restrictions or merely selects a less
isolated executor after validation.

**Requested vendor clarification:** does `JULEP_PURE_NATIVE_DEPS` authorize
*the exact signed source bytes* to run with host privileges, or only
*dependency installation for a pure whose source still passes tier-appropriate
validation*?

## 4. Corroborating evidence — grant scoping across worker processes

`poc/authz/native_grant_scoping.py` was rerun as a **process-level** test
(`evidence/authz/native_grant_scoping.stdout`, 7/7 PASS). It uses four real OS
subprocesses, one shared `LocalDirArtifactStore`, the same granted pure name,
the same `JULEP_PURE_NATIVE_DEPS` value, and **two distinct allowlisted
Ed25519 signing keys**:

| Worker process | Requests | Result |
|---|---|---|
| A | bundle X signed by key A, then bundle Y signed by key B | X accepted **and invoked** → `variant: X`; Y rejected by process-local `name -> source_hash` pin |
| B | bundle Y signed by key B, then unsigned bundle Z | Y accepted **and invoked** → `variant: Y`; Z rejected as unsigned |
| C | bundle Y signed by key B | accepted **and invoked** → `variant: Y` — fresh process has no prior pin |
| D | bundle Y signed by key B, allowlist contains only key A | rejected — signer allowlist still enforced |

Observed source hashes differed (`pure:b8d35235a88e9eb5` for X,
`pure:fe41aa003ac58267` for Y), the four worker PIDs were distinct, and the
invocations returned the expected per-bundle `variant` values rather than
stopping at registration.

Consequences:

- The grant binds a pure **name**, not a particular source hash.
- Across fresh workers/processes, different validly signed bundles from
  different allowlisted signers can claim the same granted name and actually
  execute under it.
- The name→hash pin is **process-local**; it does not survive worker restart
  or replacement. A fleet with mixed worker ages or rolling deployments can
  execute different signed content under the same granted name until all
  workers resolve the same bundle reference.
- This is a deployment-consistency observation, not an independent RCE: every
  executed bundle still required a valid signature from a worker-allowlisted
  signer and the operator grant.

Limitations: the test exercises `resolve_and_register` plus `get_pure(...)`
invocation in fresh Python processes with a local artifact store; it does not
model Temporal workflow replay, control-plane release selection, or production
worker lifecycle beyond process restart/replacement.

## 5. Deployment scenarios where the boundary matters

| Scenario | Exposure |
|---|---|
| A. Operator publishes all bundles, grants native sparingly | Residual risk depends on Reading A/B: either trusted-native hardening or fail-closed validation gap |
| B. Deployment delegates bundle signing to tenant/third-party authors | Highest exposure — any granted or name-colliding bundle yields host RCE; signature proves provenance, not safety |
| C. Release pipeline compromised | High — pipeline holds publish+sign capability; native grant on target worker completes the chain |
| D. Local/dev mode (`julep dev`) | Loopback-only; all-zero dev signing key is public but scope is local — not a production path |

## 6. Remediation request

1. **Clarify the contract.** State explicitly whether `native_venv` bundle
   source is trusted-by-grant or must pass tier-appropriate fail-closed
   validation.
2. **If native is trusted execution:** keep it operator-only, use dedicated
   worker identities, keep host secrets out of the worker environment, apply
   network egress allowlists, and consider binding grants to
   `(name, sourceHash)` rather than name alone.
3. **If native must remain fail-closed:** replace `_WASM_GUEST_STDLIB_MODULES`
   with a native-tier allow/deny policy that reflects host capabilities, and
   persist the name→source-hash pin across worker restarts or bind the grant
   to signed content.
4. **If untrusted/third-party bundles are in scope:** run native pures under
   real OS isolation — container/namespace, seccomp, non-root UID, read-only
   rootfs, no inherited host environment, explicit egress policy, resource
   limits. Python import denylists, dunder bans, and restricted builtins are
   not a boundary (see `report-hardening-verification.md`).

## 7. CVSS note

`AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = **7.2 (proposed upper bound)**.
`PR:H` reflects operator-level publication/signing plus worker grant in the
default supported configuration. Alternatives:

- Delegated signing / pipeline compromise (scenarios B/C): arguable `PR:L`
  → **8.8**.
- Conservative reading where bundle introduction is a local privileged
  operation rather than network-reachable: `AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`
  = **6.7 (Medium)**.

`AV:N` remains the weakest metric: the demonstrated trigger is a
network-delivered workflow run invoking the registered pure, while bundle
introduction is operator-side. We retain 7.2 only as a proposed score pending
the vendor's deployment model and contract clarification. All scores are
conditional hypotheses: 8.8 applies only if delegated signing or pipeline
compromise gives an attacker a worker-allowlisted signature path, and the
vendor should select the vector for the actual deployment.
