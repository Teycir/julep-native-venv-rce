# Vendor-facing summary — Julep `native_venv` bundle execution

**Date (UTC):** 2026-11-22T17:43:20Z
**Target:** `julep-ai/julep` `3.0.0rc6` @ `fc74d079a18c8124b2627ca4717f5a9c269267db`  
**Public issue:** [`julep-ai/julep#1632`](https://github.com/julep-ai/julep/issues/1632) (open). The issue cites `GHSA-rhfp-jw6w-wrqq`; that advisory URL currently returns 404, so the GHSA is treated as cited-but-unverified.

## Bottom line

Confirmed in the pinned source tree and local lab:

1. `native_venv` executes bundle-supplied Python source with `exec()` in a host subprocess.
2. `_validate_portable_source` applies `_WASM_GUEST_STDLIB_MODULES` to both tiers, so `os`, `subprocess`, `socket`, `ctypes`, etc. pass validation for native execution.
3. Bundle signatures are detached provenance/integrity checks; `executorTier` is inside signed manifest bytes.
4. The worker-side `JULEP_PURE_NATIVE_DEPS` grant is operator configuration and authorizes pure **names**, not source hashes.
5. A process-level test using four distinct OS worker processes, two allowlisted signers, and one shared artifact store shows:
   - accepted workers resolve **and invoke** different signed bundles under the same granted name, returning distinct `variant: X` / `variant: Y` results;
   - a warm worker pins `name -> source_hash` only within its process;
   - a fresh replacement worker accepts and executes the alternate bundle;
   - unsigned bundles and non-allowlisted signers are still rejected.

This grant-scoping result is a supporting deployment-consistency observation, not a second RCE, signature bypass, grant bypass, or unauthorized-access finding.

Not established:

- No unauthenticated or ordinary client-role path to introduce executable bundle source was found.
- No live production deployment was compromised; all tests are local source-tree/application tests.
- Whether the observed behavior violates Julep's intended security contract is unresolved and is the main question for vendor review.

## Contract question for Julep

The API docstring for `register_pure_from_source` says bundle source is:

> the body of an **untrusted (if signed) pure: it must run fail-closed through its selected tier**

The native-tier docs say:

> `JULEP_PURE_NATIVE_DEPS` is therefore **the operator trust boundary: adding a pure name to that allowlist means trusting that bundle's source to run as native code on the worker**.

Please clarify which guarantee is intended:

- **Trusted-native reading:** the grant authorizes the exact signed source to run with host privileges; source validation is not expected to provide OS isolation.
- **Fail-closed reading:** bundle source remains untrusted in every tier and must pass tier-appropriate validation before execution.

If the fail-closed reading is intended, the current implementation has a validation gap because the wasm guest's import allowlist is reused for host execution.

## Severity posture

Proposed, deployment-dependent — these are conditional scoring hypotheses, not confirmed CVSS assessments; the vendor should validate the vector for the actual deployment and attacker path.

| Assumption / attacker path | Vector | Score |
|---|---|---|
| Default operator-controlled publication/signing/grant; network-triggered workflow | `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` | 7.2 High (proposed upper bound) |
| Delegated signing, tenant-held admin keys, or publication-pipeline compromise gives the attacker an allowlisted signature path | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.8 High |
| Bundle introduction treated as local privileged operation | `AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` | 6.7 Medium |

`AV:N` is the weakest metric because bundle introduction is operator-side while the demonstrated trigger is a network-delivered workflow run. The 8.8 case applies only if delegated signing or pipeline compromise actually gives an attacker a worker-allowlisted signature path; it is not established for the default configuration.

## Requested actions

1. Confirm the intended `native_venv` trust contract and update docs/spec accordingly.
2. If native execution is trusted-by-grant, document that explicitly and isolate workers: dedicated identity, no host secrets, no unnecessary mounts, egress allowlist.
3. If native execution must remain fail-closed, replace `_WASM_GUEST_STDLIB_MODULES` with a native-tier source policy and bind grants to `(name, sourceHash)` or another signed content identifier.
4. If untrusted or third-party bundles are in scope, run native pures under real OS isolation: container/namespace, seccomp, non-root UID, read-only rootfs, no inherited host environment, explicit egress policy, and resource limits.
5. Do not rely on Python import denylists, dunder bans, or restricted `__builtins__` as a security boundary; the included hardening verification shows bypasses and compatibility failures.

## Evidence index

- [`report-rt01.md`](report-rt01.md) — primary RT-01 report with live host-execution/exfiltration proof.
- [`report-hardening-verification.md`](report-hardening-verification.md) — researcher-proposed mitigation bypasses and compatibility results.
- [`evidence/authz/security_contract.md`](evidence/authz/security_contract.md) — contract analysis, grant-scoping evidence, deployment scenarios, and CVSS notes.
- [`evidence/authz/attacker_model.md`](evidence/authz/attacker_model.md) — enumeration of bundle-source entry paths.
- [`evidence/authz/authorization_analysis.md`](evidence/authz/authorization_analysis.md) — route/authentication/signature/grant tests.
- [`poc/authz/native_grant_scoping.py`](poc/authz/native_grant_scoping.py) — process-level grant-scoping test.
- [`SHA256SUMS.txt`](SHA256SUMS.txt) — repository integrity manifest.
