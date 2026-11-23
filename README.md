# Julep Native Execution Security Assessment — Host RCE, Trust Boundaries and Python Hardening

Start with [`vendor-facing-report.md`](vendor-facing-report.md) for vendor triage; the remainder of this repository is the supporting technical evidence archive.

Coordinated vulnerability disclosure for `julep-ai/julep`.

## Plain-language summary

Julep can run bundle code in a locked sandbox (`wasm`) or directly on the host (`native_venv`). The native mode is intentionally less isolated, but the source checks reuse the sandbox's allowed-module list. That means code allowed to run natively can still ask for host powers like running commands, opening sockets, or reading process/environment data.

In the tested version, a properly signed bundle with a worker-side native grant could execute host commands and exfiltrate data; we proved this end-to-end. The catch: this is not a normal-user bug in the default setup. It needs the operator-side publication/signing path plus the worker grant. The open question is whether Julep intended native mode to be trusted host execution or still fail-closed for bundle source.

Why it matters: if native mode is meant to be trusted-only, the risk is that grants/deployments may be broader than operators expect; if bundle source is meant to stay untrusted, the current checks do not provide a real boundary. In either case there is a real issue to resolve — what changes is the gravity: trusted-native intent makes it an isolation/documentation/grant-scoping hardening problem, while fail-closed intent makes it a security validation bug.

## Executive summary

The `native_venv` execution tier runs bundle-supplied source with
`exec(source, {"pure": pure})` in a host subprocess. A signed bundle containing
`import os` / `import subprocess` achieves host RCE and data exfiltration —
verified end-to-end with a live listener (`poc/rt01/`, `evidence/rt01/`).

**RT-01 — primary finding, High 7.2 (proposed upper bound).**
`AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`. Exploitation must satisfy **four
distinct controls**: (1) ability to introduce a valid signed bundle through
the deployment's publication pipeline (CLI `deploy`/`application` commands —
the control plane never signs), (2) an Ed25519 signature from a
worker-allowlisted operator key, (3) a worker-side `JULEP_PURE_NATIVE_DEPS`
grant naming the pure, and (4) admin release/deployment authorization where
the deployment path requires it (`POST /releases`, `POST /deployments` are
`require_admin`). Compromising any one alone is not sufficient. Deployment
variants that delegate signing to tenants or expose admin keys argue `PR:L`
(8.8); if publication is treated as a *local* privileged operation,
`AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 6.7 (Medium) — `AV:N` is retained
because the trigger is a network-delivered workflow run, but bundle
introduction is operator-side (see `security_contract.md` §7). Whether this is
a contract violation or a dangerous trusted-native capability depends on the
vendor clarification requested in `security_contract.md` §3.

**RT-02 / RT-03 — remediation bypasses, not independent vulnerabilities.**
Researcher-proposed hardening variants (Variant A: tier-aware import
denylist + reflection bans; Variant B1: restricted `__builtins__`; Variant B2:
layered combination — tracked in `julep-ai/julep#1632`, a researcher-filed
proposal, **not** vendor-deployed remediation) are bypassable via
`operator.attrgetter("__globals__")(pure)["__builtins__"]` and
`().__class__.__base__.__subclasses__()` → `sys.modules["os"]`. These target a
*proposed* fix, not deployed code; they inherit RT-01's prerequisites.

**RT-04 — informational.** The fully layered variant (B2) blocks the tested
payloads but also blocks legitimate `import packaging` — the exact capability
the native tier exists to provide. In-process Python restrictions are not a
security boundary; the fix is OS-level sandboxing.

| ID | Severity | CVSS 3.1 | CWE | Title |
|----|----------|----------|-----|-------|
| RT-01 | High | 7.2 proposed | CWE-94 | `native_venv` tier executes arbitrary bundle source → host RCE |
| RT-02 | Remediation bypass | — | CWE-693 | Tier-aware import denylist bypassed via `attrgetter`/`__globals__` |
| RT-03 | Remediation bypass | — | CWE-693 | Restricted `__builtins__` bypassed via `__subclasses__` → `sys.modules["os"]` |
| RT-04 | Informational | — | — | Layered controls block payloads but break legitimate `import packaging` |

Public reference: upstream issue [`julep-ai/julep#1632`](https://github.com/julep-ai/julep/issues/1632) (open; created 2026-10-16, body says originally reported 2026-09-09). The issue cites `GHSA-rhfp-jw6w-wrqq`, but that advisory URL currently returns 404 — treat the GHSA as cited-but-unverified until publication is confirmed.

## Reports

- [`vendor-facing-report.md`](vendor-facing-report.md) — concise disclosure summary for vendor triage
- [`report-rt01.md`](report-rt01.md) — original finding: `native_venv` host code execution, verified with live exfiltration (`poc/rt01/`, `evidence/rt01/`)
- [`report-hardening-verification.md`](report-hardening-verification.md) — verification/addendum: researcher-proposed hardening variants A/B1/B2, bypass payloads, patch diffs, 14-assertion run matrix (`poc/hardening/`, `evidence/hardening/`)
- [`evidence/authz/authorization_analysis.md`](evidence/authz/authorization_analysis.md) — supporting appendix: route authz inventory, authentication decisions, signature verification, native-grant binding
- [`evidence/authz/attacker_model.md`](evidence/authz/attacker_model.md) — complete enumeration of pure-source entry paths and attacker prerequisites
- [`evidence/authz/security_contract.md`](evidence/authz/security_contract.md) — vendor-documented trust boundary, signature semantics, the unresolved native-tier contract question, and deployment scenarios

## Affected

- `julep-ai/julep` `3.0.0rc6`, commit `fc74d079a18c8124b2627ca4717f5a9c269267db`
- Scope: `julep/registry.py::_validate_portable_source`, `Registry.register_pure_from_source`, `julep/execution/native_venv_executor.py::_DRIVER`, `julep/worker_store.py::resolve_and_register`
- Configuration: self-hosted control plane + `native_venv` worker, Ed25519-signed bundles

## Disclosure status — read first

This repository is **private**. It is the complete proof package — every claim
is demonstrated by artifacts under `poc/` and `evidence/` (raw transcripts,
SHA256 manifests, timestamps, patch diffs, runnable exploit scripts).

| When (UTC) | Step |
|---|---|
| 2026-11-21 | RT-01 finding verified in local authorised lab |
| 2026-11-22 | Hardening verification engagement: variants A/B1/B2 implemented, bypass matrix executed |
| 2026-11-22 | Authorization analysis: route inventory, auth decisions, signature chain, native-grant binding |
| 2026-11-22 | Contract/grant-scoping revision: process-level signer test, GHSA status corrected, vendor summary added |
| 2026-11-22 | Final revision: process-level grant-scoping test now invokes the registered pure; titles normalized |
| 2026-11-22 | Reporting revision: status/CVSS conditionality/grant-scoping impact clarified |
| 2026-11-22T17:54:26Z | Disclosure email sent to `developers@julep.ai` (cc `diwank@julep.ai`) with `julep-native-venv-rce.zip` evidence package |
| 2026-11-23 18:12Z | Upstream `julep-ai/julep` re-checked at HEAD `fc74d07` (the affected 3.0.0rc6 commit itself — HEAD == affected commit). **No fix**: `_WASM_GUEST_STDLIB_MODULES` still contains `os`/`subprocess`/`socket`/`ctypes`; `_validate_portable_source` still applies it to `native_venv`; `exec()` still runs bundle source in host subprocess. Only tag is v3.0.0rc5 — no v3.0.0rc6 release. |
| pending | Vendor response / triage / CVE assignment |

## Authorization analysis — attacker prerequisites

The chain `external user → API → bundle publication → signature verification →
native grant → worker execution` was tested at four levels:

1. **Structural AST inventory** (`poc/authz/route_authz_check.py`) — all 25
   routes resolved transitively; 10 mutating, all gated, 0 ungated.
2. **Production application** (`poc/authz/test_production_app_authz.py`) — the
   real app built via `julep.server.app.create_app` (not a re-assembled
   FastAPI). All 25 routes' dependant trees asserted to carry the *exact*
   expected gate, and 125 HTTP checks confirm 401/403/pass per role
   (`evidence/authz/production_app_authz.stdout`). Result: **PASS**.
3. **Authentication decisions** (`poc/authz/test_auth_decisions.py`) — 23/23:
   admin/client/worker/missing/bad across all three gates.
4. **Signature + native-grant binding** (`poc/authz/bundle_signature_proof.py`,
   `poc/authz/native_grant_binding.py`) — `executorTier:"native"` lives inside
   the signed manifest bytes, so it cannot be flipped post-signing; the
   worker-side `native_grant` (`JULEP_PURE_NATIVE_DEPS`) is operator config,
   enforced at resolution. 8/8 binding assertions pass, including direct
   `executorTier`-removal tampering and the env-var grant path.

Conclusion: ordinary client credentials cannot publish bundles or reach
mutating admin routes. A full path enumeration
([`evidence/authz/attacker_model.md`](evidence/authz/attacker_model.md)) found
**no route for an unauthenticated or client-role attacker** to introduce
executable source onto a `native_venv` worker — every path terminates at an
operator-held signing key, the publication pipeline, or operator env vars.
The registration API's docstring says bundle source is "the body of an
**untrusted (if signed) pure: it must run fail-closed through its selected
tier**," while the tier docs call `JULEP_PURE_NATIVE_DEPS` "the operator trust
boundary" for source running "as native code." Those texts support two
defensible readings — trusted-native execution versus fail-closed validation
in every tier — so the contract question is explicitly left for vendor
clarification in
[`evidence/authz/security_contract.md`](evidence/authz/security_contract.md).
The implementation fact is narrower and still important:
`_validate_portable_source` applies the wasm guest's stdlib allowlist
(`os`, `subprocess`, `socket`, `ctypes` are permitted — neutered stubs in wasm
but fully capable on the host) to native-tier source.
Corroborating process-level scoping test
([`poc/authz/native_grant_scoping.py`](poc/authz/native_grant_scoping.py),
7/7 PASS): four distinct OS worker processes, two allowlisted signing keys,
and one shared artifact store show the grant binds a pure *name*, not content
— accepted workers resolve **and invoke** the pure, returning distinct
`variant: X` / `variant: Y` results under the same granted name; a warm
worker pins name→hash only within its process, a fresh worker executes the
alternate signed bundle, and a non-allowlisted signer is still rejected.
This is a supporting deployment-consistency observation, not a second RCE or
an unauthorized-access finding.
This is why RT-01 is scored `PR:H` (7.2 proposed upper bound), not `PR:L`
(8.8); delegated signing or pipeline compromise argues 8.8, and the
conservative `AV:L` reading is 6.7 Medium. All numeric scores are conditional
hypotheses pending vendor validation of the deployment-specific attack path.

## Recommendation

Two architectures, per `security_contract.md` §6:

- **A — trusted native execution (if that is the intended contract):** keep
  the tier for operator-published bundles; fix `_validate_portable_source` to
  use a *native-tier* allowlist or explicitly document that the grant waives
  source restrictions; dedicated worker identity, no host secrets, egress
  allowlist, and consider binding grants to `(name, sourceHash)`.
- **B — untrusted/third-party bundles:** real OS isolation — container /
  namespace, seccomp, non-root UID, read-only rootfs, no host env, explicit
  egress policy, resource limits. Python in-process restrictions are not a
  boundary (RT-02/RT-03 bypasses; RT-04 compatibility break).



## Fix verification — upstream `julep-ai/julep` HEAD `fc74d079a18c8124b2627ca4717f5a9c269267db` (2026-11-23 18:12 UTC)

Cloned `https://github.com/julep-ai/julep.git` at HEAD `fc74d079a18c8124b2627ca4717f5a9c269267db`
— **which is the affected commit itself** (the report's audited version `3.0.0rc6`). Inspected
`julep/registry.py`, `julep/execution/native_venv_executor.py`, `julep/worker_store.py`.

| Check | Result |
|---|---|
| HEAD commit | `fc74d079a18c8124b2627ca4717f5a9c269267db` (= affected 3.0.0rc6 commit) |
| Newer release tag | None — only `v3.0.0rc5` exists; no `v3.0.0rc6` tag |
| Commits after affected commit | None (it is HEAD) |
| `_WASM_GUEST_STDLIB_MODULES` contains `os`, `subprocess`, `socket`, `ctypes` | **YES — unchanged** |
| `_validate_portable_source` applies wasm allowlist to native tier | **YES — unchanged** |
| `native_venv_executor._DRIVER` calls `exec()` in host subprocess | **YES — unchanged** |
| Worker `JULEP_PURE_NATIVE_DEPS` grant binds pure name (not source hash) | **YES — unchanged** |

**Conclusion: RT-01 remains fully exploitable.** No fix released, no CVE assigned (GHSA-rhfp-jw6w-wrqq cited in issue #1632 returns 404 — unverified). The wasm-guest import allowlist is still applied to native-tier host execution, and `exec()` still runs bundle source in a real host subprocess.

## Evidence hygiene

All secrets and environment values in `evidence/` are **synthetic test
values** (`sk-live-poc-secret-…`, `sk-live-hardening-secret-…`, Ed25519 seeds
`0x42…`/`0x77…`, `local-dev` keys) generated for the lab; no real credentials
are present. Host-identifying details (hostname, uid, kernel) are retained
because they are part of the proof that execution escaped the sandbox; the
repository is private and the raw engagement artifacts remain the hashed
source of truth.

## Integrity

`SHA256SUMS.txt` covers every tracked file in this repository except itself
(a manifest cannot contain its own hash) — verified with
`sha256sum -c SHA256SUMS.txt`. It is generated with:

```bash
find . -type f ! -path './.git/*' ! -path './SHA256SUMS.txt' | sort | xargs sha256sum > SHA256SUMS.txt
```

`README.md` and `SHA256SUMS-hardening.txt` are included. The per-engagement
manifests inside `evidence/` are the original artifacts as generated during
testing; their paths are relative to the engagement directories, not this repo
root.

## Reproduction environment

| Component | Version |
|---|---|
| Upstream | `julep-ai/julep` @ `fc74d079a18c8124b2627ca4717f5a9c269267db` (`3.0.0rc6`) |
| Python | 3.14.8 |
| uv | 0.12.5 |
| OS | Kali Linux, kernel 7.2.15+kali-amd64 |

Full environment capture: [`evidence/hardening/environment.txt`](evidence/hardening/environment.txt)
Hardening run matrix (14 cases, expected outcomes + raw proofs): [`evidence/hardening/matrix.json`](evidence/hardening/matrix.json), driver [`evidence/hardening/run_matrix.sh`](evidence/hardening/run_matrix.sh)
Patch application: diffs in [`poc/hardening/patches/`](poc/hardening/patches/), resulting files in [`poc/hardening/patched/`](poc/hardening/patched/)

## Layout

```
vendor-facing-report.md           concise vendor triage summary
report-rt01.md                     RT-01 original report
report-hardening-verification.md   RT-02/03/04 verification report
poc/rt01/                          original native_venv RCE PoC
poc/hardening/                     hardening patches, bypass payloads, run matrix
poc/authz/                         authorization/signature assessment scripts
evidence/rt01/                     RT-01 raw transcripts, bundle manifest, hashes
evidence/hardening/                verification logs, matrix.json, timestamps
evidence/authz/                    route matrix, live wiring + signature proofs
SHA256SUMS.txt                     repo-wide integrity manifest
SHA256SUMS-hardening.txt           original hardening-engagement manifest
```
