# Julep `native_venv` — Sandbox Escape via Python Object Model (Import Denylists Are Not a Boundary)

Coordinated vulnerability disclosure for `julep-ai/julep`.

## Executive summary

The `native_venv` execution tier runs bundle-supplied source with
`exec(source, {"pure": pure})` in a host subprocess. A signed bundle containing
`import os` / `import subprocess` achieves host RCE and data exfiltration —
verified end-to-end with a live listener (`poc/rt01/`, `evidence/rt01/`).

**RT-01 — production finding, High 7.2** (`AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`).
Exploitation must satisfy **three controls simultaneously**: (1) an admin-level
API key to publish a bundle (`require_admin` routes), (2) an Ed25519 signature
from a worker-allowlisted operator key, and (3) a worker-side
`JULEP_PURE_NATIVE_DEPS` grant naming the pure. Compromising any one alone is
not sufficient — e.g. a stolen admin key cannot forge the operator signature,
and a leaked signing key cannot grant itself the worker-side native tier.
A realistic attack scenario is compromise of a release/signing pipeline that
holds both publication and signing capability, on a worker already granting
the pure native tier. Deployments that issue admin keys to tenants or expose
the signing key collapse this toward `PR:L` (8.8).

**RT-02 / RT-03 — remediation bypasses, not independent vulnerabilities.** The
hardening proposed in upstream issue #1632 (tier-aware import denylist +
reflection bans, restricted `__builtins__`) is bypassable via
`operator.attrgetter("__globals__")(pure)["__builtins__"]` and
`().__class__.__base__.__subclasses__()` → `sys.modules["os"]`. These target a
*proposed* fix, not deployed code; they inherit RT-01's prerequisites.

**RT-04 — informational.** The fully layered variant (B2) blocks the tested
payloads but also blocks legitimate `import packaging` — the exact capability
the native tier exists to provide. In-process Python restrictions are not a
security boundary; the fix is OS-level sandboxing.

| ID | Severity | CVSS 3.1 | CWE | Title |
|----|----------|----------|-----|-------|
| RT-01 | High | 7.2 | CWE-94 | `native_venv` tier executes arbitrary bundle source → host RCE |
| RT-02 | Remediation bypass | — | CWE-693 | Tier-aware import denylist bypassed via `attrgetter`/`__globals__` |
| RT-03 | Remediation bypass | — | CWE-693 | Restricted `__builtins__` bypassed via `__subclasses__` → `sys.modules["os"]` |
| RT-04 | Informational | — | — | Layered controls block payloads but break legitimate `import packaging` |

Public reference: [GHSA-rhfp-jw6w-wrqq](https://github.com/julep-ai/julep/security/advisories/GHSA-rhfp-jw6w-wrqq) · upstream issue `julep-ai/julep#1632`

## Reports

- [`report-rt01.md`](report-rt01.md) — original finding: `native_venv` escape, verified with live exfiltration (`poc/rt01/`, `evidence/rt01/`)
- [`report-hardening-verification.md`](report-hardening-verification.md) — verification/addendum: proposed hardening variants A/B1/B2, bypass payloads, patch diffs, 14-assertion run matrix (`poc/hardening/`, `evidence/hardening/`)
- [`evidence/authz/authorization_analysis.md`](evidence/authz/authorization_analysis.md) — supporting appendix: route authz inventory, authentication decisions, signature verification, native-grant binding
- [`evidence/authz/attacker_model.md`](evidence/authz/attacker_model.md) — complete enumeration of pure-source entry paths and attacker prerequisites

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
| pending | Vendor disclosure / CVE assignment |

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
admin API call plus an operator-held signing key, or operator env vars.
Exploitation therefore requires all three controls at once: admin publication
rights, an allowlisted operator signature over a manifest whose
`executorTier:"native"` claim is inside the signed bytes, and a worker-side
`JULEP_PURE_NATIVE_DEPS` grant. This is why RT-01 is scored `PR:H` (7.2), not
`PR:L` (8.8). The finding is a sandbox-boundary failure: the native tier's
documented purpose is dependency installation, but it grants unrestricted
host `exec()` to any authorized bundle. Remaining deployment-specific
unknowns: whether a given deployment delegates admin keys or bundle signing
to tenants.

## Recommendation

Do not rely on import denylists or in-process `__builtins__` restriction as the
boundary for `native_venv`. Execute native pures in a real sandbox: container /
namespace isolation, seccomp, non-root UID, read-only rootfs, no host
environment or mounts, egress allowlist. If in-process checks are retained as
defence-in-depth, combine tier-aware denylist + all-dunder AST ban +
restricted builtins, and add the payloads in `poc/hardening/payloads/` as
regression tests. Treat the native grant as a signed per-bundle capability,
not a name-only worker allowlist.

## Integrity

`SHA256SUMS.txt` covers every tracked file in this repository except itself
(a manifest cannot contain its own hash) — verified with
`sha256sum -c SHA256SUMS.txt`. It is generated with:

```bash
find . -type f ! -path './.git/*' ! -name 'SHA256SUMS.txt' | sort | xargs sha256sum > SHA256SUMS.txt
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
