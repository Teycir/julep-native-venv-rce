# Julep `native_venv` — Sandbox Escape via Python Object Model (Import Denylists Are Not a Boundary)

Coordinated vulnerability disclosure for `julep-ai/julep`.

The `native_venv` execution tier runs bundle-supplied source with
`exec(source, {"pure": pure})` in a host subprocess. A signed bundle containing
`import os` / `import subprocess` achieves host RCE and data exfiltration
(RT-01, High 8.8). The remediation proposed in `julep-ai/julep#1632` — a
tier-aware import denylist plus reflection bans — is bypassable via
`operator.attrgetter("__globals__")(pure)["__builtins__"]` and
`().__class__.__base__.__subclasses__()` (RT-02, RT-03). The fully layered
variant (B2) blocks the tested payloads but also blocks legitimate
`import packaging` — the exact capability the tier exists to provide — so
in-process Python restrictions are not a security boundary (RT-04).

| ID | Severity | CVSS 3.1 | CWE | Title |
|----|----------|----------|-----|-------|
| RT-01 | High | 8.8 | CWE-94 | `native_venv` tier executes arbitrary bundle source → host RCE |
| RT-02 | High | — | CWE-693 | Tier-aware import denylist bypassed via `attrgetter`/`__globals__` |
| RT-03 | High | — | CWE-693 | Restricted `__builtins__` bypassed via `__subclasses__` → `sys.modules["os"]` |
| RT-04 | Informational | — | — | Layered controls block payloads but break legitimate `import packaging` |

Public reference: [GHSA-rhfp-jw6w-wrqq](https://github.com/julep-ai/julep/security/advisories/GHSA-rhfp-jw6w-wrqq) · upstream issue `julep-ai/julep#1632`

## Reports

- [`report-rt01.md`](report-rt01.md) — original finding: `native_venv` escape, verified with live exfiltration (`poc/rt01/`, `evidence/rt01/`)
- [`report-hardening-verification.md`](report-hardening-verification.md) — verification/addendum: proposed hardening variants A/B1/B2, bypass payloads, patch diffs, 14-assertion run matrix (`poc/hardening/`, `evidence/hardening/`)

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
| pending | Vendor disclosure / CVE assignment |

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

`SHA256SUMS.txt` covers every file in this repository (57 files, verified with
`sha256sum -c`). The per-engagement manifests inside `evidence/` are the
original artifacts as generated during testing; their paths are relative to the
engagement directories, not this repo root.

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

## Open question for triage — attacker prerequisites

The PoC calls `resolve_and_register(..., allowed_signers=[pub],
native_grant=[PURE_NAME])` with a lab-generated Ed25519 key. What is **not yet
demonstrated** is the real-world authorization chain:

`external user → API → bundle publication → signature verification → native grant → worker execution`

Specifically unresolved:

1. Who can publish a signed bundle in a real deployment (ordinary user vs.
   administrator-only)?
2. Can a third-party bundle author obtain an accepted signature?
3. Can the attacker influence the `native` tier / `JULEP_PURE_NATIVE_DEPS`, or is
   it strictly operator-controlled?
4. Does the deployed worker actually execute the resulting pure?

If only a fully trusted administrator can sign and grant `native`, the vendor
could argue host execution is expected behaviour. Demonstrating traversal of
this chain with ordinary-user privileges is the highest-value remaining work.

## Layout

```
report-rt01.md                     RT-01 original report
report-hardening-verification.md   RT-02/03/04 verification report
poc/rt01/                          original native_venv RCE PoC
poc/hardening/                     hardening patches, bypass payloads, run matrix
evidence/rt01/                     RT-01 raw transcripts, bundle manifest, hashes
evidence/hardening/                verification logs, matrix.json, timestamps
SHA256SUMS-hardening.txt           integrity manifest for hardening artifacts
```
