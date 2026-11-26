# Disclosure timeline — Julep native_venv host execution

Canonical UTC history for RT-01 (`julep-ai/julep` 3.0.0rc6, commit `fc74d079a18c8124b2627ca4717f5a9c269267db`).
Rendered inline in [`README.md`](README.md#timeline-utc).

| Date (UTC) | Event | Evidence |
|---|---|---|
| 2026-10-16T15:02:57Z | Issue `julep-ai/julep#1632` filed with initial analysis (still open) | [#1632](https://github.com/julep-ai/julep/issues/1632) |
| 2026-11-21T21:46:13Z | RT-01 verified locally: signed `native_venv` bundle runs host source; live egress listener captured proof | `evidence/rt01/` |
| 2026-11-22T10:08:19Z | Hardening matrix A/B1/B2 executed: 14 assertions, bypass payloads, patch diffs | `evidence/hardening/` |
| 2026-11-22 | Authorization analysis: 25-route inventory, auth decisions, signature chain, native-grant binding | `evidence/authz/` |
| 2026-11-22T17:54:26Z | Vendor notification sent: To `developers@julep.ai`, Cc `diwank@julep.ai`; evidence zip attached | `evidence/disclosure/` |
| 2026-11-23T18:12:00Z | Upstream HEAD `fc74d07` re-checked: HEAD == affected 3.0.0rc6 commit; wasm allowlist still applied to native tier, `exec()` still host subprocess; **no fix** | README § Fix verification |
| 2026-11-26T13:15:06Z | Repository made public with full proof package and vendor-contact record | this file |
| 2026-11-26 | VulnCheck submission filed — case `8d8e3d06-120c-407f-8948-b9fecded18a3` | VulnCheck case record |
| 2026-11-26T13:32:50Z | Vulners CNA CVE request emailed to `cna@vulners.com` (Message-ID `<qWM0U53swAzZ9cJn_SrAeWMVeLykmnAwN5W3Ou3caXBCszNMVPA2xYqgze1BSY63LQMr2_DEK9NZl9pJ2LlFJlUqe2HJtJBCp0YVHXOT6PQ=@protonmail.com>`, `.eml` sha256 `dba97ad2…5023d`) | `submission/vulners/sent/` |
| _TBD_ | Vendor response / triage / CVE assignment | — |

## Notes

- No vendor reply received as of 2026-11-26T13:15:06Z; inbox and spam checked.
- Upstream has no published `SECURITY.md`; disclosure used the project's public `developers@` address plus the maintainer Cc listed above.
- The prior GitHub issue predates the consolidated email and remains open; the email references it.
- No fixed-day embargo is asserted. Timing is deferred to the vendor/CVE process.
