# Synthetic incident: `incident-01`

**SYNTHETIC DATA ONLY.** No real systems, customers, or secrets. All IPs are
RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`) or known benign scanner space; the API key id is a fake
placeholder.

## The story (one coherent incident)

A deploy service-account **API key was accidentally committed to a public repo**
→ an attacker used it for **credential stuffing** against the web login →
**succeeded as `svc_deploy`** → **escalated to admin** via an unguarded
`/api/admin/grant_role` endpoint → **bulk-exported the customers table** three
times, exfiltrating ~64 MB outbound.

Timeline (all 2026-06-10 UTC):

| time | sourcetype | what |
|------|-----------|------|
| 01:20 | `app:payments` | leaked API key `AKIA-DEPLOY-7Q2` loaded from repo-committed config |
| 02:18 | `linux_secure` | **DECOY**: SSH scanner brute-forces bastion-01 (all fail) |
| 02:23 | `access_combined` | credential stuffing on `/api/login` (10 × 401) then **200** as `svc_deploy` |
| 02:24 | `access_combined` + `app:payments` | `/api/admin/grant_role` → `svc_deploy` becomes admin |
| 02:25–02:27 | `access_combined` + `pan:traffic` | 3 × `/api/export/customers`, ~64 MB outbound |

## Sourcetypes (Splunk-style)

| file | index | sourcetype | role |
|------|-------|-----------|------|
| `web_access.jsonl` | `web` | `access_combined` | web request log (the main attack surface) |
| `linux_secure.jsonl` | `os` | `linux_secure` | SSH auth log (carries the decoy) |
| `app_payments.jsonl` | `app` | `app:payments` | app audit/error log (privilege + export events) |
| `fw_traffic.jsonl` | `network` | `pan:traffic` | firewall/netflow (exfil byte volume) |
| `threat_intel.csv` | — | lookup | offline indicator reputations |

Every event carries a `row` field; provenance refs are `<file>:<row>`
(e.g. `web_access.jsonl:15`). The same events also carry `index` and
`sourcetype`, so real SPL `index=… sourcetype=…` filters work over them.

## The decoy

The SSH brute-force burst from `45.155.205.99` (`linux_secure.jsonl:1-8`) is
designed to look like the intrusion vector. It is **not**: zero successful
logons, and the IP is rated **benign** in `threat_intel.csv:2`. The agent must
form that wrong hypothesis first, find the contradiction, and self-correct to
the web credential-stuffing chain.

## Ground truth

`ground_truth.json` lists the 4 expected findings (MITRE + ops class), the
decoy to reject, the root cause, the blast radius, and the IOCs. It is used
only for the offline accuracy self-check.
