# Synthetic incident: `incident-03-insider`

**SYNTHETIC DATA ONLY.** No real systems, people, or secrets. All IPs are RFC
5737 / RFC 1918 ranges. `j.kwon`, `s.muller`, etc. are fictional.

## The story (insider data theft)

A privileged DBA (`j.kwon`) logged into SSO **after hours from a BYOD laptop** →
ran **three unapproved bulk exports** against `db-prod-01` (`customers`,
`payment_methods`, `salaries`, ~97,870 sensitive records) → their workstation
`DBA-WS-03` **uploaded ~30 MB to an unsanctioned personal cloud-storage
endpoint** (`198.51.100.44`).

MITRE: **T1530** (Data from Cloud Storage / insider bulk export).

## Planted decoy

The scheduled ETL account `svc_etl_nightly` exported **500,000 rows** of `orders`
— far more *volume* than the insider. Ranking by row count points here, but that
job ran **during business hours, was approved/whitelisted**, and the account is
`benign` in threat intel. The agent must reject the high-volume-but-legitimate
job and self-correct to the after-hours, unapproved exports.

## Sourcetypes

| file | sourcetype | index |
|------|-----------|-------|
| `db_audit.jsonl` | `db:audit` | `dlp` |
| `okta_auth.jsonl` | `okta:authentication` | `saas` |
| `fw_traffic.jsonl` | `pan:traffic` | `network` |
| `threat_intel.csv` | lookup | — |

Ground truth + scoring keys: `ground_truth.json`. Agent manifest: `scenario.json`.
