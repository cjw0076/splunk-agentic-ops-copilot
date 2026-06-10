# Synthetic incident: `incident-04-cloud-ato`

**SYNTHETIC DATA ONLY.** No real systems, accounts, or secrets. All IPs are RFC
5737 / sample ranges. Users and apps are fictional.

## The story (cloud / SaaS account takeover)

An attacker on a malicious residential proxy in Lagos (`102.89.40.7`)
**push-bombed `d.okafor` with 6 denied MFA challenges** until one was accepted →
a **successful SSO login from NG minutes after a legitimate US login**
(impossible travel) → the attacker **consented a malicious OAuth app**
(`MailRuleSyncer`, `mail.send` + `offline_access`) for **token persistence** →
created an inbox-hiding rule → pulled a finance board deck.

MITRE chain: **T1078** (Valid Accounts / impossible travel) → **T1098.001**
(Additional Cloud Credentials — OAuth persistence).

## Planted decoy

`s.muller` appears to log in from the **US then Frankfurt within minutes** —
textbook impossible travel. But both egress IPs are **sanctioned corporate VPN
egress** nodes (US + EU egress of the *same* VPN), rated `benign` in threat
intel. The detector consults threat intel and suppresses the all-benign-IP geo
change, so the agent does **not** raise a false positive on `s.muller`.

## Sourcetypes

| file | sourcetype | index |
|------|-----------|-------|
| `okta_auth.jsonl` | `okta:authentication` | `saas` |
| `okta_system.jsonl` | `okta:system` | `saas` |
| `web_access.jsonl` | `access_combined` | `web` |
| `threat_intel.csv` | lookup | — |

Ground truth + scoring keys: `ground_truth.json`. Agent manifest: `scenario.json`.
