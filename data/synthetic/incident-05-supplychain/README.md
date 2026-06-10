# Synthetic incident: `incident-05-supplychain`

**SYNTHETIC DATA ONLY.** No real systems, registries, or secrets. All IPs are RFC
5737 ranges; secret names (`NPM_TOKEN`, …) are placeholders with no values.

## The story (supply-chain / poisoned dependency)

The `web-frontend` CI pipeline on `build-runner-09` installed a **typosquatted
dependency** (`colour-picker@3.1.9`, impersonating `color-picker`) whose
**postinstall hook ran a remote shell** → it **read the CI pipeline secrets**
(`NPM_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `GH_PAT`) → the build host — which should
only receive inbound traffic — **beaconed outbound** to a malicious endpoint
(`203.0.113.91`) → a published artifact carried an unexpected extra bundle chunk.

MITRE chain: **T1195.001** (Supply Chain Compromise: Software Dependencies) →
**T1071.001** (Application Layer Protocol — C2 from build infra).

## Planted decoy

A legitimate **major version bump of `webpack` to 5.92.0 broke 12 unit tests** —
which looks like a malicious dependency change. But `webpack 5.92.0` is an
official `benign` release, ran no install-time scripts, and caused no outbound
traffic. A failing test is not a compromise; the agent must self-correct to
`colour-picker`.

## Sourcetypes

| file | sourcetype | index |
|------|-----------|-------|
| `ci_build.jsonl` | `ci:build` | `cicd` |
| `fw_traffic.jsonl` | `pan:traffic` | `network` |
| `app_payments.jsonl` | `app:payments` | `app` |
| `threat_intel.csv` | lookup | — |

Ground truth + scoring keys: `ground_truth.json`. Agent manifest: `scenario.json`.
