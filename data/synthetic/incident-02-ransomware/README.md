# Synthetic incident: `incident-02-ransomware`

**SYNTHETIC DATA ONLY.** No real systems, files, or secrets. All IPs are RFC 5737
documentation ranges. `eicar.com` is the standard, harmless antivirus test file.

## The story (ransomware)

A macro-laden `Invoice_April.docm` opened on `FIN-WS-07` spawned an encoded
PowerShell stager → it **inhibited recovery** (`vssadmin delete shadows`,
`wbadmin delete catalog`, `bcdedit /set recoveryenabled No`) → `svch0st.exe`
(note the masquerading zero) **encrypted 8 finance documents** to a `.locky`
extension and dropped `READ_ME_TO_DECRYPT.txt` → the host **beaconed** to a known
Locky C2 (`203.0.113.77`).

MITRE chain: **T1490** (Inhibit System Recovery) → **T1486** (Data Encrypted for
Impact), plus an ops `service_error_cascade` on the file server.

## Planted decoy

An **EICAR antivirus test file** lit up AV dashboards on `IT-LAB-02`. It looks
like patient zero but is the benign standard test artifact (rated `benign` in
`threat_intel.csv`), and that host shows zero shadow-copy deletion or `.locky`
encryption. The agent must self-correct from the EICAR host to `FIN-WS-07`.

## Sourcetypes

| file | sourcetype | index |
|------|-----------|-------|
| `sysmon.jsonl` | `xmlwineventlog:sysmon` | `endpoint` |
| `fw_traffic.jsonl` | `pan:traffic` | `network` |
| `app_payments.jsonl` | `app:payments` | `app` |
| `threat_intel.csv` | lookup | — |

Ground truth + scoring keys: `ground_truth.json`. Agent manifest: `scenario.json`.
