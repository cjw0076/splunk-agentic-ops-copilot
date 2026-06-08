# SPL-001 Command Packet: Security MCP Investigation Copilot

Status: access-gated

## Goal

Build a Splunk Security-track investigation copilot that uses Splunk MCP/SPL to investigate alerts, preserve evidence, and produce an incident note.

## Official Facts

- Deadline: 2026-06-15 09:00 PDT, 2026-06-16 01:00 KST.
- Tracks: Observability, Security, Platform & Developer Experience.
- Required: English submission, 3-minute-or-less public demo, public open-source repo, README/setup/dependencies/example config, `architecture_diagram.(md|pdf|png)`.
- Bonus targets: Best Use of Splunk MCP Server, Hosted Models, Developer Tools.
- Sources: https://splunk.devpost.com/, https://splunk.devpost.com/rules, https://help.splunk.com/en/splunk-cloud-platform/mcp-server-for-splunk-platform/1.1/about-mcp-server-for-splunk-platform

## Build Direction

Primary: Security + MCP bonus

- alert intake
- SPL generation/explanation
- cross-signal search
- evidence ledger
- human approval
- final incident note

Fallback: local simulated Splunk interface if account/license blocks.

## Next 3

1. Operator verifies Splunk account, trial, developer license, and MCP server access.
2. Choose sample dataset: suspicious login, suspicious file, or APM spike.
3. Reuse `agent-evidence-ledger` from FIND EVIL for trace export.

## Stop Conditions

- No Splunk MCP/trial/license access by 2026-06-10 KST.
- Cannot keep tokens/config out of public repo.
- Hosted Models unavailable; degrade to MCP/AI Assistant only.

