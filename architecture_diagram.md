# Architecture Diagram

This project uses a deterministic agent loop over Splunk-shaped data. The
offline backend executes real SPL over synthetic events; the live backend seam
uses the same SPL strings against Splunk REST when `SPLUNK_URL` and
`SPLUNK_TOKEN` are supplied.

```mermaid
flowchart LR
    subgraph Data["Splunk data sources"]
        D1["Synthetic events\njsonl/csv/manifests"]
        D2["Live Splunk deployment\noptional REST backend"]
    end

    subgraph Search["Search boundary"]
        S1["SearchBackend\nSyntheticBackend | SplunkRestBackend"]
        S2["SPL engine / Splunk REST\nsame SPL strings"]
        S3["Evidence refs preserved\nsource file + row"]
    end

    subgraph Agent["Agentic investigation loop"]
        A1["Anomaly trigger"]
        A2["Initial hypothesis"]
        A3["Run SPL to test"]
        A4["Contradiction"]
        A5["Self-correction"]
        A6["MITRE findings"]
        A7["Root cause + blast radius"]
    end

    subgraph AI["AI / agent layer"]
        I1["Deterministic copilot policy"]
        I2["Correlation searches as SPL"]
        I3["Optional narration layer\nfuture extension"]
    end

    subgraph Outputs["Outputs"]
        O1["Append-only ledger"]
        O2["Replayable trace"]
        O3["Eval report"]
        O4["Web dashboard"]
        O5["Remediation checklist"]
    end

    D1 --> S1
    D2 --> S1
    S1 --> S2 --> S3
    S3 --> A1 --> A2 --> A3 --> A4 --> A5 --> A6 --> A7
    I1 --> A2
    I2 --> A3
    I3 -. optional .-> O4
    A6 --> O1
    A7 --> O1
    A1 --> O2
    A3 --> O2
    A5 --> O2
    O1 --> O3
    O1 --> O4
    A7 --> O5
```

## Data Flow

1. Events are loaded read-only from synthetic case directories or live Splunk.
2. The copilot chooses SPL searches for the incident hypothesis.
3. Search results preserve source evidence refs through aggregation.
4. The agent rejects contradicted hypotheses, writes MITRE-mapped findings, and
   produces root cause, blast radius, and remediation.
5. The ledger, trace, eval report, and dashboard expose the full reasoning path.

## Splunk Interaction

- Offline: `SyntheticBackend` runs real SPL locally for reproducible judging.
- Live: `SplunkRestBackend` submits the same SPL to Splunk REST search jobs.
- The repository includes mocked REST tests so the live seam is verified without
  storing any Splunk credentials.
