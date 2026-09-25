# Shadow AI Detection Framework

An MSP-oriented, vendor-neutral framework for discovering and assessing unsanctioned AI use across heterogeneous client environments.

The project separates four concerns:

1. **Catalog** — AI providers, products, domains, endpoint artifacts, extensions, and agent indicators.
2. **Detection specifications** — portable descriptions of the behavior to detect and the evidence needed.
3. **Platform adapters** — implementation-specific queries for Defender XDR, Microsoft Sentinel, and later Splunk, Elastic, Wazuh, osquery, and RMM platforms.
4. **Evidence and governance** — approval status, confidence, risk context, source attribution, and licensing.

## Current scope

The first milestone provides:

- A curated starter catalog of AI network and endpoint indicators.
- Portable detection specifications with explicit evidence levels and limitations.
- Microsoft Defender XDR hunting queries for network access, non-browser API access, local runtimes, model files, MCP activity, browser extensions, software inventory, and agent governance.
- Microsoft Sentinel ASIM queries backed by a generated watchlist.
- Read-only Windows and macOS/Linux RMM collectors with a shared observation schema.
- A standard-library-only builder and validator.
- A self-contained, interactive HTML report builder for client-scoped historical observations, provider/evidence filters, and review decisions.
- Tests that reject unsafe catalog values and known-invalid MDE assumptions such as `SentBytes`, `ReceivedBytes`, and invented file-read actions.

All initial rules are discovery or hunting content. They are not automatic blocking rules.

## Build and validate

```bash
python3 tools/build.py
python3 -m unittest discover -s tests -v
```

## Build a private client report

Export validated observation JSON from the RMM into that client's private archive, then build one report per client. Never put client observations, HTML reports, or review-decision files in this public repository.

```bash
python3 tools/build_report.py \
  --observations /secure/client-a/shadow-ai/observations \
  --period 2026-09 \
  --client-label "Client A" \
  --reviews /secure/client-a/shadow-ai/review-decisions.json \
  --output /secure/client-a/shadow-ai/reports/2026-09.html
```

The generated HTML is self-contained and works offline. It opens with an executive summary, scan coverage, key counts, and provider/evidence/time visuals, with interactive provider, evidence type, confidence, and text filters. Acknowledged or justified findings can be hidden without deleting observations; review decisions can be exported from the report and loaded into the next monthly build. Local account names are omitted unless `--include-local-users` is deliberately supplied. See [Monthly collection and reporting](docs/monthly-reporting.md) for the proposed operating procedure and unresolved storage/scheduling choices.

Generated, ready-to-run artifacts are written under `dist/`.

Collector self-tests do not inspect endpoint data:

```bash
python3 dist/rmm-macos-linux/shadow_ai_inventory.py --self-test | python3 tools/validate_observation.py
pwsh -NoProfile -File dist/rmm-windows/ShadowAIInventory.ps1 -SelfTest
```

## Design principles

- Do not treat all AI use as malicious.
- Do not claim data transfer without telemetry that actually measures it.
- Do not emit prompts, responses, API keys, raw browser history, or file contents by default.
- Keep client policy and approval state separate from the shared indicator catalog.
- Preserve tenant isolation in collection, storage, investigation, and reporting.
- Require source, validation date, and licensing information for borrowed material.
- Prefer normalized schemas and portable rules over vendor-specific logic.

See [Architecture](docs/architecture.md), [Detection model](docs/detection-model.md), [RMM collectors](docs/rmm-collectors.md), [Backlog](docs/backlog.md), and [Source register](docs/source-register.md).

## Project status

Early build. Queries must be validated against each client's enabled telemetry and licensing before they are promoted from hunting to scheduled detections.
