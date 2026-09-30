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
- Read-only Windows and macOS/Linux RMM collectors with a shared observation schema, including a native Perl fallback for macOS endpoints without Python/Xcode tools.
- A standard-library-only builder and validator.
- A self-contained, interactive client report builder for monthly observations, provider/evidence filters, and review decisions.
- A private, multi-client CSV feed builder for technician dashboards, with separate findings and scan-coverage datasets.
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

For an internal technician dashboard spanning clients, use a private client-to-archive manifest with `tools/build_dashboard_feed.py`. It emits one private CSV with findings from each endpoint's latest scan and another with each endpoint's latest scan status, so a BI/dashboard source can filter by client without exposing endpoint or local-user identities. The client labels, finding keys, extension IDs, and domains remain confidential telemetry; do not store the manifest or feeds in this repository. See [Monthly collection and reporting](docs/monthly-reporting.md#private-technician-dashboard-feed) for the manifest format, permissions, row grain, and current BrightGauge datasource dependency.

To build a standalone, offline technician dashboard from the same manifest, use `tools/build_internal_dashboard.py`. It shows each endpoint's latest scan by default, with client/provider/product, finding type, confidence, review-state, and text filters; sortable client comparison values and finding columns; scan health; and a customer CSV export that stays disabled until exactly one client is selected. The dashboard does not carry forward findings absent from an endpoint's latest scan. Retain task observations only as long as needed to refresh current state and prepare the monthly report; the delivered monthly email/PDF can serve as the historical snapshot. The HTML embeds confidential multi-client telemetry, so its output directory must be private and outside this repository. This local file is not protected by BrightGauge SSO/MFA and must not be put in a shared location without an approved access boundary. See [Monthly collection and reporting](docs/monthly-reporting.md#private-internal-html-dashboard) for use and limits.

For a first refresh without a private client manifest, `tools/discover_rmm_clients.py` creates mappings from only company names and IDs attached to the exact scanner task names; it does not copy scan JSON or unrelated task output. Repeat `--task-name` to include another explicit platform/version collector. Review the generated mapping, then use `tools/refresh_dashboard_from_rmm_export.py` for a repeatable refresh. That command retains only validated rows for explicitly listed exact scanner task names and manifest-mapped companies, refreshes the private archive, both BrightGauge feeds, and the sortable HTML technician view, then removes the temporary task-only CSV. Repeat `--task-name` for each approved platform/version task; similar but unlisted tasks remain excluded. The source CSV content remains unchanged, but local permissions are tightened to owner-only before reading because browser downloads may be broadly readable. Identical imports are skipped, existing dashboard outputs require an explicit `--overwrite`, and the command does not upload data or schedule refreshes. Use `--allow-truncated-rows` only when accepting a visibly incomplete dashboard is intentional; malformed output exactly 30,000 characters long is excluded and a warning is embedded in the dashboard. For a two-step workflow that keeps a task-only CSV for separate review, use `tools/filter_rmm_task_export.py` followed by `tools/refresh_dashboard.py`. The lower-level `tools/import_rmm_task_export.py` remains available when only archiving is needed. See [RMM task export ingestion](docs/monthly-reporting.md#rmm-task-export-ingestion) for the manifest format and commands.

See [BrightGauge dashboard design and data contract](docs/brightgauge-dashboard.md) for the finding-level view, metric definitions, client scoping, and refresh requirements.

Generated, ready-to-run artifacts are written under `dist/`.

Collector self-tests do not inspect endpoint data:

```bash
python3 dist/rmm-macos-linux/shadow_ai_inventory.py --self-test | python3 tools/validate_observation.py
pwsh -NoProfile -File dist/rmm-windows/ShadowAIInventory.ps1 -SelfTest
perl dist/rmm-macos-linux/shadow_ai_inventory.pl --self-test | python3 tools/validate_observation.py
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
