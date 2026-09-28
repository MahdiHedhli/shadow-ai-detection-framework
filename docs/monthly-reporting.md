# Monthly Shadow AI collection and reporting

This is the proposed operating method for using the RMM collector and HTML report builder. It is a design/runbook only; it does not create an RMM schedule, choose storage, or authorize a client-wide deployment.

## Pilot path

1. Select a small, client-approved device group with Windows endpoints that represent the browser/app mix. Start with about three endpoints; include a known-positive and a negative control when the client can identify them.
2. Run the reviewed, self-contained RMM task only on that group. Retain task output for success and partial-coverage exit codes; flag fatal and partial runs for review.
3. Validate each output against `schema/observation.schema.json` using `tools/validate_observation.py`. Reject invalid output; never repair it by guessing fields.
4. Copy each valid observation into that client's restricted archive as an immutable, timestamped JSON record. Do not overwrite previous scans. Keep this archive and its access controls separate from all other client archives.
5. Build the report from the pilot archive. Review scan health, unsupported areas, low-confidence matches, summaries, and filter behavior with the client before expanding the target group.

The collector observations include endpoint hostnames, collection times, matched AI indicators, and local account names in source JSON. The default report omits local account names. Raw observations, review decisions, and generated HTML remain client-confidential and must not be committed to this repository or placed in a shared cross-client folder.

## Proposed monthly cadence

After the pilot has passed review and the client approves recurring collection, a reasonable starting proposal is three scans per month (for example, on the 1st, 15th, and final day), followed by report generation on the first day of the next month after the final collection has completed. A monthly report should state its observation window and show scan coverage; it must not describe missed or partial scans as clean endpoints.

This cadence is a proposal, not an active schedule. Before enabling it, document the client's approval, exact device group, timezone, retries/offline handling, RMM output retention, maximum output size, review owner, and stop/rollback path. Review the first two cycles before treating it as steady state.

## Storage decision — still open

Do not use this public GitHub repository as telemetry storage. Compare these options for the pilot client and select one with the client's retention and access requirements:

- **RMM task history:** operationally simple if it retains complete output for the required period, supports reliable export, and enforces tenant-scoped permissions. Confirm retention, export, size limits, and history behavior before relying on it as the archive.
- **Tenant-isolated encrypted storage:** store validated observations in a client-restricted location with encryption, versioning/append-only controls, least-privilege access, and an agreed retention/deletion schedule. This is the preferred direction if RMM history is not a durable archive, but the actual service/location remains TBD.
- **Database/ingestion service:** consider only if an ongoing multi-client service is needed. Require authenticated tenant identity, authorization checks, encrypted transport/storage, access logging, retention enforcement, and a tested tenant-isolation boundary before ingestion.

Keep one archive directory and one customer report output per client. The customer report builder is intentionally invoked separately for each client. A combined finding-level view is allowed only in the access-controlled internal technician dashboard, with an approved access boundary. Keep endpoint hostnames, local usernames, reviewer names, and review reasons out of that cross-client feed by default; apply the selected-client scope consistently to every view and export. Never place combined feeds or reports in this public repository or an unapproved shared folder.

## Private technician dashboard feed

For an MSP-wide technician view, `tools/build_dashboard_feed.py` creates two
BrightGauge-friendly CSVs from separate, validated client archives: one row per
finding observation and a separate scan-coverage feed. A private manifest maps
each stable `client_id` and display label to its own archive and optional review
file. The script preserves that tenant boundary when reading reviews and never
places endpoint hostnames, local usernames, reviewer names, or review reasons in
the dashboard feeds. It includes a stable pseudonymous finding key so repeated
observations and review status can be correlated; treat that key, client labels,
extension IDs, domains, and both CSVs as confidential telemetry.

Keep the manifest, source archives, and generated CSVs outside this public
repository. The output directory must be private (POSIX mode `0700` or stricter)
and the files are created as `0600`. The feed builder refuses paths inside the
public repository, escapes spreadsheet-formula prefixes, and does not replace
existing files unless `--overwrite` is explicitly supplied.

Example private manifest (store it only in the secured reporting environment):

```json
{
  "schema_version": "1.0",
  "clients": [
    {
      "client_id": "client-a",
      "client_label": "Client A",
      "observations": "./client-a/observations",
      "reviews": "./client-a/review-decisions.json"
    }
  ]
}
```

Build the current-month feed to a restricted local folder:

```bash
python3 tools/build_dashboard_feed.py \
  --manifest /secure/shadow-ai/dashboard-clients.json \
  --output-dir /secure/shadow-ai/brightgauge-feed \
  --period 2026-09
```

The findings feed's grain is one finding event per scan; it is not a count of
unique devices or currently active findings. Use `finding_key` for a distinct
finding identity across versions/scans, while keeping `finding_id` and
`observation_id` as event identifiers. The scans feed has one row per
observation and emits `no_observations` rather than implying a clean scan when a
client has no data for the selected period. The two feeds can power client,
provider, product, category, confidence, evidence, and review-state filters.
Client exports must apply the same selected-client scope to every view and must
not include other clients' rows.

The RMM automation-history dataset is a separate run-count source and must not be combined with finding metrics. ConnectWise documents CSV-backed datasets using Dropbox or OneDrive, which may provide a path for dedicated findings and scan feeds. Before connecting a source, validate its licensing, refresh behavior, client mapping, and whether the feed can be restricted to an approved folder. Never replace an existing datasource or upgrade a plan implicitly.

The automation-history dataset may include unrelated task records. Do not export it wholesale. Use a task-scoped extraction or dedicated CSV feeds, then verify that client filters, sorting, exports, and review-state hiding consistently apply to the selected client before sharing.

## Generate and review the monthly report

For the report month, provide the client-specific observations, a client display label, the month (`YYYY-MM`), and the client's private review-decision file:

```bash
python3 tools/build_report.py \
  --observations /secure/client/shadow-ai/observations \
  --period 2026-09 \
  --client-label "Client name" \
  --reviews /secure/client/shadow-ai/review-decisions.json \
  --output /secure/client/shadow-ai/reports/2026-09.html
```

The HTML board is self-contained/offline and starts with an executive summary, endpoint/scan coverage, visible finding counts, and provider, evidence-type, and scan-date charts. Readers can filter by provider/product, evidence type, confidence, and search text. They can mark a finding acknowledged or justified with a reviewer and reason, hide reviewed findings, and download the updated decisions for the next report. These decisions are metadata, not deletion: source observations are unchanged. The decision file stores the current disposition; retain dated copies in the client's private archive if a full decision-change audit trail is required. Do not accept an acknowledgement as proof that an activity is safe; retain the client's stated reason and re-review it under the client's policy.

Use the standalone HTML as the filterable report. A printed/PDF copy is a static snapshot of the currently selected filters and is not interactive. Check the period, collection status, chart totals, representative rows, mobile/narrow rendering, and hidden-reviewed count before delivery. Reports contain endpoint details and must be shared only through a client-approved, access-controlled channel.

## Distribution and automation

Before enabling automated report distribution, configure verified recipients, client-specific permissions, an approved channel, and a clear per-client versus internal audience. Never distribute a report containing another client's data.

After the mechanics are validated, the intended next engineering step is to deploy the report and automation workflow in an appropriate private organization repository and configure a tenant-aware job there. The public repository should contain generic collector/report code, schemas, and tests only. Keep client configuration, observations, decisions, credentials, storage URLs, recipient lists, and generated reports in private tenant-controlled systems.

## Pilot exit criteria

- The chosen endpoints are explicitly scoped and the client approves the collection and destination.
- The RMM output is complete, valid JSON and passes the observation validator.
- Browser extensions and matched website-domain indicators appear correctly for known-positive tests; negative controls remain clean within measured coverage.
- Partial collection, duplicate outputs, repeated observations, filter intersections, and acknowledgements behave as documented.
- The report contains only that client's rows, review state, and label; output files are outside the public repository.
- Storage, retention, access, schedule, and distribution choices are approved before broad collection.
