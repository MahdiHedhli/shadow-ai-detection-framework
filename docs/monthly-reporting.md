# Shadow AI collection and reporting

This is the proposed operating method for using the RMM collector and report builder. It is a design/runbook only; it does not create an RMM schedule, choose storage, or authorize a client-wide deployment.

## Reporting priority

The primary view should describe the **latest known scan state** for the selected client or internal MSP-wide scope: current findings, current review dispositions, scan health, and the last successful collection time. Historical trends are secondary. A monthly emailed client report (optionally attached as PDF) is an acceptable history snapshot, and retaining those delivered reports is sufficient for the current history requirement. A machine-readable archive remains optional unless later row-level filtering, recalculation, or audit needs justify it. Until the live source path is validated, do not present stale or missing observations as current, and label the data's actual scan time.

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

## Monthly emailed report as the history snapshot

For the current reporting goal, an emailed monthly client report is an acceptable history snapshot. BrightGauge can schedule a client report daily, weekly, or monthly and optionally attach a PDF. Build it from validated scan data, include the observation window and last successful scan time, and keep client mapping and recipient scope isolated. The delivered email/PDF is sufficient as the historical snapshot; separately retaining it in a restricted location is optional. This PDF is a presentation snapshot, not a machine-readable scan archive; it cannot support later row-level filtering or recalculation. Keep the current operational view separate from this monthly snapshot. Before enabling delivery, verify recipients, client mapping, and report scope. BrightGauge's [Client Reporting guide](https://docs.connectwise.com/BrightGauge/070/030) documents recurring schedules and optional PDF attachments.

## Storage and access controls

Do not use this public GitHub repository as telemetry storage. Compare these options for the pilot client and select one with the client's retention and access requirements:

- **RMM task history:** operationally simple if it retains complete output for the required period, supports reliable export, and enforces tenant-scoped permissions. Confirm retention, export, size limits, and history behavior before relying on it as the archive.
- **Tenant-isolated encrypted storage:** store validated observations in a client-restricted location with encryption, versioning/append-only controls, least-privilege access, and an agreed retention/deletion schedule. Prefer this direction if RMM history is not a durable archive.
- **Database/ingestion service:** consider only if an ongoing multi-client service is needed. Require authenticated tenant identity, authorization checks, encrypted transport/storage, access logging, retention enforcement, and a tested tenant-isolation boundary before ingestion.

Keep one archive directory and one customer report output per client. The customer report builder is intentionally invoked separately for each client. A combined finding-level view is appropriate only in an internal technician dashboard with an approved access boundary. Keep endpoint hostnames, local usernames, reviewer names, and review reasons out of that cross-client feed by default; apply the selected-client scope consistently to every view and export. Never place combined feeds or reports in this public repository or an unapproved shared folder.

## Private technician dashboard feed

For an MSP-wide technician view, `tools/build_dashboard_feed.py` creates two
BrightGauge-friendly CSVs from separate, validated client archives: one row per
finding in each endpoint's latest scan and a separate latest-scan coverage
feed. A private manifest maps
each stable `client_id` and display label to its own archive and optional review
file. The script preserves that tenant boundary when reading reviews and never
places endpoint hostnames, local usernames, reviewer names, or review reasons in
the dashboard feeds. It includes a stable pseudonymous finding key so a current
signal and review status can be correlated; treat that key, client labels,
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
      "rmm_company_unique_id": "<private-RMM-company-ID>",
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

The findings feed's grain is one finding in each endpoint's latest scan. The
scans feed has one row per endpoint's latest scan and preserves a latest scan
with zero findings; it emits `no_observations` rather than implying a clean scan
when a client has no data for the selected period. Both feeds include a
deterministic SHA-256 `id` row key for stable row identity during ingestion and
refresh. Verify BrightGauge's CSV update/replace behavior before production. Finding
IDs are derived from the mapped client ID, observation ID, and finding ID;
scan IDs use the mapped client ID and observation ID (or client ID and period
for a no-observation row). These IDs omit endpoint names but are not secrets
or an anonymization guarantee. The feeds do not backfill older findings when a
newer scan omits them. Use `finding_key` as the stable, pseudonymous signal
identity. The two feeds can power client,
provider, product, category, confidence, evidence, and review-state filters.
Client exports must apply the same selected-client scope to every view and must
not include other clients' rows.

### BrightGauge dataset model

Keep the two grains in separate datasets so scan-coverage counts are not
confused with finding-row counts. In the CSV dataset setup, use `id` as the
stable text row identifier and `client_label` as the client-mapping column;
confirm those roles in BrightGauge before saving. Planned field types are:

| Dataset | Grain and primary dimensions | Numeric/date fields | Client mapping |
| --- | --- | --- | --- |
| `shadow-ai-findings.csv` | One finding in each endpoint's latest scan; dimensions include `client_label`, `provider_name`, `product`, `category`, `confidence`, `review_status`, and `os_family` | `confidence_rank`, `evidence_level` as numbers; `observed_at`, `collected_at`, `reviewed_at` as dates/timestamps | `client_label` |
| `shadow-ai-scans.csv` | One latest scan per endpoint; dimensions include `client_label`, `os_family`, `collector_version`, and `scan_status` | `finding_observations` as a number; `partial` as boolean; `collected_at` as date/timestamp | `client_label` |

Use row count on the findings dataset for finding observations, not unique
users or devices. Use scan-row count for represented latest scans, and sum
`finding_observations` only within the scans dataset. `client_id` is the stable
internal filter key; keep it alongside the display/mapping label. Treat IDs,
client labels, domains, and extension metadata as confidential. Do not add a
client-facing report until a single-client filter preview proves the dataset's
client mapping is functioning.

The existing RMM automation-history dataset is a separate run-count source and
must not be combined with finding metrics. BrightGauge's **Upload CSV** dataset
workflow uses a connected Dropbox or OneDrive datasource; it is not a
standalone local-file ingestion path. Check datasource availability and plan
capacity before treating it as a pilot option. Keep the two normalized feeds
(`findings.csv` and `scans.csv`) separate. The feeds are current-state outputs,
not historical trend stores. A short-lived, restricted working archive must
retain enough observations to select the latest scan per endpoint and build the
current month's report, then can follow an approved retention/deletion schedule
after the report is delivered. The emailed report/PDF is the agreed historical
snapshot for this first version.
Before connecting the CSVs, verify field typing, update/replace behavior,
refresh timing, client mapping, and whether the source can be restricted to an
approved folder. Each upload/refresh must contain the full latest-state view for
all mapped clients, not only endpoints scanned during that run. Never replace an
existing datasource or upgrade a plan
implicitly. Store the source archives and generated feeds in approved
tenant-controlled storage, never in this public repository or a broadly shared
folder. See the [ConnectWise Datasets guide](https://docs.connectwise.com/BrightGauge/090/005)
and [dataset documentation index](https://docs.connectwise.com/BrightGauge/Reports_and_Dashboards_%28formerly_BrightGauge%29_Documentation_Site_Map)
for the dataset workflow.

The automation-history dataset may include unrelated task records. Do not export it wholesale. Use a task-scoped extraction or dedicated CSV feeds, then verify that client filters, sorting, exports, and review-state hiding consistently apply to the selected client before sharing.

### Current-state summary through RMM custom endpoint fields

BrightGauge's **Custom Endpoint Fields** dataset is generally available and
ConnectWise documents it as hourly, latest-value data. It may provide the
current-state summary path without adding another datasource: populate a small
typed set of endpoint fields from the RMM task, then build per-client gauges
from that dataset. This is not yet verified end to end. First prove on one
authorized pilot endpoint that the RMM Script Editor can write the required
fields from scanner output and that BrightGauge synchronizes those values.

Keep field values to non-sensitive scalars such as last-scan time, scan status,
and finding counts. Do not store raw observation JSON, local usernames,
browser-history entries, matched domains, or full extension metadata in custom
fields. This route is a summary, not a replacement for the finding-level HTML
table and selected-client CSV export. See the [ConnectWise RMM/BrightGauge
dataset guide](https://docs.connectwise.com/BrightGauge/040/010/BrightGauge_-_Connect_to_ConnectWise_RMM_%28formerly_Command%29)
for the Custom Endpoint Fields dataset and its refresh behavior.

## RMM task export ingestion

### Existing BrightGauge Automation Details source

The existing ConnectWise RMM **Automation Details** dataset can serve as the
export source for the first ingestion test: its visible schema includes
`company_unique_id`, `task_name`, and `execution_output`, which are the
importer's required columns. The current pilot gauge aggregates task IDs into
run counts; that view is not a finding inventory. Use the dataset's row-level
records and filter to one exact Shadow AI scanner task before extracting. Do
not include unrelated automation rows.

This is an extraction source, not durable history. ConnectWise documents that
Automation Details is synchronized every 24 hours using only the latest two
days of source data (although the source describes up to three months of daily
availability). The current importer uses a private observation archive as
working storage so the latest endpoint state can be rebuilt from validated
records; the archive is not required as a long-term historical system of
record. The delivered monthly email/PDF can serve as history. Verify the actual
export columns and task-output format on a restricted sample before importing
a larger segment. If the
tenant's CSV export delivers the file by email rather than directly to
restricted staging, do not use that workflow as unattended collection; choose
an approved retrieval path first.

When a task-scoped CSV export is available, `tools/import_rmm_task_export.py`
can validate and append its JSON observations to the private per-client
archives. Add each source `company_unique_id` to the matching client's private
manifest as `rmm_company_unique_id`; do not put real company IDs or labels in a
public example or in this repository. If the UI only provides a broader
Automation Details export, use the one-command refresh below. It performs the
exact-task reduction in restricted temporary storage before import; never load
the broad export itself directly into the dashboard pipeline.

Do not treat a gauge drilldown CSV as equivalent to the dataset export. A
recent pilot-run drilldown omitted `task_name`, and its `execution_output`
cells were not valid JSON (including one cell at the 30,000-character export
limit). The importer must reject that file; do not repair delimiters or infer
missing task identity. Use the row-level Automation Details dataset export or
another source that passes the required-column and observation-schema checks.

For a first refresh without an existing manifest, `tools/discover_rmm_clients.py`
can create a private mapping from only the selected task's `company_unique_id`
and `company_name` columns. It never copies `execution_output` or unrelated task
rows, creates pseudonymous client IDs and per-client archive paths, and refuses
ambiguous company names so they can be reconciled manually.

```bash
python3 tools/discover_rmm_clients.py \
  --input /secure/staging/automation-details.csv \
  --task-name "Shadow AI Inventory - Windows" \
  --task-name "Shadow AI Inventory - macOS (Perl)" \
  --output /secure/shadow-ai/dashboard-clients.json
```

Repeat `--task-name` to discover the union of clients represented by multiple
explicit platform or versioned collector tasks.

Review the generated private client labels and mappings before the first
refresh. The manifest and every generated archive/feed/report remain outside
the public repository.

When a new client appears in later exports, preserve existing archive and
review mappings by writing a merged manifest beside the current one. The
merge accepts only company IDs and labels from the exact selected tasks; it
does not retain task output. It rejects display-name conflicts for manual
reconciliation.

```bash
python3 tools/discover_rmm_clients.py \
  --input /secure/staging/automation-details.csv \
  --task-name "Shadow AI Inventory - Windows" \
  --merge-existing /secure/shadow-ai/dashboard-clients.json \
  --output /secure/shadow-ai/dashboard-clients-next.json
```

Review the new private mapping, then use it for the refresh. Keep the previous
manifest until the refresh is verified; the output is a new file and never
overwrites the existing mapping.

```bash
python3 tools/refresh_dashboard_from_rmm_export.py \
  --input /secure/staging/automation-details.csv \
  --manifest /secure/shadow-ai/dashboard-clients.json \
  --task-name "Shadow AI Inventory - Windows" \
  --task-name "Shadow AI Inventory - macOS (Perl)" \
  --staging-dir /secure/staging/shadow-ai \
  --output-dir /secure/shadow-ai/brightgauge-feed \
  --dashboard /secure/shadow-ai/internal-dashboard.html
```

Repeat `--task-name` for every approved platform or versioned collector task
that should feed the same dashboard. Each value is matched exactly; similar
names and every task not explicitly listed remain excluded. The command
validates and imports only those task rows whose RMM company IDs are mapped in
the private manifest. It leaves the broad source unchanged,
removes the temporary task-only CSV, and rebuilds the feeds/dashboard from the
latest state in the private working archive. Existing outputs are protected
unless `--overwrite` is supplied. It does not upload data to BrightGauge or
configure a schedule.

For a two-step process that keeps a task-only CSV for separate review, use the
local reducer below before running `tools/refresh_dashboard.py`:

```bash
python3 tools/filter_rmm_task_export.py \
  --input /secure/staging/automation-details.csv \
  --manifest /secure/shadow-ai/dashboard-clients.json \
  --task-name "Shadow AI Inventory - Windows" \
  --task-name "Shadow AI Inventory - macOS (Perl)" \
  --output /secure/staging/shadow-ai-task-only.csv
```

The reducer streams the source without changing it, skips rows for other tasks
without parsing or copying their output, and accepts only company IDs mapped in
the private manifest. It validates selected scanner JSON, writes only the
three required columns to a new file with mode `0600` inside a `0700` staging
directory, and refuses to overwrite. Keep both source and reduced export in
restricted storage and follow the approved source-retention process; do not
print either file's contents or commit them to this repository. This is a
fallback intake step, not authorization to create or export a broad dataset.

Some BrightGauge Automation Details exports use semicolons between JSON
members. The reducer normalizes only semicolons outside quoted JSON strings,
then still requires strict JSON parsing and full schema validation. If a
selected execution output is exactly 30,000 characters and cannot be parsed,
the default is to fail the import. This may indicate truncation at the export
limit. Use `--allow-truncated-rows` only for a deliberately partial technician
view: the malformed row is excluded and the dashboard displays a warning with
the count and that affected findings are missing. Re-export or rerun those
executions before interpreting that view as complete. This flag is not a way
to suppress other malformed rows or broaden the selected task/client scope.
Current collectors prevent most such truncation by emitting a bounded
`SHADOWAI_GZIP_V1:` envelope when compact JSON exceeds 12,000 bytes. Intake
decodes that envelope before schema validation and archives ordinary JSON.
Legacy tasks must be updated to use the current collector build; already
truncated rows still require a fresh execution.

For a single repeatable refresh of the archive, both BrightGauge CSV feeds, and
the sortable technician HTML view, run:

```bash
python3 tools/refresh_dashboard.py \
  --input /secure/staging/shadow-ai-task-export.csv \
  --manifest /secure/shadow-ai/dashboard-clients.json \
  --task-name "Shadow AI Inventory - Windows" \
  --output-dir /secure/shadow-ai/brightgauge-feed \
  --dashboard /secure/shadow-ai/internal-dashboard.html
```

Omit `--period` for present state. Use `--period YYYY-MM` only when selecting
the latest scan per endpoint within a particular month. The default rebuilds
from the complete working archive so endpoints not scanned in the newest run
remain represented by their latest known scan. The command refuses
to replace existing feed or dashboard files unless `--overwrite` is supplied;
re-importing identical observation IDs is safe and idempotent. It does not
upload to BrightGauge or configure a refresh schedule: upload the two feeds
through the approved dataset workflow and verify field types, mappings,
retention, and filters there.

To archive observations without rebuilding the views, the lower-level import
command remains available:

```bash
python3 tools/import_rmm_task_export.py \
  --input /secure/staging/shadow-ai-task-export.csv \
  --manifest /secure/shadow-ai/dashboard-clients.json \
  --task-name "Shadow AI Inventory - Windows"
```

The input must be a task-filtered CSV containing `company_unique_id`,
`task_name`, and `execution_output`. The importer independently requires every
row to match that exact task and a mapped company ID; it rejects a broad export
containing unrelated task rows, unmapped clients, invalid/oversized JSON,
conflicting observation IDs, or paths inside this public repository. It
validates the collector schema, stores immutable JSON files named by
`observation_id` under the mapped client archives, uses mode `0600` files and
`0700` archive directories on POSIX, and treats identical re-imports as skips.
If storage fails mid-run, rerunning the same export is safe: previously stored
identical observations are skipped. The CSV itself remains in its private
staging location for the operator's approved retention/deletion process.

### Handling raw RMM exports

Treat the export and every `execution_output` value as confidential endpoint
telemetry. Apply the exact scanner-task filter and confirm the intended company
scope in RMM before exporting. Download directly to a restricted local staging
directory; do not open or preview the CSV in a browser/task-output pane, paste
raw output into chat, tickets, email, or shell history, or copy it into this
repository. Some RMM views render the complete scanner JSON when a task run is
selected. Use only the downloaded, task-scoped file with
`tools/refresh_dashboard.py`; it validates every row and archives observations
under the mapped client. Keep staging access limited and remove the source CSV
according to the approved retention policy after verifying import and feed
generation. Prefer aggregate counts for routine status, and protect them at the
same level as dashboard feeds when cross-client activity is sensitive. Never
print the underlying JSON as a troubleshooting shortcut.

The importer does not fetch from BrightGauge or choose storage/retention; a
task-scoped export workflow and private manifest must be established separately.
Do not extract or publish the raw `execution_output` field wholesale. The
lower-level `tools/build_dashboard_feed.py` and
`tools/build_internal_dashboard.py` commands remain available for independent
rebuilds. The private technician dashboard also provides a single-client,
currently-filtered HTML report export with a print-to-PDF action and selected-
client CSV export. Both are disabled until exactly one client is selected;
neither includes endpoint/local-user identities or reviewer notes. Use
`tools/build_report.py` when a standalone observation-archive report is needed
outside the dashboard.

## Private internal HTML dashboard

For a filterable technician view before a findings dataset is available in
BrightGauge, build an offline dashboard directly from the same private manifest
and validated archives:

```bash
python3 tools/build_internal_dashboard.py \
  --manifest /secure/shadow-ai/dashboard-clients.json \
  --output /secure/shadow-ai/internal-dashboard.html
```

The dashboard opens to the latest scan per endpoint from the restricted working
archive. If `--period YYYY-MM` is supplied, it selects each endpoint's latest
scan within that month; omit it for the latest scan regardless of month. A
technician can scope the dashboard to one client; the selected scope applies
to summary metrics, charts, findings, and exports. It supports provider/product,
finding type, confidence, review-state, and text filters; sortable finding
columns; a sortable client comparison table with finding counts, scan health,
and oldest latest scan time per client; and scan-health status. Finding values
honor every active finding filter. Endpoint counts reflect only scan
records present in the archive and are not a verified fleet denominator. A
latest partial scan remains partial; older findings are not backfilled into the
present-state view. Customer CSV and HTML report exports stay disabled until
one client is selected and include only that client's currently filtered
findings. The customer HTML report also includes summary metrics, charts, and
any applicable source-export quality warning. Endpoint and local-user
identities, reviewer names, and review reasons are omitted from both customer
exports. Retain the delivered monthly email/PDF as the historical snapshot.
Browser-created customer exports inherit the browser's local download
permissions; restrict the files before sharing or retaining them, and only
share through an approved client delivery channel.

The output is a self-contained file embedding the included client telemetry;
it makes no network requests and has no built-in SSO/MFA protection. The
builder requires a parent directory with POSIX mode `0700` or stricter, creates
the HTML with mode `0600`, and refuses outputs within this public repository or
an existing file unless `--overwrite` is explicit. Keep it local or in an
approved, access-controlled location; do not attach it to tickets, email it,
or place it in a broadly shared folder. Rebuild after new scans rather than
assuming the page refreshes itself. Use the approved, access-controlled shared
technician dashboard once a dedicated findings feed and filterable dataset are
connected.

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

The preferred history mechanism is a **monthly client-scoped report delivered by email**, with a PDF attachment retained as that month's snapshot. Once a findings-level BrightGauge dataset is connected and its client mappings and report filters have been verified, use BrightGauge Client Reporting's native monthly schedule and PDF attachment option rather than building a separate email sender. BrightGauge supports scheduled client reports and an optional PDF attachment; the documented attachment limit is 25 MB. See [ConnectWise Client Reporting](https://docs.connectwise.com/BrightGauge/070/030).

Until that data path is ready, generate and review each client's report from the private working observations, then deliver it only through an approved channel to verified recipients. Do not send the all-client technician dashboard or a multi-client feed as a history artifact. Before enabling automated distribution, configure verified recipients, client-specific permissions, an approved channel, and a clear per-client versus internal audience. Never distribute a report containing another client's data. Long-term machine-readable scan retention is optional for this first version; retain it only if a later audit or recalculation requirement justifies the added data lifecycle.

After the mechanics are validated, deploy the report and automation workflow in an appropriate private organization repository and configure a tenant-aware job there. The public repository should contain generic collector/report code, schemas, and tests only. Keep client configuration, observations, decisions, credentials, storage URLs, recipient lists, and generated reports in private tenant-controlled systems.

## Pilot exit criteria

- The chosen endpoints are explicitly scoped and the client approves the collection and destination.
- The RMM output is complete, valid JSON and passes the observation validator.
- Browser extensions and matched website-domain indicators appear correctly for known-positive tests; negative controls remain clean within measured coverage.
- Partial collection, duplicate outputs, repeated observations, filter intersections, and acknowledgements behave as documented.
- The report contains only that client's rows, review state, and label; output files are outside the public repository.
- Storage, retention, access, schedule, and distribution choices are approved before broad collection.
