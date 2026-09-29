# RMM endpoint collectors

The generated collectors add a portable endpoint-inventory layer for clients that do not share the same EDR or SIEM. They produce the same JSON observation shape on Windows, macOS, and Linux and are intended for scheduled, read-only execution by an RMM.

## Deployment artifacts

- `dist/rmm-windows/ShadowAIInventory.ps1` supports Windows PowerShell 5.1 or later.
- `dist/rmm-macos-linux/shadow_ai_inventory.py` supports Python 3 using only the standard library.
- `dist/rmm-macos-linux/shadow_ai_inventory.pl` is a macOS-native fallback for devices without Python; it uses the macOS Perl `JSON::PP` module and SQLite command-line utility.
- `dist/rmm-macos-linux/shadow_ai_inventory_rmm.sh` bundles that Perl fallback for RMM products whose macOS task editor executes Bash. It embeds the Perl source, writes it to a mode-0600 temporary file during execution, and removes the file on exit; endpoints do not download code.
- `schema/observation.schema.json` is the platform-neutral output contract.
- `tools/validate_observation.py` performs dependency-free structural and privacy checks.

The endpoint indicator array inside each collector is generated from `catalog/endpoint_artifacts.csv`. Edit the catalog and rebuild instead of maintaining separate lists inside deployment scripts.

## Extension catalog history

`catalog/browser_extension_history.csv` is the durable observation ledger for extension IDs. It records each dated listing check and is also published under `dist/catalog/` for reporting. `catalog/browser_extension_candidates.csv` holds redirected replacement IDs awaiting manual publisher verification; candidate rows never enter endpoint detections automatically.

The `Update browser extension inventory` GitHub workflow runs every Monday at 07:17 UTC and can also be started manually. It revalidates every cataloged listing, appends that day's result, rebuilds and tests the distribution, and opens a review pull request. This preserves the complete framework history in both the ledger and Git commits. Store availability alone does not prove publisher identity, so the workflow deliberately does not auto-promote a new ID.

## Privacy and security boundary

The collectors inspect process metadata and a bounded set of known application, model, MCP configuration, browser-extension, and browser-history locations for every discovered local user profile. Extension inventory covers Firefox plus stable, Beta, Dev, and Canary variants of Chrome and Edge where supported, along with Brave, Chromium, Vivaldi, Arc, and Opera-family profile locations. Browser extensions are classified locally using exact IDs from `catalog/browser_extensions.csv` first, then specific product-name patterns from `catalog/browser_extension_name_patterns.csv`. Chromium collectors also inspect the bounded manifest index inside `Preferences` and `Secure Preferences`, plus presence-only directories for cataloged IDs under `Local Extension Settings` and `Sync Extension Settings`. This covers registered extensions whose package directory is absent or staged elsewhere and extensions that use a different store ID. Only matched extension metadata is emitted. For profiles with extensions, the collector also emits total and classified counts so coverage gaps can be measured without disclosing unrelated extension IDs or names. Permissions, descriptions, preference contents, and manifest contents are never reported. Exact-ID package-directory matches are high confidence; preference-index, extension-state, and local name fallback matches are medium confidence. State-directory presence can be stale and does not prove current execution. The collectors do not perform a whole-disk search or follow symbolic links/reparse points.

The Perl macOS fallback intentionally implements the core bounded checks (processes, known model/MCP paths, exact cataloged Chromium extension IDs, and Chrome/Edge/Brave/Chromium/Firefox history hostnames). It uses only the OS-provided Perl/JSON::PP and SQLite command-line utility, does not install software, and does not require Xcode Command Line Tools. Its narrower extension coverage does not include manifest-name/domain fallbacks, extension-state directories, Safari history, or installed-software inventory; `scope` lists only the checks it actually performs. Prefer the Python collector when a working Python 3 runtime already exists. The Perl fallback is macOS-only and has a metadata-only `--self-test` mode.

On Windows, installed-software coverage combines machine uninstall keys, the current-user key, uninstall keys from user hives that Windows already has loaded, `Get-AppxPackage -AllUsers`, and bounded known application locations. The collector never loads offline user registry hives. Current Claude Desktop deployments are detected through their `Claude` MSIX package; the bounded `%LOCALAPPDATA%\AnthropicClaude` check covers the legacy standalone installer.

Command-line arguments and browser-history URLs are evaluated only on the endpoint and are never included in output. History inspection is capped at 256 MiB per browser profile. The macOS/Linux collector queries URL hostnames from each supported browser database; the Windows collector performs a bounded string match because Windows PowerShell 5.1 does not include a SQLite client. History findings contain only the matched domain from the public catalog, browser name, profile name, and local username.

The Windows string match is low-confidence, presence-only evidence: deleted SQLite records or URL-shaped strings embedded elsewhere in the database can remain detectable. A history finding shows that a cataloged AI domain was present in the browser database; it does not prove account ownership, login state, data submission, or policy violation.

The collectors do not emit:

- prompts or responses;
- file or configuration contents;
- API keys, tokens, or environment-variable values;
- raw browser URLs, page titles, timestamps, or unrelated history;
- unrelated browser-extension IDs, names, permissions, descriptions, or manifest contents;
- raw process command lines.

They make no network requests and perform no remediation. A finding means “observed,” not “malicious” or “policy-violating.” Apply tenant-specific approval and risk policy after ingestion.

## Exit behavior

| Code | Meaning |
|---:|---|
| 0 | Collection completed. Findings may or may not be present. |
| 1 | Fatal collector failure; standard output should not be ingested as an observation. |
| 2 | A usable observation was emitted, but one or more collection areas were partial. |

This convention intentionally avoids using a nonzero exit code to signal that AI was found. Configure the RMM to retain standard output for codes 0 and 2, alert on code 1, and mark code 2 for collection-health review.

## Suggested rollout

1. Run `-SelfTest` on Windows or `--self-test` on macOS/Linux through the intended RMM execution context.
2. Validate the returned JSON with `tools/validate_observation.py` in the ingestion pipeline.
3. Pilot real collection on a small, representative endpoint group and measure execution time, output size, access-denied rates, and false positives.
4. Set an output-size limit appropriate to the RMM. The schema caps findings at 5,000; production ingestion should additionally enforce a byte limit.
5. Store observations in a tenant-isolated location, enrich them with client-specific approval state, and expire endpoint metadata according to the client retention policy.

## RMM task configuration

For RMMs that execute PowerShell scripts and retain task output, package the generated Windows collector as a versioned, read-only custom task (for example, `Shadow AI Inventory - Windows`). Embed the reviewed `dist/rmm-windows/ShadowAIInventory.ps1` contents in the task; do not make endpoints download or execute a mutable script from a public URL. Set the expected run time from pilot measurements with a conservative ceiling, retain standard output for exit codes 0 and 2, alert on exit code 1, and flag exit code 2 for collection-health review. Run the self-test before the first collection, then assign only to a consented pilot device group.

For an authorized macOS pilot in ConnectWise RMM's **Bash Script** editor, paste `dist/rmm-macos-linux/shadow_ai_inventory_rmm.sh`, not the raw `.pl` file: the editor invokes Bash, which then calls the built-in `/usr/bin/perl`. Give the task a distinct name such as `Shadow AI Inventory - macOS (Perl)` so task history and exports can be scoped precisely. First run a self-test bundle built with `python3 tools/build_perl_rmm_bundle.py --output /secure/path/shadow-ai-inventory-rmm.sh --self-test` and confirm it returns one schema-shaped JSON observation with an empty findings list. The regular build omits that self-test flag and performs the bounded collection. If the RMM runner cannot pass script arguments, use a separate self-test bundle for the one-time check; do not leave the self-test argument in the production task. The Perl fallback covers only its documented bounded macOS scope; prefer Python 3 when it is already available and validated, but do not install Python fleet-wide solely for this inventory. Start with the authorized pilot group and review partial/error status before expansion.

The RMM task output is the handoff into reporting: retain the JSON as task output, export only that scanner task, then process it through the private importer/refresh command in [Monthly collection and reporting](monthly-reporting.md#rmm-task-export-ingestion). Give it a distinct name where the RMM allows. If the RMM emits a generic task label, scope the export to only the scanner's executions before download; the importer requires an exact `task_name` and intentionally rejects mixed-task exports rather than silently combining unrelated output.

To protect against BrightGauge's 30,000-character output-cell limit, current collectors emit ordinary schema JSON through 12,000 UTF-8 bytes and a `SHADOWAI_GZIP_V1:` base64/gzip envelope above that size. The private importer validates envelope length, bounded decompressed size, gzip framing, UTF-8, and then the normal observation schema; it archives only the decoded observation JSON. A compressed payload that still exceeds 24,000 characters fails visibly instead of being clipped. Existing RMM tasks must be updated with the newly built collector artifacts before this protection applies; already-truncated historical rows still need a fresh execution.

### BrightGauge latest-state summary via endpoint custom fields

ConnectWise RMM's Script Editor can map a script step's `%output%` to an
endpoint custom field with its **Set Custom Field** function. BrightGauge also
has a Command datasource dataset named **Custom Endpoint Fields**; in the
RampUp account it is described as syncing hourly and always showing the latest
information. This is a viable companion view for a small, bounded per-device
summary (for example, scan status, last-scan time, finding count, and collector
version), after a one-endpoint write-back test confirms the exact field types
and values appear in that dataset.

This is not the findings-history pipeline: custom-field values are latest-state
per endpoint, so later runs replace the previous value. Do not map the full
scanner JSON, browser-history evidence, user/profile details, or MCP paths into
custom fields. The RMM custom-fields screen warns against using fields to
retrieve personally identifiable information, and a summary field cannot
preserve finding-level history. Keep full task JSON in the task output and use
the task-scoped export/import process for historical findings and scan feeds.

Validate Windows browser-history and extension coverage against approved known-positive and negative-control endpoints before expanding a pilot. Review lower-confidence name- or manifest-domain-based extension matches before treating them as confirmed products; exact catalog-ID matches provide stronger evidence. Keep pilot telemetry and target identities out of this public repository.

Do not schedule a broad fleet rollout based only on task success. First review output size, run time, coverage summaries, low-confidence matches, and tenant authorization. Weekly collection is a reasonable initial pilot cadence when approved. Historical inventory must be append-only and tenant-isolated: retain each observation with its collection timestamp, collector version, stable device identity, and a pseudonymous subject identifier where possible. Avoid overwriting the prior run with the latest result. Apply the customer's retention period and restrict report access because observations include endpoint and local-user identifiers.

The extension-catalog workflow and endpoint collector release are separate controls. The GitHub workflow reviews store listings weekly and opens a pull request; it does not change the RMM task. Promote catalog changes only after human verification, rebuild and validate the distribution, then update the versioned RMM task deliberately. Do not let an automated listing check silently change detection behavior on client endpoints.

RMM output is suitable as a per-tenant operational report when the platform can preserve task history and support tenant-scoped permissions. If the RMM cannot export observations safely or provide useful cross-run comparisons, send validated JSON through an authenticated, tenant-aware ingestion service rather than combining client data in a shared spreadsheet or mailbox. Keep Microsoft 365 reporting as a downstream view unless its ingestion, identity mapping, retention, and tenant isolation are explicitly established.

For Windows pilots, include at least one confirmed per-user MSIX application and one traditional uninstall-registry application. Compare the collector result with RMM application inventory; RMM products commonly omit per-user packaged applications.

Do not enable automated removal or blocking directly from these inventory findings. Require corroborating evidence and a client-approved response policy first.

## Self-test examples

```powershell
.\ShadowAIInventory.ps1 -SelfTest
```

```bash
python3 shadow_ai_inventory.py --self-test | python3 tools/validate_observation.py
```

```bash
perl shadow_ai_inventory.pl --self-test | python3 tools/validate_observation.py
```

```bash
bash shadow_ai_inventory_rmm.sh --self-test | python3 tools/validate_observation.py
```

Self-test emits an empty observation and does not enumerate profiles, processes, installed software, browser extensions, or browser history.
