# RMM endpoint collectors

The generated collectors add a portable endpoint-inventory layer for clients that do not share the same EDR or SIEM. They produce the same JSON observation shape on Windows, macOS, and Linux and are intended for scheduled, read-only execution by an RMM.

## Deployment artifacts

- `dist/rmm-windows/ShadowAIInventory.ps1` supports Windows PowerShell 5.1 or later.
- `dist/rmm-macos-linux/shadow_ai_inventory.py` supports Python 3 using only the standard library.
- `schema/observation.schema.json` is the platform-neutral output contract.
- `tools/validate_observation.py` performs dependency-free structural and privacy checks.

The endpoint indicator array inside each collector is generated from `catalog/endpoint_artifacts.csv`. Edit the catalog and rebuild instead of maintaining separate lists inside deployment scripts.

## Extension catalog history

`catalog/browser_extension_history.csv` is the durable observation ledger for extension IDs. It records each dated listing check and is also published under `dist/catalog/` for reporting. `catalog/browser_extension_candidates.csv` holds redirected replacement IDs awaiting manual publisher verification; candidate rows never enter endpoint detections automatically.

The `Update browser extension inventory` GitHub workflow runs every Monday at 07:17 UTC and can also be started manually. It revalidates every cataloged listing, appends that day's result, rebuilds and tests the distribution, and opens a review pull request. This preserves the complete framework history in both the ledger and Git commits. Store availability alone does not prove publisher identity, so the workflow deliberately does not auto-promote a new ID.

## Privacy and security boundary

The collectors inspect process metadata and a bounded set of known application, model, MCP configuration, browser-extension, and browser-history locations for every discovered local user profile. Extension inventory covers Firefox plus Chrome, Edge, Brave, Chromium, Vivaldi, Arc, and Opera-family profile locations where supported. Browser extensions are classified locally using exact IDs from `catalog/browser_extensions.csv` first, then specific product-name patterns from `catalog/browser_extension_name_patterns.csv`. Chromium collectors also compare catalog IDs locally with the bounded `Preferences` and `Secure Preferences` indexes, covering a known extension registered to the profile even when its package directory is absent or staged elsewhere. Only matched extension metadata is emitted. For profiles with extensions, the collector also emits total and classified counts so coverage gaps can be measured without disclosing unrelated extension IDs or names. Permissions, descriptions, preference contents, and manifest contents are never reported. Exact-ID package-directory matches are high confidence; preference-index and local name fallback matches are medium confidence. The collectors do not perform a whole-disk search or follow symbolic links/reparse points.

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

For Windows pilots, include at least one confirmed per-user MSIX application and one traditional uninstall-registry application. Compare the collector result with RMM application inventory; RMM products commonly omit per-user packaged applications.

Do not enable automated removal or blocking directly from these inventory findings. Require corroborating evidence and a client-approved response policy first.

## Self-test examples

```powershell
.\ShadowAIInventory.ps1 -SelfTest
```

```bash
python3 shadow_ai_inventory.py --self-test | python3 tools/validate_observation.py
```

Self-test emits an empty observation and does not enumerate profiles, processes, installed software, browser extensions, or browser history.
