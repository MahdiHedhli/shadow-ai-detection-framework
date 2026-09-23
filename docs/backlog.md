# Backlog

This backlog records work that should not be promoted to production until it has been validated with representative client endpoints and the intended management stack.

## macOS multi-tenant workstream

### P0: establish a deployable Mac collector

- Inventory macOS versions, Apple silicon/Intel mix, RMM execution account, script interpreter availability, MDM enrollment, and browser mix across pilot tenants.
- Do not assume Python 3 exists. Choose and test either an RMM-provided runtime, a shell-only bootstrap-free collector, or a signed universal binary. The production job must not download or execute code from the internet.
- Preserve the shared observation schema, privacy guarantees, bounded reads, and exit-code behavior used by the Windows collector.
- Measure runtime, output size, permission failures, and partial-collection rates separately for each client.

### P0: known-positive pilot matrix

- Select at least one consented known-positive and one negative-control Mac at each client.
- Include both standard-user and local-admin profiles where they exist, plus Apple silicon and Intel devices if both remain deployed.
- Seed or confirm representative evidence: an AI desktop app, a Chromium or Firefox extension, browser-history presence, and an MCP configuration. Record expected results before running the collector.
- Re-run after logout, browser disablement, application removal, and endpoint restart to distinguish current state from stale artifacts.

### P1: Mac application and local-tool inventory

- Expand beyond `/Applications` to bounded per-user `~/Applications` locations.
- Identify applications by signed bundle identifier and Team ID when available, not only by a mutable app name or path.
- Evaluate bounded package-receipt, Launch Services, Homebrew/cask, and command-line-tool evidence without performing a full-disk search.
- Cover Claude, ChatGPT, Cursor, Windsurf, Ollama, LM Studio, and other cataloged tools with separately scored installed, configured, and running evidence.

### P1: browser and extension coverage

- Validate every local profile for Chrome-family browsers, Edge, Brave, Arc, Firefox, and other browsers actually present at each client.
- Add Safari as a separate adapter. Safari web extensions are packaged inside host apps and should use the composed extension identity—bundle identifier plus Team ID—rather than Chromium IDs.
- Distinguish installed, enabled, and enabled-for-profile states where macOS exposes them reliably. Do not label installation or stale state as active use.
- Continue emitting only matched AI-extension metadata and count-only coverage summaries; never emit unrelated extension identities or permissions.

### P1: Apple privacy controls

- Establish a default collection tier that requires no new privacy grants and reports inaccessible evidence as partial coverage.
- Test Safari and protected per-user data under current macOS privacy controls. Do not bypass TCC.
- If enhanced evidence requires access, document the smallest PPPC permission and deliver it only through the client's MDM after explicit approval. Keep the RMM binary or script identity and signing requirement stable enough for the profile.
- Treat managed Safari extension policy as a governance input on supported devices, not as proof that an extension executed.

### P1: MCP and agent configuration

- Validate presence-only configuration discovery for Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Gemini CLI, Codex, and other cataloged clients across every local user.
- Report product, configuration type, local user, and tokenized location only. Never read or emit server definitions, arguments, environment values, secrets, or configuration contents.

## Ongoing MSP operations

- Compare three tenant-isolated ingestion options after endpoint accuracy is validated: RMM-native dashboard/reporting, enrichment of the planned Microsoft 365 report, or a separate Shadow AI reporting service.
- Define collection cadence, offline-device retry behavior, observation retention, per-client approval lists, and delta reporting.
- Preserve raw observations per tenant and generate cross-client MSP summaries only from non-identifying aggregates.
- Add health reporting for collector version, partial coverage, stale endpoints, runtime, and output truncation before scheduling broadly.
- Keep discovery separate from remediation. Blocking, uninstalling, or alert escalation requires corroborating evidence and an approved client policy.

## Exit criteria for broad Mac rollout

- Known-positive tests meet the agreed detection target at both clients with documented false negatives.
- Negative controls do not disclose unrelated browser, application, or configuration data.
- The selected runtime works without ad hoc software installation on the supported Mac fleet.
- TCC/PPPC requirements and failure modes are documented and approved.
- Observations reach the chosen tenant-isolated reporting destination with auditable retention and access controls.
