# Security Policy

## Reporting a vulnerability

Do not open a public issue containing credentials, client identifiers, tenant data, detection bypass details tied to a live client, or sensitive telemetry samples.

Until a private reporting channel is configured, report security concerns directly to the repository owner through an approved internal channel.

## Data-handling requirements

- Never commit prompts, responses, access tokens, API keys, cookies, OAuth grants, or client telemetry.
- Use synthetic fixtures in tests and documentation.
- Redact secrets before storing command lines or configuration excerpts.
- Keep per-client approval lists and exceptions outside the shared repository.
- Treat generated watchlists as security configuration and review changes before deployment.
- Run endpoint discovery scripts in read-only mode by default.
- Do not terminate processes, remove software, revoke consent, or block traffic without an explicit client-approved response policy.

## Supply-chain requirements

The initial build uses only the Python standard library. Future dependencies must be pinned, reviewed, and documented before adoption.

