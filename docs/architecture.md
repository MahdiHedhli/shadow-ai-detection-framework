# Architecture

## Objective

Provide one detection program that can accept telemetry from different endpoint, identity, network, cloud, browser, and RMM stacks without rewriting the program's risk model for every client.

## Logical flow

```text
Client telemetry -> platform adapter -> normalized observation -> correlation -> policy overlay -> finding
```

### Shared layer

The shared layer contains:

- Provider and product catalog
- Indicator provenance
- Detection specifications
- Confidence rules
- Platform adapters
- Test fixtures

It must not contain client identifiers, approval decisions, exceptions, or telemetry.

### Client layer

Each client supplies:

- Available telemetry sources
- Approved, conditional, prohibited, and unknown products
- Asset and identity criticality
- Data classifications
- Retention and privacy requirements
- Response authority

### Observation model

Every adapter should emit or map to these concepts:

- Tenant or client scope
- Event timestamp
- User, device, application, and agent identities
- Provider and product
- Channel: web, API, endpoint, browser extension, OAuth, agent, MCP, or local model
- Activity: observed, installed, executed, authenticated, authorized, uploaded, invoked, or administered
- Evidence source and source event identifier
- Approval state
- Confidence
- Sensitive-data context when supplied by an authoritative DLP or classification source

## Evidence levels

1. **Presence** — an artifact, installation, extension, domain, or agent exists.
2. **Use** — execution, repeated access, authentication, authorization, or invocation is observed.
3. **Organizational connection** — corporate identity, managed device, company data, payment, or integration is involved.
4. **Sensitive interaction** — an authoritative DLP, sensitivity label, upload, or protected-resource signal is present.
5. **High-impact automation** — the AI system or agent can execute code, write data, send messages, make purchases, or invoke privileged tools.

Detections must state the highest evidence level they can establish. Correlation may raise the level; a domain lookup alone may not.

## MSP isolation requirements

- Partition telemetry and findings by immutable client identifier.
- Apply least-privilege access and client-scoped analyst roles.
- Encrypt data in transit and at rest.
- Keep client watchlists and exception lists in their own workspaces or vault-backed configuration.
- Audit query execution and response actions.
- Prevent cross-client joins unless the data has been explicitly anonymized and approved for aggregate analysis.

