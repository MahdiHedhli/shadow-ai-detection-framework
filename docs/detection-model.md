# Detection Model

## Dispositions

- `approved`
- `conditionally_approved`
- `unreviewed`
- `prohibited`
- `exception`

The shared catalog does not assign a client disposition. Adapters default to `unreviewed`; the client policy overlay supplies the final value.

## Confidence

- **Low:** keyword, name, or single weak artifact match.
- **Medium:** exact domain, executable, extension ID, configuration file, or repeated activity.
- **High:** authenticated organizational use, confirmed installation plus execution, privileged OAuth/agent permission, or multiple independent signals.

## Severity

Severity is derived from context, not product name:

- Presence on a managed endpoint: informational or low.
- Repeated use of an unreviewed product: low or medium.
- Non-browser API use, service-account use, or automation: medium or high.
- Sensitive-data DLP evidence or privileged agent access: high.
- Confirmed prohibited transfer or autonomous high-impact action: high or critical under the client's policy.

## Promotion criteria

A hunting query may become a scheduled detection only after:

1. Its required tables and fields are present.
2. It runs successfully in the target environment.
3. Positive and negative fixtures have been tested.
4. False-positive behavior has been measured during a baseline period.
5. A client owner, response path, and suppression strategy exist.
6. The rule does not collect unnecessary content or secrets.

