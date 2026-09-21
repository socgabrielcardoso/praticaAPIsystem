# Security Policy

praticaAPIsystem is a defensive threat intelligence project. Security issues should be handled with enough detail to reproduce the problem without exposing live credentials, private infrastructure or unrelated third party data.

## Supported version

The main branch is the actively maintained version.

## Reporting

Use a private GitHub security advisory when available. Include the affected component, impact, reproduction steps, expected behavior and any safe proof of concept needed to validate the issue.

Do not publish API keys, tokens, internal IP ranges, customer data or credentials in issues, commits, screenshots or logs.

## Secrets

Provider credentials are read from environment variables. The repository intentionally ignores local environment files. Example values must remain empty.

Rotate a credential immediately if it is ever committed or exposed outside the intended secret store.

## Defensive scope

The project is intended for IOC enrichment, triage and defensive investigation. External intelligence services remain authoritative for their own data, quotas and terms of use. A returned score is supporting evidence for an analyst, not an automatic authorization to block, delete or isolate an asset.

## Network safety

Private and non globally routable IP indicators are not sent to external intelligence providers. URLs containing embedded usernames or passwords are rejected before enrichment.
