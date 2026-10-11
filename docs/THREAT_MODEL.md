# IOC enrichment gateway: threat model

Status: **security requirements and test plan**, not a claim of implemented mitigations.

## Attack surface
IOC values, provider API responses, redirect targets, URL parameters, DNS, CLI options, configuration and exported results are untrusted. Provider API keys, analyst data and local filesystem access are protected assets.

## Required abuse-case tests
| Threat | Defensive requirement | Test |
| --- | --- | --- |
| SSRF via submitted IOC | Treat IOC as data; never fetch a submitted URL/IP unless explicitly allowlisted and restricted | Loopback, link-local, RFC1918, IPv6 and metadata endpoint candidates do not trigger network access |
| Redirect and DNS rebinding | Restrict redirects, validate resolved addresses at connection point | Redirect into internal network is blocked |
| Oversized/unexpected provider responses | Body-size limits, schema validation, timeout and bounded concurrency | Malformed/oversized response fails safely |
| Provider outage or quota abuse | Explicit connect/read timeouts, backoff, rate limits and caching policy | Simulated timeout returns safe structured error |
| Secret disclosure | Read credentials only from environment/secret store; redact logs and exception traces | Fixture scan contains no live secrets |
| Injection in exported reports | Encode all untrusted fields for HTML/CSV/terminal context | Formula-like CSV cells and markup cannot execute |
| Unauthorized API exposure | Bind to loopback by default in development; require auth and TLS for shared deployments | Unauthorized calls do not expose results |
| Supply-chain risk | Lock/scan dependencies and run isolated CI | Vulnerability scan and tests reported per commit |

## Release checks
Run `pytest`, `ruff check .`, dependency audit and synthetic SSRF/timeout tests before release. Do not claim these pass without execution logs. Only use permitted IOC sources; never upload private enterprise telemetry to third-party enrichment APIs without approval.
