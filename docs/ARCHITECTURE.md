# Architecture

praticaAPIsystem receives an indicator, normalizes it, selects compatible intelligence providers, queries them concurrently and returns one defensive assessment with the underlying evidence preserved.

## Flow

Input enters through the CLI or FastAPI layer.

The indicator parser accepts IPv4, IPv6, domains, HTTP or HTTPS URLs, MD5, SHA1, SHA256 and CVE identifiers. Common defanged forms such as hxxps and example[.]com are restored before validation.

The service layer determines which providers support the indicator type. Credentials are checked before a request is created. Private or non globally routable IP data is kept local.

Provider adapters isolate external API behavior. Each adapter converts its native response into the same Finding model so correlation does not depend on vendor specific schemas.

The scoring layer evaluates provider findings without discarding source evidence. Multiple independent adverse signals increase confidence. Missing data remains unknown instead of being treated as clean.

The result is returned with the normalized indicator, verdict, score, provider evidence, skipped providers, provider errors, tags and execution time.

## Providers

VirusTotal covers IPs, domains, URLs and file hashes.

AbuseIPDB adds abuse reputation for public IP addresses.

URLhaus adds malware distribution intelligence for hosts and URLs.

GreyNoise adds internet scanner and IP behavior context.

AlienVault OTX adds pulse based threat intelligence across several IOC types.

NVD adds CVSS and vulnerability metadata for CVEs.

FIRST EPSS adds exploitation probability for CVEs.

## Safety controls

Secrets are loaded from environment variables through pydantic settings and are never included in provider state responses.

HTTP redirects are disabled for outbound provider requests.

External calls have bounded timeouts, connection limits and retry limits.

API responses receive a correlation identifier, no store caching directive and nosniff header.

The service refuses to send private IP indicators to external intelligence providers.

## Execution surfaces

The FastAPI application exposes health, provider inventory, single indicator analysis and batch analysis.

The Typer CLI supports direct terminal based triage and can also launch the API service.

The Docker image runs as an unprivileged user and includes an application health check.

GitHub Actions validates Python 3.11 and 3.13 with Ruff, pytest and bytecode compilation.
