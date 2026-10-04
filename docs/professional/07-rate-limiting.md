# Rate Limiting

Apply controls according to endpoint cost and abuse potential.

Prioritize:
- authentication;
- password reset;
- search/enumeration;
- resource creation;
- expensive processing;
- notification triggers.

Return predictable 429 behavior and avoid leaking internal thresholds unnecessarily.