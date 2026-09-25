# Validation

## Local checks

Use the development dependencies and run:

```bash
pytest
ruff check .
```

When container behavior changes, build the image and run the API in the same configuration expected by the project.

## API checks

Validate:
- accepted IOC inputs;
- malformed values;
- provider timeouts or unavailable integrations;
- deterministic normalization;
- defensive verdict generation;
- absence of API keys in logs or responses.

## Acceptance criteria

A change should keep provider-specific behavior behind clear interfaces, preserve defensive error handling and make verdicts traceable to normalized evidence.
