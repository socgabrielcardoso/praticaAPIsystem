# Security Tests

Test:
- unauthenticated access;
- invalid token;
- wrong role;
- wrong owner;
- malformed payload;
- extra fields;
- extreme values;
- replay;
- rate limit;
- safe errors.

Tests should assert both response and relevant security side effects.