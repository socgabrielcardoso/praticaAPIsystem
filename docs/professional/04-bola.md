# BOLA / IDOR

Object identifiers are references, not permission.

For each request, derive the authenticated subject and verify access to the specific object.

Tests should attempt access to another synthetic user's object and expect rejection.