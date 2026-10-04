# Idempotency

Sensitive create or payment-like operations may require idempotency.

A client-supplied unique key, validated and stored server-side, can prevent accidental or malicious replay from producing duplicate effects.