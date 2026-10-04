# Error Handling

Use stable external errors and protected internal detail.

External response:
- safe message;
- status code;
- correlation ID.

Internal log:
- technical cause;
- stack information when needed;
- request context without secrets.