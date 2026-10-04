# API Authorization

Every protected operation requires server-side authorization.

Validate:
- object ownership;
- role/permission;
- tenant boundary;
- action;
- resource state.

Never infer authorization from UI visibility or client-provided role fields.