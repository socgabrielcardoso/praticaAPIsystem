# Pagination

Collection endpoints should enforce bounded page sizes.

Benefits:
- predictable resource usage;
- reduced accidental data exposure;
- stable client behavior.

Do not allow clients to request unlimited datasets through a single parameter.