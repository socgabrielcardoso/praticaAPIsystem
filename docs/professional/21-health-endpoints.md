# Health Endpoints

Health checks should report enough for orchestration without exposing secrets, environment variables, stack traces or internal dependency details.

Separate liveness from readiness when the deployment model benefits from it.