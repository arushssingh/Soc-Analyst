"""
FastAPI application for the SOC Analyst Environment.

Endpoints:
    - POST /reset: Reset the environment
    - POST /step: Execute an action
    - GET /state: Get current environment state
    - GET /schema: Get action/observation schemas
    - WS /ws: WebSocket endpoint for persistent sessions
"""

try:
    from openenv.core.env_server.http_server import create_app
except Exception as e:
    raise ImportError(
        "openenv is required. Install with: pip install 'openenv-core[core]'"
    ) from e

try:
    from ..models import SOCAction, SOCObservation
    from .soc_analyst_env_environment import SocAnalystEnvironment
except (ImportError, ModuleNotFoundError):
    from models import SOCAction, SOCObservation
    from server.soc_analyst_env_environment import SocAnalystEnvironment


app = create_app(
    SocAnalystEnvironment,
    SOCAction,
    SOCObservation,
    env_name="soc_analyst_env",
    max_concurrent_envs=4,
)


def main(host: str = "0.0.0.0", port: int = 8000) -> None:
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
