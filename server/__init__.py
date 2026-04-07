"""SOC Analyst environment server components."""

try:
    from .soc_analyst_env_environment import SocAnalystEnvironment
except (ImportError, ModuleNotFoundError):
    from server.soc_analyst_env_environment import SocAnalystEnvironment

__all__ = ["SocAnalystEnvironment"]
