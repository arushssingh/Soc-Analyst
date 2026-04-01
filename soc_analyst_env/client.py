"""SOC Analyst Environment Client."""

from typing import Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

from .models import SOCAction, SOCObservation


class SocAnalystEnv(
    EnvClient[SOCAction, SOCObservation, State]
):
    """
    Client for the SOC Analyst Environment.

    Example:
        >>> with SocAnalystEnv(base_url="http://localhost:8000") as client:
        ...     result = client.reset(task_type="phishing_triage")
        ...     print(result.observation.message)
        ...
        ...     result = client.step(SOCAction(
        ...         action_type="get_alert_queue", params={}
        ...     ))
        ...     print(result.observation.data)
    """

    def _step_payload(self, action: SOCAction) -> Dict:
        return {
            "action_type": action.action_type,
            "params": action.params,
        }

    def _parse_result(self, payload: Dict) -> StepResult[SOCObservation]:
        obs_data = payload.get("observation", {})
        observation = SOCObservation(
            message=obs_data.get("message", ""),
            data=obs_data.get("data", {}),
            task_type=obs_data.get("task_type", ""),
            step_number=obs_data.get("step_number", 0),
            max_steps=obs_data.get("max_steps", 0),
            available_actions=obs_data.get("available_actions", []),
            done=payload.get("done", False),
            reward=payload.get("reward"),
            metadata=obs_data.get("metadata", {}),
        )
        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict) -> State:
        return State(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
        )
