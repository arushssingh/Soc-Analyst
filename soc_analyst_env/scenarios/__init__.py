"""Scenario data for the SOC Analyst environment."""

from typing import Optional

try:
    from .apt import APT_SCENARIOS
    from .malware import MALWARE_SCENARIOS
    from .phishing import PHISHING_SCENARIOS
except ImportError:
    from scenarios.apt import APT_SCENARIOS
    from scenarios.malware import MALWARE_SCENARIOS
    from scenarios.phishing import PHISHING_SCENARIOS

_SCENARIO_REGISTRY = {
    "phishing_triage": PHISHING_SCENARIOS,
    "malware_investigation": MALWARE_SCENARIOS,
    "apt_detection": APT_SCENARIOS,
}

MAX_STEPS = {
    "phishing_triage": 15,
    "malware_investigation": 25,
    "apt_detection": 40,
}


def load_scenario(task_type: str, seed: Optional[int] = None):
    """Load a scenario by task type and optional seed.

    Returns a Scenario object selected deterministically from the
    available scenarios for the given task type.
    """
    scenarios = _SCENARIO_REGISTRY.get(task_type)
    if scenarios is None:
        raise ValueError(
            f"Unknown task type: {task_type}. "
            f"Valid types: {list(_SCENARIO_REGISTRY.keys())}"
        )
    idx = (seed or 0) % len(scenarios)
    return scenarios[idx]
