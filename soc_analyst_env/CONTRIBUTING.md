## Project Structure

```
soc_analyst_env/
├── openenv.yaml                        # OpenEnv manifest
├── pyproject.toml                      # Package config and dependencies
├── models.py                           # Action, Observation, State Pydantic types
├── client.py                           # WebSocket client for the environment
├── inference.py                        # Baseline LLM agent using OpenAI client
├── scenarios/
│   ├── __init__.py                     # Scenario loader
│   ├── phishing.py                     # Task 1 scenarios (3 scenarios)
│   ├── malware.py                      # Task 2 scenarios (3 scenarios)
│   └── apt.py                          # Task 3 scenarios (2 scenarios)
└── server/
    ├── app.py                          # FastAPI application
    ├── soc_analyst_env_environment.py  # Core environment + graders
    ├── requirements.txt
    └── Dockerfile
```

## Adding a New Scenario

1. Open the relevant scenario file (e.g. `scenarios/phishing.py`)
2. Define a new function returning a `Scenario` object
3. Add it to the list at the bottom of the file (e.g. `PHISHING_SCENARIOS`)

## Running Tests

```bash
python3 -c "
from server.soc_analyst_env_environment import SocAnalystEnvironment
from models import SOCAction

env = SocAnalystEnvironment()
obs = env.reset(task_type='phishing_triage', seed=0)
print(obs.message)
"
```

## Validate

```bash
openenv validate --verbose
```
