# SOC Analyst Environment

An OpenEnv environment that simulates a **Security Operations Center (SOC) analyst workstation**. AI agents investigate cybersecurity alerts by examining evidence across multiple log sources, querying threat intelligence, correlating events, and making triage decisions with appropriate remediation actions.

## Motivation

SOC analysts face an overwhelming volume of security alerts daily -- most organizations see 10,000+ alerts per day with only a handful of analysts to triage them. This environment models the core workflow of alert investigation, providing a realistic training and evaluation ground for AI agents in cybersecurity operations.

The environment uses **realistic scenarios based on MITRE ATT&CK techniques**, including phishing campaigns, malware infections with C2 beacons, and multi-stage APT intrusions with full kill chain coverage.

## Tasks

### Task 1: Phishing Email Triage (Easy)

The agent receives email security alerts and must examine email headers, body content, URLs, and sender reputation to classify emails as **phishing** or **legitimate**.

- **Difficulty**: Easy (5-8 steps typical)
- **Max steps**: 15
- **Key skills**: Email header analysis, URL/domain reputation checking, identifying social engineering patterns

### Task 2: Malware Alert Investigation (Medium)

The agent receives endpoint detection alerts (e.g., suspicious PowerShell execution, PsExec usage) and must investigate by correlating logs across multiple sources (endpoint, firewall, IDS, DNS) to determine if the alert is a true positive or false positive.

- **Difficulty**: Medium (10-20 steps typical)
- **Max steps**: 25
- **Key skills**: Log correlation, threat intel lookups, understanding attack chains, remediation selection

### Task 3: APT Kill Chain Detection (Hard)

The agent faces a multi-stage Advanced Persistent Threat and must trace the full attack chain -- from initial access through lateral movement to data exfiltration -- across 7+ log sources. Must produce a comprehensive incident report.

- **Difficulty**: Hard (20-35 steps typical)
- **Max steps**: 40
- **Key skills**: Kill chain analysis, multi-source correlation, incident reporting, MITRE ATT&CK mapping

## Action Space

The agent interacts via typed actions with `action_type` and `params`:

| Action | Parameters | Description |
|--------|-----------|-------------|
| `get_alert_queue` | -- | View pending security alerts |
| `examine_alert` | `alert_id` | Get full alert details |
| `examine_email` | `email_id` | Get email headers, body, URLs, attachments |
| `query_logs` | `source`, `filter_ip?`, `filter_keyword?` | Query log sources (firewall, ids_ips, endpoint, email_gateway, auth_logs, dns_logs, proxy_logs) |
| `check_threat_intel` | `indicator`, `indicator_type?` | Look up IP/domain/hash in threat intel |
| `check_url_reputation` | `url` | Check URL risk score and category |
| `check_file_hash` | `hash_value` | Look up file hash in malware databases |
| `correlate_events` | `source_ip?`, `dest_ip?` | Cross-correlate events across all log sources |
| `get_endpoint_details` | `hostname` | Get host OS, user, role, services |
| `classify_alert` | `alert_id`, `verdict`, `confidence?`, `evidence?` | Submit verdict (true_positive / false_positive / benign / suspicious) |
| `take_remediation` | `action`, `target`, `justification?` | Execute remediation (block_ip / block_domain / quarantine_host / quarantine_email / disable_account / escalate_to_tier2 / no_action) |
| `submit_incident_report` | `title`, `severity`, `kill_chain_phases`, `evidence_summary`, `affected_hosts?`, `iocs?`, `recommendations?` | Submit comprehensive incident report (APT task) |

## Observation Space

Each observation contains:

```json
{
  "message": "Human-readable description of the result",
  "data": { "...": "Structured result data (alert details, log entries, etc.)" },
  "task_type": "phishing_triage | malware_investigation | apt_detection",
  "step_number": 3,
  "max_steps": 15,
  "available_actions": ["get_alert_queue", "examine_alert", "..."],
  "done": false,
  "reward": 0.02
}
```

## Reward Function

The reward function provides **partial credit signals** throughout the episode:

- **Investigation actions** (examine, query, check): Small positive rewards (+0.01 to +0.03) for productive investigation steps
- **Evidence discovery**: Rewards for finding threat intel matches, malicious URLs, and known hashes
- **Classification accuracy**: Larger rewards (+0.15) for correct verdicts, penalties (-0.05) for incorrect ones
- **Final episode score**: Weighted composite score (0.0-1.0) computed at episode end

### Grading Weights by Task

| Component | Phishing | Malware | APT |
|-----------|----------|---------|-----|
| Classification accuracy | 40% | 25% | -- |
| Evidence/indicator identification | 30% | 25% | 25% |
| Investigation thoroughness | 20% | 20% (log coverage) | 20% (report quality) |
| Remediation quality | -- | 20% | 15% |
| Kill chain coverage | -- | -- | 30% |
| Efficiency | 10% | 10% | 10% |

## Setup

### Prerequisites

- Python 3.10+
- `openenv-core[core]>=0.2.2`

### Install Dependencies

```bash
cd soc_analyst_env
uv sync          # or: pip install -e .
```

### Run Locally

```bash
# Start the server
uv run server
# or
uvicorn server.app:app --host 0.0.0.0 --port 8000
```

### Run with Docker

```bash
docker build -t soc-analyst-env:latest -f server/Dockerfile .
docker run -p 8000:8000 soc-analyst-env:latest
```

### Run Inference

```bash
# Set environment variables
export API_BASE_URL="https://router.huggingface.co/v1"
export MODEL_NAME="meta-llama/Llama-3.3-70B-Instruct"
export HF_TOKEN="your-token-here"

# Run baseline agent (direct mode, no server needed)
python inference.py

# Or with a running server
export SOC_ENV_URL="http://localhost:8000"
python inference.py
```

### Validate

```bash
openenv validate
```

## Baseline Scores

Scores vary by model. The grading system is designed so that:

- **Random agent**: ~0.05-0.15 (no investigation, random classifications)
- **Simple heuristic**: ~0.30-0.50 (examines alerts, classifies without deep investigation)
- **Competent agent**: ~0.60-0.80 (thorough investigation, correct classifications)
- **Expert agent**: ~0.85-1.00 (optimal investigation, all evidence found, correct remediation)

## Environment Architecture

```
soc_analyst_env/
+-- openenv.yaml              # OpenEnv manifest
+-- pyproject.toml             # Dependencies
+-- models.py                  # Action, Observation, State types
+-- client.py                  # WebSocket client
+-- inference.py               # Baseline LLM agent
+-- scenarios/
|   +-- phishing.py            # 3 phishing scenarios
|   +-- malware.py             # 3 malware scenarios
|   +-- apt.py                 # 2 APT scenarios
+-- server/
    +-- app.py                 # FastAPI application
    +-- soc_analyst_env_environment.py  # Core environment logic + graders
    +-- Dockerfile
```

## API Reference

### Reset

```
POST /reset
{"task_type": "phishing_triage", "seed": 0}
```

### Step

```
POST /step
{"action": {"action_type": "examine_alert", "params": {"alert_id": "ALERT-2024-0101"}}}
```

### State

```
GET /state
```
