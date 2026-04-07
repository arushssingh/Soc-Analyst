"""
Inference Script for SOC Analyst Environment
=============================================

Baseline agent that uses an LLM via the OpenAI client to investigate
security alerts in the SOC Analyst environment.

MANDATORY environment variables:
    API_BASE_URL   The API endpoint for the LLM.
    MODEL_NAME     The model identifier to use for inference.
    HF_TOKEN       Your Hugging Face / API key.
"""

import json
import os
import textwrap
from typing import Any, Dict, List

from openai import OpenAI

API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY")
MODEL_NAME = os.getenv("MODEL_NAME", "meta-llama/Llama-3.3-70B-Instruct")

ENV_URL = os.getenv("SOC_ENV_URL", "http://localhost:8000")
BENCHMARK = "soc_analyst_env"
TEMPERATURE = 0.2
MAX_TOKENS = 1024


# --- Structured stdout helpers (hackathon validator format) ---

def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: str | None) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} score={score:.2f} rewards={rewards_str}",
        flush=True,
    )

# --- Tool definitions for the LLM ---

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_alert_queue",
            "description": "Get the current alert queue with pending security alerts.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "examine_alert",
            "description": "Get detailed information about a specific alert.",
            "parameters": {
                "type": "object",
                "properties": {
                    "alert_id": {"type": "string", "description": "The alert ID to examine"},
                },
                "required": ["alert_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "examine_email",
            "description": "Get full email details including headers, body, URLs, and attachments.",
            "parameters": {
                "type": "object",
                "properties": {
                    "email_id": {"type": "string", "description": "The email ID to examine"},
                },
                "required": ["email_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_logs",
            "description": "Query a specific log source. Sources: firewall, ids_ips, endpoint, email_gateway, auth_logs, dns_logs, proxy_logs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "source": {"type": "string", "description": "Log source name"},
                    "filter_ip": {"type": "string", "description": "Optional IP filter"},
                    "filter_keyword": {"type": "string", "description": "Optional keyword filter"},
                },
                "required": ["source"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_threat_intel",
            "description": "Check threat intelligence for an indicator (IP, domain, hash, URL).",
            "parameters": {
                "type": "object",
                "properties": {
                    "indicator": {"type": "string", "description": "The indicator to look up"},
                    "indicator_type": {"type": "string", "description": "Type: ip, domain, hash, url"},
                },
                "required": ["indicator"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_url_reputation",
            "description": "Check the reputation and risk score of a URL.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The URL to check"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_file_hash",
            "description": "Look up a file hash in malware databases.",
            "parameters": {
                "type": "object",
                "properties": {
                    "hash_value": {"type": "string", "description": "The file hash to check"},
                },
                "required": ["hash_value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "correlate_events",
            "description": "Cross-correlate events across all log sources by IP address.",
            "parameters": {
                "type": "object",
                "properties": {
                    "source_ip": {"type": "string", "description": "Source IP to correlate"},
                    "dest_ip": {"type": "string", "description": "Destination IP to correlate"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_endpoint_details",
            "description": "Get details about a specific endpoint/host (OS, user, role, etc.).",
            "parameters": {
                "type": "object",
                "properties": {
                    "hostname": {"type": "string", "description": "The hostname to look up"},
                },
                "required": ["hostname"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "classify_alert",
            "description": "Submit classification verdict for an alert. Verdicts: true_positive, false_positive, benign, suspicious.",
            "parameters": {
                "type": "object",
                "properties": {
                    "alert_id": {"type": "string", "description": "Alert ID to classify"},
                    "verdict": {
                        "type": "string",
                        "enum": ["true_positive", "false_positive", "benign", "suspicious"],
                    },
                    "confidence": {"type": "number", "description": "Confidence 0.0-1.0"},
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Evidence supporting the verdict",
                    },
                },
                "required": ["alert_id", "verdict"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "take_remediation",
            "description": "Execute remediation action. Actions: block_ip, block_domain, quarantine_host, quarantine_email, disable_account, escalate_to_tier2, no_action.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": [
                            "block_ip", "block_domain", "quarantine_host",
                            "quarantine_email", "disable_account",
                            "escalate_to_tier2", "no_action",
                        ],
                    },
                    "target": {"type": "string", "description": "Target (IP, domain, hostname)"},
                    "justification": {"type": "string", "description": "Reason for the action"},
                },
                "required": ["action", "target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_incident_report",
            "description": "Submit comprehensive incident report (required for APT detection task).",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                    "kill_chain_phases": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "MITRE ATT&CK phases observed (e.g., initial_access, execution, lateral_movement, exfiltration)",
                    },
                    "evidence_summary": {"type": "string"},
                    "affected_hosts": {"type": "array", "items": {"type": "string"}},
                    "iocs": {"type": "array", "items": {"type": "string"}, "description": "Indicators of compromise"},
                    "recommendations": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["title", "severity", "kill_chain_phases", "evidence_summary"],
            },
        },
    },
]

SYSTEM_PROMPT = textwrap.dedent("""\
    You are an expert SOC (Security Operations Center) analyst.
    You investigate security alerts by examining evidence across multiple log sources,
    checking threat intelligence, correlating events, and making triage decisions.

    Investigation methodology:
    1. Review the alert queue to understand pending alerts
    2. Examine each alert in detail
    3. For email alerts: examine the email content, headers, and URLs
    4. Query relevant log sources for supporting evidence
    5. Check threat intelligence for known indicators (IPs, domains, hashes)
    6. Correlate events across sources to build the full picture
    7. Classify alerts with evidence-backed verdicts
    8. Take appropriate remediation actions
    9. For complex incidents (APT): submit a comprehensive incident report

    Always gather sufficient evidence before making classifications.
    Be thorough but efficient - minimize unnecessary steps.
""")


def run_episode(task_type: str, seed: int = 0) -> float:
    """Run a single episode using WebSocket client for state persistence."""
    from client import SocAnalystEnv
    from models import SOCAction

    llm_client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

    env = SocAnalystEnv(base_url=ENV_URL)
    final_score = 0.0
    rewards: List[float] = []
    step_count = 0
    success = False

    try:
        env.connect()
        result = env.reset(task_type=task_type, seed=seed)
        obs = result.observation
        max_steps = obs.max_steps

        log_start(task=task_type, env=BENCHMARK, model=MODEL_NAME)

        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Environment observation:\n"
                    f"Task: {obs.task_type}\n"
                    f"Message: {obs.message}\n"
                    f"Data: {json.dumps(obs.data, indent=2)}\n"
                    f"Available actions: {obs.available_actions}\n\n"
                    f"You have {max_steps} steps. Investigate and resolve the alerts."
                ),
            },
        ]

        done = result.done

        while not done and step_count < max_steps:
            try:
                completion = llm_client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=messages,
                    tools=TOOLS,
                    tool_choice="auto",
                    temperature=TEMPERATURE,
                    max_tokens=MAX_TOKENS,
                    stream=False,
                )
            except Exception as exc:
                print(f"[DEBUG] LLM error: {exc}", flush=True)
                break

            msg = completion.choices[0].message

            if msg.tool_calls:
                messages.append({
                    "role": "assistant",
                    "content": msg.content,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                        for tc in msg.tool_calls
                    ],
                })

                for tc in msg.tool_calls:
                    action_type = tc.function.name
                    try:
                        params = json.loads(tc.function.arguments)
                    except json.JSONDecodeError:
                        params = {}

                    step_count += 1
                    action_str = f"{action_type}({json.dumps(params)})"

                    action = SOCAction(action_type=action_type, params=params)
                    result = env.step(action)
                    obs = result.observation
                    done = result.done
                    reward = result.reward or 0.0

                    rewards.append(reward)
                    log_step(step=step_count, action=action_str, reward=reward, done=done, error=None)

                    obs_dict = {
                        "message": obs.message,
                        "data": obs.data,
                        "step_number": obs.step_number,
                        "max_steps": obs.max_steps,
                    }
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": json.dumps(obs_dict),
                    })

                    if done:
                        final_score = obs.data.get("final_score", reward)
                        break
            else:
                if msg.content:
                    messages.append({"role": "assistant", "content": msg.content})
                messages.append({
                    "role": "user",
                    "content": "Use the available tools to investigate. Call a tool now.",
                })
                step_count += 1
                rewards.append(0.0)
                log_step(step=step_count, action="no_tool_call", reward=0.0, done=False, error=None)

    finally:
        env.close()
        final_score = min(max(final_score, 0.0), 1.0)
        success = final_score >= 0.1
        log_end(success=success, steps=step_count, score=final_score, rewards=rewards)

    return float(final_score)


def run_episode_direct(task_type: str, seed: int = 0) -> float:
    """Run a single episode using direct environment instantiation (no server)."""
    from server.soc_analyst_env_environment import SocAnalystEnvironment
    from models import SOCAction

    llm_client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

    env = SocAnalystEnvironment()
    obs = env.reset(task_type=task_type, seed=seed)
    max_steps = obs.max_steps

    log_start(task=task_type, env=BENCHMARK, model=MODEL_NAME)

    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Environment observation:\n"
                f"Task: {obs.task_type}\n"
                f"Message: {obs.message}\n"
                f"Data: {json.dumps(obs.data, indent=2)}\n"
                f"Available actions: {obs.available_actions}\n\n"
                f"You have {max_steps} steps. Investigate and resolve the alerts."
            ),
        },
    ]

    done = obs.done
    step_count = 0
    final_score = 0.0
    rewards: List[float] = []
    success = False

    try:
        while not done and step_count < max_steps:
            try:
                completion = llm_client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=messages,
                    tools=TOOLS,
                    tool_choice="auto",
                    temperature=TEMPERATURE,
                    max_tokens=MAX_TOKENS,
                    stream=False,
                )
            except Exception as exc:
                print(f"[DEBUG] LLM error: {exc}", flush=True)
                break

            msg = completion.choices[0].message

            if msg.tool_calls:
                messages.append({
                    "role": "assistant",
                    "content": msg.content,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                        for tc in msg.tool_calls
                    ],
                })

                for tc in msg.tool_calls:
                    action_type = tc.function.name
                    try:
                        params = json.loads(tc.function.arguments)
                    except json.JSONDecodeError:
                        params = {}

                    step_count += 1
                    action_str = f"{action_type}({json.dumps(params)})"

                    action = SOCAction(action_type=action_type, params=params)
                    obs = env.step(action)
                    done = obs.done
                    reward = obs.reward or 0.0

                    rewards.append(reward)
                    log_step(step=step_count, action=action_str, reward=reward, done=done, error=None)

                    obs_dict = {
                        "message": obs.message,
                        "data": obs.data,
                        "step_number": obs.step_number,
                        "max_steps": obs.max_steps,
                    }
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": json.dumps(obs_dict),
                    })

                    if done:
                        final_score = obs.data.get("final_score", reward)
                        break
            else:
                if msg.content:
                    messages.append({"role": "assistant", "content": msg.content})
                messages.append({
                    "role": "user",
                    "content": "Use the available tools to investigate. Call a tool now.",
                })
                step_count += 1
                rewards.append(0.0)
                log_step(step=step_count, action="no_tool_call", reward=0.0, done=False, error=None)

    finally:
        final_score = min(max(final_score, 0.0), 1.0)
        success = final_score >= 0.1
        log_end(success=success, steps=step_count, score=final_score, rewards=rewards)

    return float(final_score)


def main() -> None:
    """Run baseline agent on all 3 tasks."""
    tasks = [
        ("phishing_triage", 0),
        ("malware_investigation", 0),
        ("apt_detection", 0),
    ]

    # Use direct mode (no server needed) if no ENV_URL is set
    use_direct = os.getenv("SOC_ENV_URL") is None
    runner = run_episode_direct if use_direct else run_episode

    scores: Dict[str, float] = {}
    for task_type, seed in tasks:
        score = runner(task_type, seed)
        scores[task_type] = score

    avg = sum(scores.values()) / len(scores) if scores else 0.0
    print(f"[DEBUG] BASELINE SCORES: {scores} average={avg:.3f}", flush=True)


if __name__ == "__main__":
    main()
