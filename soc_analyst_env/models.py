"""
Data models for the SOC Analyst Environment.

Defines the Action, Observation, and internal data types for a Security
Operations Center analyst triage and investigation simulation.
"""

from enum import Enum
from typing import Any, Dict, List, Optional

from openenv.core.env_server.types import Action, Observation, State
from pydantic import Field


# --- Enums ---


class TaskType(str, Enum):
    PHISHING_TRIAGE = "phishing_triage"
    MALWARE_INVESTIGATION = "malware_investigation"
    APT_DETECTION = "apt_detection"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertVerdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"


class RemediationAction(str, Enum):
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    QUARANTINE_HOST = "quarantine_host"
    QUARANTINE_EMAIL = "quarantine_email"
    DISABLE_ACCOUNT = "disable_account"
    ESCALATE_TO_TIER2 = "escalate_to_tier2"
    NO_ACTION = "no_action"


class LogSource(str, Enum):
    FIREWALL = "firewall"
    IDS_IPS = "ids_ips"
    ENDPOINT = "endpoint"
    EMAIL_GATEWAY = "email_gateway"
    AUTH_LOGS = "auth_logs"
    DNS_LOGS = "dns_logs"
    PROXY_LOGS = "proxy_logs"


class KillChainPhase(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"


# --- Action / Observation ---

VALID_ACTIONS = [
    "get_alert_queue",
    "examine_alert",
    "examine_email",
    "query_logs",
    "check_threat_intel",
    "check_url_reputation",
    "check_file_hash",
    "correlate_events",
    "get_endpoint_details",
    "classify_alert",
    "take_remediation",
    "submit_incident_report",
]


class SOCAction(Action):
    """Action for the SOC Analyst environment.

    The agent selects an action_type and provides parameters in params.
    This design maps naturally to LLM function-calling.
    """

    action_type: str = Field(
        ...,
        description=(
            "The investigation action to take. One of: "
            + ", ".join(VALID_ACTIONS)
        ),
    )
    params: Dict[str, Any] = Field(
        default_factory=dict,
        description="Parameters for the selected action",
    )


class SOCObservation(Observation):
    """Observation returned by the SOC Analyst environment.

    Contains a human-readable message and structured data from the
    last action, plus episode context.
    """

    message: str = Field(default="", description="Human-readable result description")
    data: Dict[str, Any] = Field(
        default_factory=dict, description="Structured result data"
    )
    task_type: str = Field(default="", description="Current task type")
    step_number: int = Field(default=0, description="Current step number")
    max_steps: int = Field(default=0, description="Maximum steps for this episode")
    available_actions: List[str] = Field(
        default_factory=list, description="Actions the agent can take"
    )


# --- Extended State ---


class SOCState(State):
    """Tracks investigation progress across the episode."""

    task_type: str = ""
    scenario_id: str = ""
    alerts_examined: List[str] = Field(default_factory=list)
    logs_queried: List[str] = Field(default_factory=list)
    threat_intel_checked: List[str] = Field(default_factory=list)
    urls_checked: List[str] = Field(default_factory=list)
    hashes_checked: List[str] = Field(default_factory=list)
    endpoints_checked: List[str] = Field(default_factory=list)
    emails_examined: List[str] = Field(default_factory=list)
    correlations_run: int = 0
    verdicts_submitted: Dict[str, str] = Field(default_factory=dict)
    remediations_taken: List[Dict[str, str]] = Field(default_factory=list)
    incident_report: Optional[Dict[str, Any]] = None
    evidence_collected: List[str] = Field(default_factory=list)


# --- Internal Scenario Data Types ---


class LogEntry:
    """A single log entry from a security data source."""

    __slots__ = (
        "timestamp", "source", "source_ip", "dest_ip",
        "message", "raw",
    )

    def __init__(
        self,
        timestamp: str,
        source: str,
        message: str,
        source_ip: str = "",
        dest_ip: str = "",
        raw: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.timestamp = timestamp
        self.source = source
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.message = message
        self.raw = raw or {}

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "timestamp": self.timestamp,
            "source": self.source,
            "message": self.message,
        }
        if self.source_ip:
            result["source_ip"] = self.source_ip
        if self.dest_ip:
            result["dest_ip"] = self.dest_ip
        if self.raw:
            result["details"] = self.raw
        return result


class EmailData:
    """An email record for phishing investigation."""

    __slots__ = (
        "email_id", "from_address", "to_address", "subject",
        "body", "headers", "urls", "attachments",
    )

    def __init__(
        self,
        email_id: str,
        from_address: str,
        to_address: str,
        subject: str,
        body: str,
        headers: Optional[Dict[str, str]] = None,
        urls: Optional[List[str]] = None,
        attachments: Optional[List[Dict[str, str]]] = None,
    ) -> None:
        self.email_id = email_id
        self.from_address = from_address
        self.to_address = to_address
        self.subject = subject
        self.body = body
        self.headers = headers or {}
        self.urls = urls or []
        self.attachments = attachments or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "email_id": self.email_id,
            "from": self.from_address,
            "to": self.to_address,
            "subject": self.subject,
            "body": self.body,
            "headers": self.headers,
            "urls": self.urls,
            "attachments": self.attachments,
        }


class Alert:
    """A security alert in the SOC queue."""

    __slots__ = (
        "alert_id", "timestamp", "source", "title",
        "severity", "description", "indicators",
    )

    def __init__(
        self,
        alert_id: str,
        timestamp: str,
        source: str,
        title: str,
        severity: str,
        description: str,
        indicators: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.alert_id = alert_id
        self.timestamp = timestamp
        self.source = source
        self.title = title
        self.severity = severity
        self.description = description
        self.indicators = indicators or {}

    def summary(self) -> Dict[str, str]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "title": self.title,
            "source": self.source,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "indicators": self.indicators,
        }


class ThreatIntelEntry:
    """A threat intelligence database record."""

    __slots__ = (
        "indicator", "indicator_type", "threat_type",
        "confidence", "description", "tags",
    )

    def __init__(
        self,
        indicator: str,
        indicator_type: str,
        threat_type: str,
        confidence: float,
        description: str,
        tags: Optional[List[str]] = None,
    ) -> None:
        self.indicator = indicator
        self.indicator_type = indicator_type
        self.threat_type = threat_type
        self.confidence = confidence
        self.description = description
        self.tags = tags or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "threat_type": self.threat_type,
            "confidence": self.confidence,
            "description": self.description,
            "tags": self.tags,
        }


class Scenario:
    """Complete scenario definition for a task."""

    __slots__ = (
        "scenario_id", "task_type", "alerts", "log_database",
        "emails", "threat_intel_database", "url_reputation",
        "file_hashes", "endpoint_data", "ground_truth",
    )

    def __init__(
        self,
        scenario_id: str,
        task_type: str,
        alerts: List[Alert],
        log_database: Dict[str, List[LogEntry]],
        ground_truth: Dict[str, Any],
        emails: Optional[List[EmailData]] = None,
        threat_intel_database: Optional[List[ThreatIntelEntry]] = None,
        url_reputation: Optional[Dict[str, Dict[str, Any]]] = None,
        file_hashes: Optional[Dict[str, Dict[str, Any]]] = None,
        endpoint_data: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        self.scenario_id = scenario_id
        self.task_type = task_type
        self.alerts = alerts
        self.log_database = log_database
        self.emails = emails or []
        self.threat_intel_database = threat_intel_database or []
        self.url_reputation = url_reputation or {}
        self.file_hashes = file_hashes or {}
        self.endpoint_data = endpoint_data or {}
        self.ground_truth = ground_truth
