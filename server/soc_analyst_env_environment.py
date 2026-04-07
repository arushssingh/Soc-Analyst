"""
SOC Analyst Environment Implementation.

Simulates a Security Operations Center analyst workstation where an AI agent
investigates cybersecurity alerts, correlates evidence across log sources,
and takes remediation actions.
"""

from typing import Any, Dict, List, Optional
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

try:
    from ..models import (
        VALID_ACTIONS,
        AlertVerdict,
        KillChainPhase,
        LogSource,
        RemediationAction,
        SOCAction,
        SOCObservation,
        SOCState,
        Scenario,
    )
    from ..scenarios import MAX_STEPS, load_scenario
except (ImportError, ModuleNotFoundError):
    from models import (
        VALID_ACTIONS,
        AlertVerdict,
        KillChainPhase,
        LogSource,
        RemediationAction,
        SOCAction,
        SOCObservation,
        SOCState,
        Scenario,
    )
    from scenarios import MAX_STEPS, load_scenario


class SocAnalystEnvironment(Environment):
    """
    SOC Analyst triage and investigation environment.

    The agent investigates security alerts using a toolkit of investigation
    actions, then classifies alerts and takes remediation steps. Three task
    types with increasing difficulty:

    - phishing_triage (easy): Classify emails as phishing or legitimate
    - malware_investigation (medium): Investigate endpoint alerts across logs
    - apt_detection (hard): Trace a multi-stage APT kill chain
    """

    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self) -> None:
        super().__init__()
        self._state = SOCState(episode_id=str(uuid4()), step_count=0)
        self._scenario: Optional[Scenario] = None
        self._max_steps: int = 15
        self._episode_done: bool = False

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> SOCObservation:
        task_type = kwargs.get("task_type", "phishing_triage")
        if task_type not in MAX_STEPS:
            task_type = "phishing_triage"

        self._scenario = load_scenario(task_type, seed)
        self._max_steps = MAX_STEPS[task_type]
        self._episode_done = False

        self._state = SOCState(
            episode_id=episode_id or str(uuid4()),
            step_count=0,
            task_type=task_type,
            scenario_id=self._scenario.scenario_id,
        )

        alert_summaries = [a.summary() for a in self._scenario.alerts]

        return SOCObservation(
            message=(
                f"SOC Analyst workstation ready. Task: {task_type}. "
                f"You have {len(self._scenario.alerts)} alert(s) in your queue. "
                f"Investigate the alerts and take appropriate action. "
                f"You have {self._max_steps} steps maximum."
            ),
            data={"alert_queue": alert_summaries},
            task_type=task_type,
            step_number=0,
            max_steps=self._max_steps,
            available_actions=VALID_ACTIONS,
            done=False,
            reward=0.0,
        )

    def step(self, action: SOCAction, **kwargs: Any) -> SOCObservation:
        if self._episode_done or self._scenario is None:
            return SOCObservation(
                message="Episode is over. Call reset() to start a new episode.",
                done=True,
                reward=0.0,
                task_type=self._state.task_type,
                step_number=self._state.step_count,
                max_steps=self._max_steps,
            )

        self._state.step_count += 1

        if action.action_type not in VALID_ACTIONS:
            return self._make_obs(
                f"Unknown action: {action.action_type}. "
                f"Valid actions: {', '.join(VALID_ACTIONS)}",
                reward=-0.01,
            )

        handler = getattr(self, f"_handle_{action.action_type}", None)
        if handler is None:
            return self._make_obs(
                f"Action {action.action_type} not implemented.",
                reward=-0.01,
            )

        obs = handler(action.params)

        # Check episode termination
        if self._state.step_count >= self._max_steps and not self._episode_done:
            self._episode_done = True
            final_score = self._compute_final_score()
            return SOCObservation(
                message=(
                    f"Maximum steps reached ({self._max_steps}). "
                    f"Episode complete. Final score: {final_score:.3f}"
                ),
                data={"final_score": final_score, "last_result": obs.data},
                done=True,
                reward=final_score,
                task_type=self._state.task_type,
                step_number=self._state.step_count,
                max_steps=self._max_steps,
            )

        return obs

    @property
    def state(self) -> State:
        return self._state

    # --- Helper ---

    def _make_obs(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        reward: float = 0.0,
        done: bool = False,
    ) -> SOCObservation:
        if done:
            self._episode_done = True
        return SOCObservation(
            message=message,
            data=data or {},
            task_type=self._state.task_type,
            step_number=self._state.step_count,
            max_steps=self._max_steps,
            available_actions=VALID_ACTIONS if not done else [],
            done=done,
            reward=reward,
        )

    # --- Action Handlers ---

    def _handle_get_alert_queue(self, params: Dict[str, Any]) -> SOCObservation:
        assert self._scenario is not None
        summaries = [a.summary() for a in self._scenario.alerts]
        return self._make_obs(
            f"Alert queue: {len(summaries)} alert(s) pending investigation.",
            data={"alerts": summaries},
            reward=0.01,
        )

    def _handle_examine_alert(self, params: Dict[str, Any]) -> SOCObservation:
        assert self._scenario is not None
        alert_id = params.get("alert_id", "")
        for alert in self._scenario.alerts:
            if alert.alert_id == alert_id:
                if alert_id not in self._state.alerts_examined:
                    self._state.alerts_examined.append(alert_id)
                return self._make_obs(
                    f"Alert {alert_id} details retrieved.",
                    data={"alert": alert.to_dict()},
                    reward=0.02,
                )
        return self._make_obs(
            f"Alert {alert_id} not found in queue.",
            reward=-0.01,
        )

    def _handle_examine_email(self, params: Dict[str, Any]) -> SOCObservation:
        assert self._scenario is not None
        email_id = params.get("email_id", "")
        for email in self._scenario.emails:
            if email.email_id == email_id:
                if email_id not in self._state.emails_examined:
                    self._state.emails_examined.append(email_id)
                return self._make_obs(
                    f"Email {email_id} retrieved with headers and content.",
                    data={"email": email.to_dict()},
                    reward=0.03,
                )
        return self._make_obs(
            f"Email {email_id} not found.",
            reward=-0.01,
        )

    def _handle_query_logs(self, params: Dict[str, Any]) -> SOCObservation:
        assert self._scenario is not None
        source = params.get("source", "")
        filter_ip = params.get("filter_ip", "")
        filter_keyword = params.get("filter_keyword", "")

        if source not in self._scenario.log_database:
            available = list(self._scenario.log_database.keys())
            return self._make_obs(
                f"Log source '{source}' not available. Available: {available}",
                reward=-0.01,
            )

        if source not in self._state.logs_queried:
            self._state.logs_queried.append(source)

        entries = self._scenario.log_database[source]
        results = []
        for entry in entries:
            if filter_ip and filter_ip not in (entry.source_ip, entry.dest_ip):
                continue
            if filter_keyword and filter_keyword.lower() not in entry.message.lower():
                continue
            results.append(entry.to_dict())

        return self._make_obs(
            f"Query returned {len(results)} log entries from {source}.",
            data={"source": source, "entries": results, "total": len(results)},
            reward=0.02 if results else 0.0,
        )

    def _handle_check_threat_intel(self, params: Dict[str, Any]) -> SOCObservation:
        assert self._scenario is not None
        indicator = params.get("indicator", "")
        indicator_type = params.get("indicator_type", "")

        if indicator not in self._state.threat_intel_checked:
            self._state.threat_intel_checked.append(indicator)

        matches = []
        for entry in self._scenario.threat_intel_database:
            if entry.indicator == indicator:
                matches.append(entry.to_dict())
            elif (
                indicator_type
                and entry.indicator_type == indicator_type
                and indicator in entry.indicator
            ):
                matches.append(entry.to_dict())

        if matches:
            self._state.evidence_collected.append(f"threat_intel:{indicator}")
            return self._make_obs(
                f"Threat intel match found for '{indicator}'.",
                data={"matches": matches},
                reward=0.03,
            )

        return self._make_obs(
            f"No threat intel matches for '{indicator}'.",
            data={"matches": []},
            reward=0.0,
        )

    def _handle_check_url_reputation(self, params: Dict[str, Any]) -> SOCObservation:
        assert self._scenario is not None
        url = params.get("url", "")

        if url not in self._state.urls_checked:
            self._state.urls_checked.append(url)

        rep = self._scenario.url_reputation.get(url)
        if rep:
            self._state.evidence_collected.append(f"url_rep:{url}")
            return self._make_obs(
                f"URL reputation data for '{url}'.",
                data={"url": url, "reputation": rep},
                reward=0.03,
            )

        return self._make_obs(
            f"No reputation data available for '{url}'.",
            data={"url": url, "reputation": {"category": "unknown", "risk_score": -1}},
            reward=0.0,
        )

    def _handle_check_file_hash(self, params: Dict[str, Any]) -> SOCObservation:
        assert self._scenario is not None
        hash_value = params.get("hash_value", "")

        if hash_value not in self._state.hashes_checked:
            self._state.hashes_checked.append(hash_value)

        info = self._scenario.file_hashes.get(hash_value)
        if info:
            self._state.evidence_collected.append(f"hash:{hash_value}")
            return self._make_obs(
                f"File hash match found.",
                data={"hash": hash_value, "info": info},
                reward=0.03,
            )

        return self._make_obs(
            f"No information found for hash '{hash_value}'.",
            data={"hash": hash_value, "info": None},
            reward=0.0,
        )

    def _handle_correlate_events(self, params: Dict[str, Any]) -> SOCObservation:
        assert self._scenario is not None
        source_ip = params.get("source_ip", "")
        dest_ip = params.get("dest_ip", "")
        time_window = params.get("time_window", "")

        self._state.correlations_run += 1

        correlated: List[Dict[str, Any]] = []
        for source_name, entries in self._scenario.log_database.items():
            for entry in entries:
                match = False
                if source_ip and source_ip in (entry.source_ip, ""):
                    match = True
                if dest_ip and dest_ip in (entry.dest_ip, ""):
                    match = True
                if source_ip and entry.source_ip == source_ip:
                    match = True
                if dest_ip and entry.dest_ip == dest_ip:
                    match = True
                if match:
                    result = entry.to_dict()
                    result["log_source"] = source_name
                    correlated.append(result)

        return self._make_obs(
            f"Cross-source correlation found {len(correlated)} related events.",
            data={
                "correlated_events": correlated,
                "filters": {"source_ip": source_ip, "dest_ip": dest_ip},
            },
            reward=0.03 if correlated else 0.0,
        )

    def _handle_get_endpoint_details(self, params: Dict[str, Any]) -> SOCObservation:
        assert self._scenario is not None
        hostname = params.get("hostname", "")

        if hostname not in self._state.endpoints_checked:
            self._state.endpoints_checked.append(hostname)

        info = self._scenario.endpoint_data.get(hostname)
        if info:
            return self._make_obs(
                f"Endpoint details for '{hostname}'.",
                data={"endpoint": info},
                reward=0.02,
            )

        return self._make_obs(
            f"No endpoint data found for '{hostname}'.",
            reward=-0.01,
        )

    def _handle_classify_alert(self, params: Dict[str, Any]) -> SOCObservation:
        assert self._scenario is not None
        alert_id = params.get("alert_id", "")
        verdict = params.get("verdict", "")
        confidence = params.get("confidence", 0.5)
        evidence = params.get("evidence", [])

        # Validate alert exists
        alert_ids = {a.alert_id for a in self._scenario.alerts}
        if alert_id not in alert_ids:
            return self._make_obs(
                f"Alert {alert_id} not found.",
                reward=-0.01,
            )

        # Validate verdict
        valid_verdicts = [v.value for v in AlertVerdict]
        if verdict not in valid_verdicts:
            return self._make_obs(
                f"Invalid verdict '{verdict}'. Valid: {valid_verdicts}",
                reward=-0.01,
            )

        self._state.verdicts_submitted[alert_id] = verdict

        # Check correctness and compute partial reward
        gt = self._scenario.ground_truth.get("classifications", {})
        correct = gt.get(alert_id) == verdict
        reward = 0.15 if correct else -0.05

        # Check if all alerts classified for phishing task
        task_type = self._state.task_type
        all_classified = all(aid in self._state.verdicts_submitted for aid in alert_ids)

        if task_type == "phishing_triage" and all_classified:
            self._episode_done = True
            final_score = self._compute_final_score()
            return self._make_obs(
                f"Alert {alert_id} classified as {verdict}. "
                f"All alerts classified. Final score: {final_score:.3f}",
                data={
                    "classification": {"alert_id": alert_id, "verdict": verdict, "correct": correct},
                    "final_score": final_score,
                },
                reward=final_score,
                done=True,
            )

        return self._make_obs(
            f"Alert {alert_id} classified as {verdict}.",
            data={"classification": {"alert_id": alert_id, "verdict": verdict, "correct": correct}},
            reward=reward,
        )

    def _handle_take_remediation(self, params: Dict[str, Any]) -> SOCObservation:
        assert self._scenario is not None
        action = params.get("action", "")
        target = params.get("target", "")
        justification = params.get("justification", "")

        valid_actions = [a.value for a in RemediationAction]
        if action not in valid_actions:
            return self._make_obs(
                f"Invalid remediation action '{action}'. Valid: {valid_actions}",
                reward=-0.01,
            )

        self._state.remediations_taken.append({
            "action": action,
            "target": target,
            "justification": justification,
        })

        # For malware task, check if we can end the episode
        task_type = self._state.task_type
        all_classified = all(
            a.alert_id in self._state.verdicts_submitted
            for a in self._scenario.alerts
        )
        has_remediation = len(self._state.remediations_taken) > 0

        if task_type == "malware_investigation" and all_classified and has_remediation:
            self._episode_done = True
            final_score = self._compute_final_score()
            return self._make_obs(
                f"Remediation action taken: {action} on {target}. "
                f"Investigation complete. Final score: {final_score:.3f}",
                data={
                    "remediation": {"action": action, "target": target},
                    "final_score": final_score,
                },
                reward=final_score,
                done=True,
            )

        return self._make_obs(
            f"Remediation action taken: {action} on {target}.",
            data={"remediation": {"action": action, "target": target}},
            reward=0.02,
        )

    def _handle_submit_incident_report(self, params: Dict[str, Any]) -> SOCObservation:
        assert self._scenario is not None
        report = {
            "title": params.get("title", ""),
            "severity": params.get("severity", ""),
            "kill_chain_phases": params.get("kill_chain_phases", []),
            "evidence_summary": params.get("evidence_summary", ""),
            "affected_hosts": params.get("affected_hosts", []),
            "iocs": params.get("iocs", []),
            "recommendations": params.get("recommendations", []),
        }

        self._state.incident_report = report
        self._episode_done = True
        final_score = self._compute_final_score()

        return self._make_obs(
            f"Incident report submitted. Final score: {final_score:.3f}",
            data={"report": report, "final_score": final_score},
            reward=final_score,
            done=True,
        )

    # --- Grading ---

    def _compute_final_score(self) -> float:
        task_type = self._state.task_type
        if task_type == "phishing_triage":
            return self._grade_phishing()
        elif task_type == "malware_investigation":
            return self._grade_malware()
        elif task_type == "apt_detection":
            return self._grade_apt()
        return 0.0

    def _grade_phishing(self) -> float:
        """Grade phishing triage task.

        Weights:
            0.40 - Classification accuracy
            0.30 - Indicator identification (evidence gathered)
            0.20 - Evidence quality (investigation thoroughness)
            0.10 - Efficiency (fewer steps = better)
        """
        assert self._scenario is not None
        gt = self._scenario.ground_truth

        # Classification accuracy
        gt_classes = gt.get("classifications", {})
        correct = sum(
            1 for aid, v in self._state.verdicts_submitted.items()
            if gt_classes.get(aid) == v
        )
        total = len(gt_classes)
        classification_score = correct / max(total, 1)

        # Indicator identification
        key_indicators = set(gt.get("key_indicators", []))
        found = 0
        for ind in key_indicators:
            if any(ind in item for item in self._state.evidence_collected):
                found += 1
            elif ind in self._state.threat_intel_checked:
                found += 1
            elif ind in self._state.urls_checked:
                found += 1
            elif any(ind.lower() in q.lower() for q in self._state.logs_queried):
                found += 1
        indicator_score = found / max(len(key_indicators), 1)

        # Evidence quality - did the agent use diverse investigation methods?
        evidence_actions = 0
        if self._state.emails_examined:
            evidence_actions += 1
        if self._state.threat_intel_checked:
            evidence_actions += 1
        if self._state.urls_checked:
            evidence_actions += 1
        if self._state.logs_queried:
            evidence_actions += 1
        if self._state.alerts_examined:
            evidence_actions += 1
        evidence_score = min(evidence_actions / 3.0, 1.0)

        # Efficiency
        efficiency_score = max(0.0, 1.0 - (self._state.step_count / self._max_steps))

        score = (
            0.40 * classification_score
            + 0.30 * indicator_score
            + 0.20 * evidence_score
            + 0.10 * efficiency_score
        )
        return round(min(max(score, 0.0), 1.0), 3)

    def _grade_malware(self) -> float:
        """Grade malware investigation task.

        Weights:
            0.25 - Correct verdict
            0.25 - Evidence completeness
            0.20 - Log source coverage
            0.20 - Remediation quality
            0.10 - Efficiency
        """
        assert self._scenario is not None
        gt = self._scenario.ground_truth

        # Verdict accuracy
        gt_classes = gt.get("classifications", {})
        correct = sum(
            1 for aid, v in self._state.verdicts_submitted.items()
            if gt_classes.get(aid) == v
        )
        verdict_score = correct / max(len(gt_classes), 1)

        # Evidence completeness
        key_evidence = set(gt.get("key_evidence", []))
        evidence_found = 0
        all_evidence = " ".join(self._state.evidence_collected).lower()
        for ev in key_evidence:
            if ev.lower() in all_evidence:
                evidence_found += 1
            # Check if evidence was gathered through investigation actions
            elif any(
                ev.lower() in item.lower()
                for item in (
                    self._state.threat_intel_checked
                    + self._state.hashes_checked
                    + self._state.endpoints_checked
                )
            ):
                evidence_found += 1
        evidence_score = evidence_found / max(len(key_evidence), 1)

        # Log source coverage
        relevant_sources = set(gt.get("relevant_log_sources", []))
        queried_sources = set(self._state.logs_queried)
        coverage = len(relevant_sources & queried_sources)
        source_score = coverage / max(len(relevant_sources), 1)

        # Remediation quality
        correct_rems = set(gt.get("correct_remediations", []))
        taken_rems = {r["action"] for r in self._state.remediations_taken}
        correct_taken = len(correct_rems & taken_rems)
        wrong_taken = len(taken_rems - correct_rems)
        rem_score = max(0.0, correct_taken / max(len(correct_rems), 1) - wrong_taken * 0.2)

        # Efficiency
        efficiency_score = max(0.0, 1.0 - (self._state.step_count / self._max_steps))

        score = (
            0.25 * verdict_score
            + 0.25 * evidence_score
            + 0.20 * source_score
            + 0.20 * rem_score
            + 0.10 * efficiency_score
        )
        return round(min(max(score, 0.0), 1.0), 3)

    def _grade_apt(self) -> float:
        """Grade APT kill chain detection task.

        Weights:
            0.30 - Kill chain coverage
            0.25 - Evidence completeness (IOCs, hosts)
            0.20 - Report quality
            0.15 - Remediation quality
            0.10 - Efficiency
        """
        assert self._scenario is not None
        gt = self._scenario.ground_truth
        report = self._state.incident_report or {}

        # Kill chain coverage
        gt_kill_chain = gt.get("kill_chain", {})
        reported_phases = set(report.get("kill_chain_phases", []))
        # Also consider phases from verdicts and investigation
        phases_found = 0
        for phase_name in gt_kill_chain:
            if phase_name in reported_phases:
                phases_found += 1
            # Check if agent found evidence related to this phase
            phase_evidence = gt_kill_chain[phase_name].get("evidence", [])
            for ev in phase_evidence:
                if any(
                    ev.lower() in item.lower()
                    for item in self._state.evidence_collected
                ):
                    phases_found += 0.5
                    break
        kill_chain_score = min(phases_found / max(len(gt_kill_chain), 1), 1.0)

        # Evidence completeness (IOCs and hosts)
        gt_iocs = set(gt.get("iocs", []))
        gt_hosts = set(gt.get("affected_hosts", []))

        found_iocs = 0
        for ioc in gt_iocs:
            if (
                ioc in self._state.threat_intel_checked
                or ioc in self._state.hashes_checked
                or ioc in self._state.urls_checked
                or ioc in set(report.get("iocs", []))
            ):
                found_iocs += 1
        ioc_score = found_iocs / max(len(gt_iocs), 1)

        found_hosts = 0
        reported_hosts = set(report.get("affected_hosts", []))
        checked_hosts = set(self._state.endpoints_checked)
        for host in gt_hosts:
            if host in reported_hosts or host in checked_hosts:
                found_hosts += 1
        host_score = found_hosts / max(len(gt_hosts), 1)

        evidence_score = 0.6 * ioc_score + 0.4 * host_score

        # Report quality
        report_score = 0.0
        if report:
            if report.get("title"):
                report_score += 0.2
            if report.get("severity"):
                report_score += 0.15
            if report.get("kill_chain_phases"):
                report_score += 0.25
            if report.get("evidence_summary"):
                report_score += 0.2
            if report.get("affected_hosts"):
                report_score += 0.1
            if report.get("recommendations"):
                report_score += 0.1
        else:
            # No report submitted - partial credit from classifications
            gt_classes = gt.get("classifications", {})
            correct = sum(
                1 for aid, v in self._state.verdicts_submitted.items()
                if gt_classes.get(aid) == v
            )
            report_score = 0.3 * (correct / max(len(gt_classes), 1))

        # Remediation quality
        correct_rems = set(gt.get("correct_remediations", []))
        taken_rems = {r["action"] for r in self._state.remediations_taken}
        correct_taken = len(correct_rems & taken_rems)
        rem_score = correct_taken / max(len(correct_rems), 1)

        # Efficiency
        efficiency_score = max(0.0, 1.0 - (self._state.step_count / self._max_steps))

        score = (
            0.30 * kill_chain_score
            + 0.25 * evidence_score
            + 0.20 * report_score
            + 0.15 * rem_score
            + 0.10 * efficiency_score
        )
        return round(min(max(score, 0.0), 1.0), 3)
