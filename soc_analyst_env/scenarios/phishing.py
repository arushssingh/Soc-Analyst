"""Phishing triage scenarios for Task 1 (Easy).

Each scenario presents email security alerts that the agent must investigate
and classify as phishing or legitimate.
"""

try:
    from ..models import Alert, EmailData, LogEntry, Scenario, ThreatIntelEntry
except ImportError:
    from models import Alert, EmailData, LogEntry, Scenario, ThreatIntelEntry


def _scenario_ceo_fraud() -> Scenario:
    """Business Email Compromise: CEO impersonation with typosquatted domain."""
    return Scenario(
        scenario_id="phish-001-ceo-fraud",
        task_type="phishing_triage",
        alerts=[
            Alert(
                alert_id="ALERT-2024-0101",
                timestamp="2024-03-15T09:23:00Z",
                source="email_gateway",
                title="Suspicious email - possible CEO impersonation",
                severity="high",
                description=(
                    "Email flagged by anti-spoofing filter. Sender domain "
                    "closely resembles internal domain. Contains urgent "
                    "wire transfer request."
                ),
                indicators={
                    "from_domain": "acm3corp.com",
                    "internal_domain": "acmecorp.com",
                    "email_id": "EMAIL-001",
                },
            ),
        ],
        emails=[
            EmailData(
                email_id="EMAIL-001",
                from_address="john.carter@acm3corp.com",
                to_address="lisa.chen@acmecorp.com",
                subject="URGENT: Wire Transfer Needed Today",
                body=(
                    "Lisa,\n\n"
                    "I need you to process an urgent wire transfer of $47,500 "
                    "to vendor account ending in 8834. This is time-sensitive "
                    "and must go out before 3pm today. I'm in meetings all day "
                    "so please handle this directly.\n\n"
                    "Do not discuss with others - this is confidential M&A "
                    "related.\n\n"
                    "Thanks,\nJohn Carter\nCEO, Acme Corp"
                ),
                headers={
                    "From": "john.carter@acm3corp.com",
                    "Reply-To": "john.carter@acm3corp.com",
                    "Return-Path": "bounce@acm3corp.com",
                    "Received": (
                        "from mail-out.acm3corp.com (185.234.72.11) "
                        "by mx.acmecorp.com"
                    ),
                    "SPF": "pass (domain acm3corp.com designates 185.234.72.11)",
                    "DKIM": "none",
                    "DMARC": "none (no DMARC record for acm3corp.com)",
                    "X-Mailer": "Microsoft Outlook 16.0",
                },
                urls=[],
                attachments=[],
            ),
        ],
        log_database={
            "email_gateway": [
                LogEntry(
                    timestamp="2024-03-15T09:22:58Z",
                    source="email_gateway",
                    message=(
                        "Inbound email from acm3corp.com to lisa.chen@acmecorp.com. "
                        "Anti-spoofing score: 78/100. Domain age: 3 days."
                    ),
                    source_ip="185.234.72.11",
                    raw={"domain_age_days": 3, "spoofing_score": 78},
                ),
                LogEntry(
                    timestamp="2024-03-15T09:23:00Z",
                    source="email_gateway",
                    message="Alert generated: CEO impersonation pattern detected.",
                    source_ip="185.234.72.11",
                ),
            ],
            "auth_logs": [
                LogEntry(
                    timestamp="2024-03-15T08:05:00Z",
                    source="auth_logs",
                    message="john.carter@acmecorp.com logged in from 10.0.1.50",
                    source_ip="10.0.1.50",
                    raw={"user": "john.carter", "auth_method": "SSO"},
                ),
            ],
            "dns_logs": [
                LogEntry(
                    timestamp="2024-03-15T09:22:55Z",
                    source="dns_logs",
                    message="DNS query for acm3corp.com resolved to 185.234.72.11",
                    raw={"query": "acm3corp.com", "answer": "185.234.72.11"},
                ),
            ],
        },
        threat_intel_database=[
            ThreatIntelEntry(
                indicator="acm3corp.com",
                indicator_type="domain",
                threat_type="typosquatting",
                confidence=0.92,
                description="Recently registered lookalike domain for acmecorp.com",
                tags=["BEC", "CEO-fraud", "typosquatting"],
            ),
            ThreatIntelEntry(
                indicator="185.234.72.11",
                indicator_type="ip",
                threat_type="phishing_infrastructure",
                confidence=0.85,
                description="IP associated with BEC campaigns since 2024-03",
                tags=["BEC", "phishing"],
            ),
        ],
        url_reputation={},
        ground_truth={
            "classifications": {"ALERT-2024-0101": "true_positive"},
            "key_indicators": [
                "acm3corp.com",
                "185.234.72.11",
                "domain_age_3_days",
                "no_dkim",
                "no_dmarc",
                "urgency_pressure",
                "secrecy_request",
            ],
            "correct_remediations": ["quarantine_email", "block_domain"],
            "email_verdicts": {"EMAIL-001": "phishing"},
        },
    )


def _scenario_credential_harvest() -> Scenario:
    """Credential phishing with fake login page."""
    return Scenario(
        scenario_id="phish-002-credential-harvest",
        task_type="phishing_triage",
        alerts=[
            Alert(
                alert_id="ALERT-2024-0102",
                timestamp="2024-03-16T14:10:00Z",
                source="email_gateway",
                title="Suspicious URL in email - possible credential phishing",
                severity="medium",
                description=(
                    "Email contains URL with login page redirect. "
                    "URL does not match claimed sender organization."
                ),
                indicators={
                    "suspicious_url": "https://0365-login.secureauth-verify.xyz/signin",
                    "email_id": "EMAIL-002",
                },
            ),
        ],
        emails=[
            EmailData(
                email_id="EMAIL-002",
                from_address="noreply@microsoft-alerts.xyz",
                to_address="all-staff@acmecorp.com",
                subject="Action Required: Your password expires in 24 hours",
                body=(
                    "Dear User,\n\n"
                    "Your Microsoft 365 password will expire in 24 hours. "
                    "Please click the link below to update your credentials "
                    "and avoid losing access to your email and files.\n\n"
                    "Update Password Now:\n"
                    "https://0365-login.secureauth-verify.xyz/signin\n\n"
                    "If you do not update within 24 hours, your account "
                    "will be temporarily locked.\n\n"
                    "Microsoft 365 Security Team"
                ),
                headers={
                    "From": "noreply@microsoft-alerts.xyz",
                    "Reply-To": "support@microsoft-alerts.xyz",
                    "Return-Path": "bounce@microsoft-alerts.xyz",
                    "Received": (
                        "from mail.microsoft-alerts.xyz (91.203.44.18) "
                        "by mx.acmecorp.com"
                    ),
                    "SPF": "pass (domain microsoft-alerts.xyz designates 91.203.44.18)",
                    "DKIM": "pass",
                    "DMARC": "none",
                    "X-Mailer": "PHPMailer 6.8.1",
                },
                urls=["https://0365-login.secureauth-verify.xyz/signin"],
                attachments=[],
            ),
        ],
        log_database={
            "email_gateway": [
                LogEntry(
                    timestamp="2024-03-16T14:09:55Z",
                    source="email_gateway",
                    message=(
                        "Inbound email from microsoft-alerts.xyz to distribution "
                        "list all-staff. URL inspection flagged suspicious redirect."
                    ),
                    source_ip="91.203.44.18",
                    raw={"recipients_count": 250, "url_category": "uncategorized"},
                ),
            ],
            "proxy_logs": [
                LogEntry(
                    timestamp="2024-03-16T14:22:00Z",
                    source="proxy_logs",
                    message=(
                        "User mark.davis accessed "
                        "https://0365-login.secureauth-verify.xyz/signin "
                        "- page contains login form"
                    ),
                    source_ip="10.0.2.33",
                    dest_ip="91.203.44.18",
                    raw={"user": "mark.davis", "page_title": "Microsoft Sign In"},
                ),
                LogEntry(
                    timestamp="2024-03-16T14:22:30Z",
                    source="proxy_logs",
                    message=(
                        "POST request to "
                        "https://0365-login.secureauth-verify.xyz/api/collect "
                        "from mark.davis workstation"
                    ),
                    source_ip="10.0.2.33",
                    dest_ip="91.203.44.18",
                    raw={"user": "mark.davis", "method": "POST"},
                ),
            ],
            "auth_logs": [
                LogEntry(
                    timestamp="2024-03-16T14:35:00Z",
                    source="auth_logs",
                    message=(
                        "Successful login for mark.davis from IP 103.45.67.89 "
                        "(unusual location: Eastern Europe)"
                    ),
                    source_ip="103.45.67.89",
                    raw={
                        "user": "mark.davis",
                        "geo": "Romania",
                        "login_type": "OAuth2",
                    },
                ),
            ],
        },
        threat_intel_database=[
            ThreatIntelEntry(
                indicator="microsoft-alerts.xyz",
                indicator_type="domain",
                threat_type="credential_phishing",
                confidence=0.95,
                description="Known Microsoft impersonation domain",
                tags=["credential-phishing", "Microsoft-impersonation"],
            ),
            ThreatIntelEntry(
                indicator="0365-login.secureauth-verify.xyz",
                indicator_type="domain",
                threat_type="credential_phishing",
                confidence=0.97,
                description="Active credential harvesting domain mimicking O365 login",
                tags=["credential-phishing", "O365"],
            ),
        ],
        url_reputation={
            "https://0365-login.secureauth-verify.xyz/signin": {
                "category": "phishing",
                "risk_score": 95,
                "first_seen": "2024-03-14",
                "ssl_issuer": "Let's Encrypt",
                "registrar": "Namecheap",
                "domain_age_days": 5,
            },
        },
        ground_truth={
            "classifications": {"ALERT-2024-0102": "true_positive"},
            "key_indicators": [
                "microsoft-alerts.xyz",
                "0365-login.secureauth-verify.xyz",
                "91.203.44.18",
                "PHPMailer",
                "credential_harvested",
                "unusual_login_location",
            ],
            "correct_remediations": [
                "quarantine_email",
                "block_domain",
                "disable_account",
            ],
            "email_verdicts": {"EMAIL-002": "phishing"},
            "compromised_users": ["mark.davis"],
        },
    )


def _scenario_legit_newsletter() -> Scenario:
    """False positive: legitimate marketing newsletter."""
    return Scenario(
        scenario_id="phish-003-legit-newsletter",
        task_type="phishing_triage",
        alerts=[
            Alert(
                alert_id="ALERT-2024-0103",
                timestamp="2024-03-17T10:05:00Z",
                source="email_gateway",
                title="Bulk email with tracking links detected",
                severity="low",
                description=(
                    "Email contains multiple tracking URLs and embedded images. "
                    "Flagged for review due to external sender with tracking pixels."
                ),
                indicators={
                    "from_domain": "mail.hubspot.com",
                    "tracking_urls": 4,
                    "email_id": "EMAIL-003",
                },
            ),
        ],
        emails=[
            EmailData(
                email_id="EMAIL-003",
                from_address="newsletter@salesforce-events.com",
                to_address="lisa.chen@acmecorp.com",
                subject="Dreamforce 2024: Early Bird Registration Now Open",
                body=(
                    "Hi Lisa,\n\n"
                    "Dreamforce 2024 is coming! As a valued Salesforce customer, "
                    "you're invited to register early for our annual conference.\n\n"
                    "Dates: September 17-19, 2024\n"
                    "Location: Moscone Center, San Francisco\n\n"
                    "Register now: https://www.salesforce.com/dreamforce/\n\n"
                    "View the full agenda: https://www.salesforce.com/dreamforce/agenda/\n\n"
                    "Best regards,\n"
                    "Salesforce Events Team\n\n"
                    "Unsubscribe: https://mail.hubspot.com/unsubscribe/abc123"
                ),
                headers={
                    "From": "newsletter@salesforce-events.com",
                    "Reply-To": "events@salesforce.com",
                    "Return-Path": "bounce-123@mail.hubspot.com",
                    "Received": (
                        "from o1.email.hubspot.com (192.254.113.10) "
                        "by mx.acmecorp.com"
                    ),
                    "SPF": "pass",
                    "DKIM": "pass (signed by hubspot.com)",
                    "DMARC": "pass",
                    "List-Unsubscribe": "<https://mail.hubspot.com/unsubscribe/abc123>",
                    "X-Mailer": "HubSpot",
                },
                urls=[
                    "https://www.salesforce.com/dreamforce/",
                    "https://www.salesforce.com/dreamforce/agenda/",
                    "https://mail.hubspot.com/unsubscribe/abc123",
                ],
                attachments=[],
            ),
        ],
        log_database={
            "email_gateway": [
                LogEntry(
                    timestamp="2024-03-17T10:04:58Z",
                    source="email_gateway",
                    message=(
                        "Inbound email from hubspot.com relay. DKIM valid. "
                        "Bulk mail headers present. Known marketing platform."
                    ),
                    source_ip="192.254.113.10",
                    raw={
                        "dkim_valid": True,
                        "spf_pass": True,
                        "dmarc_pass": True,
                        "bulk_score": 65,
                    },
                ),
            ],
        },
        threat_intel_database=[],
        url_reputation={
            "https://www.salesforce.com/dreamforce/": {
                "category": "business",
                "risk_score": 0,
                "domain_age_days": 9125,
                "ssl_issuer": "DigiCert",
            },
        },
        ground_truth={
            "classifications": {"ALERT-2024-0103": "false_positive"},
            "key_indicators": [
                "valid_dkim",
                "valid_spf",
                "valid_dmarc",
                "known_marketing_platform",
                "legitimate_urls",
            ],
            "correct_remediations": ["no_action"],
            "email_verdicts": {"EMAIL-003": "legitimate"},
        },
    )


PHISHING_SCENARIOS = [
    _scenario_ceo_fraud(),
    _scenario_credential_harvest(),
    _scenario_legit_newsletter(),
]
