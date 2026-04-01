"""APT kill chain detection scenarios for Task 3 (Hard).

Each scenario presents a multi-stage advanced persistent threat that the agent
must trace across multiple log sources and time windows, identifying each
phase of the kill chain.
"""

try:
    from ..models import Alert, EmailData, LogEntry, Scenario, ThreatIntelEntry
except ImportError:
    from models import Alert, EmailData, LogEntry, Scenario, ThreatIntelEntry


def _scenario_full_kill_chain() -> Scenario:
    """Full APT kill chain: spearphishing -> execution -> C2 -> lateral movement
    -> privilege escalation -> data exfiltration via DNS tunneling."""
    alerts = [
        Alert(
            alert_id="ALERT-2024-0301",
            timestamp="2024-05-10T08:30:00Z",
            source="email_gateway",
            title="Targeted email with weaponized attachment to executive",
            severity="high",
            description=(
                "Email to CFO contains macro-enabled document. Sender domain "
                "is newly registered and mimics a known law firm."
            ),
            indicators={
                "email_id": "EMAIL-APT-001",
                "from_domain": "baker-mckenzi3.com",
                "attachment": "NDA_Draft_Confidential.docm",
                "attachment_hash": "f1e2d3c4b5a6978807060504030201009f8e7d6c",
            },
        ),
        Alert(
            alert_id="ALERT-2024-0302",
            timestamp="2024-05-10T14:20:00Z",
            source="ids_ips",
            title="DNS tunneling activity detected",
            severity="critical",
            description=(
                "Anomalous DNS query patterns from SRV-FILESTORE. "
                "High-frequency TXT queries to subdomain of t1cketsystem.net "
                "with encoded payloads. Pattern consistent with DNS exfiltration."
            ),
            indicators={
                "source_ip": "10.0.6.50",
                "dns_domain": "t1cketsystem.net",
                "query_frequency": "120/min",
            },
        ),
    ]

    emails = [
        EmailData(
            email_id="EMAIL-APT-001",
            from_address="m.harris@baker-mckenzi3.com",
            to_address="robert.chen@acmecorp.com",
            subject="RE: Confidential - Merger NDA Draft for Review",
            body=(
                "Robert,\n\n"
                "Please find attached the revised NDA draft as discussed "
                "in our call last week. The board requires your sign-off "
                "by end of week.\n\n"
                "Please enable editing to view tracked changes.\n\n"
                "Best regards,\n"
                "Mark Harris\n"
                "Partner, Baker McKenzie\n"
                "+1 (212) 555-0142"
            ),
            headers={
                "From": "m.harris@baker-mckenzi3.com",
                "Reply-To": "m.harris@baker-mckenzi3.com",
                "Received": (
                    "from mail.baker-mckenzi3.com (37.120.198.44) "
                    "by mx.acmecorp.com"
                ),
                "SPF": "pass",
                "DKIM": "none",
                "DMARC": "none (no record for baker-mckenzi3.com)",
                "X-Mailer": "Thunderbird 115.8",
            },
            urls=[],
            attachments=[
                {
                    "filename": "NDA_Draft_Confidential.docm",
                    "size": "245KB",
                    "hash": "f1e2d3c4b5a6978807060504030201009f8e7d6c",
                    "content_type": "application/vnd.ms-word.document.macroEnabled.12",
                },
            ],
        ),
    ]

    log_database = {
        # Phase 1: Initial Access (spearphishing)
        "email_gateway": [
            LogEntry(
                timestamp="2024-05-10T08:28:00Z",
                source="email_gateway",
                message=(
                    "Delivered email to robert.chen@acmecorp.com with "
                    "macro-enabled attachment from baker-mckenzi3.com"
                ),
                source_ip="37.120.198.44",
                raw={
                    "from": "m.harris@baker-mckenzi3.com",
                    "attachment": "NDA_Draft_Confidential.docm",
                    "domain_age_days": 7,
                },
            ),
        ],
        # Phase 2: Execution
        "endpoint": [
            LogEntry(
                timestamp="2024-05-10T09:15:00Z",
                source="endpoint",
                message=(
                    "EXEC-PC01: WINWORD.EXE opened NDA_Draft_Confidential.docm. "
                    "Macro execution detected."
                ),
                source_ip="10.0.1.100",
                raw={
                    "hostname": "EXEC-PC01",
                    "user": "robert.chen",
                    "process": "WINWORD.EXE",
                    "technique": "T1204.002",
                },
            ),
            LogEntry(
                timestamp="2024-05-10T09:15:30Z",
                source="endpoint",
                message=(
                    "EXEC-PC01: WINWORD.EXE spawned cmd.exe -> powershell.exe. "
                    "Downloaded payload from hxxps://cdn-resources-lib.com/update.exe"
                ),
                source_ip="10.0.1.100",
                raw={
                    "hostname": "EXEC-PC01",
                    "chain": "WINWORD->cmd->powershell",
                    "download_url": "https://cdn-resources-lib.com/update.exe",
                    "technique": "T1059.001",
                },
            ),
            # Phase 3: Persistence + C2
            LogEntry(
                timestamp="2024-05-10T09:16:00Z",
                source="endpoint",
                message=(
                    "EXEC-PC01: Registry run key created: "
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityUpdate"
                ),
                source_ip="10.0.1.100",
                raw={
                    "hostname": "EXEC-PC01",
                    "technique": "T1547.001",
                    "registry_key": "SecurityUpdate",
                    "value": "C:\\Users\\robert.chen\\AppData\\Roaming\\update.exe",
                },
            ),
            # Phase 5: Lateral Movement
            LogEntry(
                timestamp="2024-05-10T10:45:00Z",
                source="endpoint",
                message=(
                    "EXEC-PC01: Mimikatz-like memory access detected. "
                    "Process update.exe accessed lsass.exe memory."
                ),
                source_ip="10.0.1.100",
                raw={
                    "hostname": "EXEC-PC01",
                    "technique": "T1003.001",
                    "source_process": "update.exe",
                    "target_process": "lsass.exe",
                },
            ),
            LogEntry(
                timestamp="2024-05-10T11:00:00Z",
                source="endpoint",
                message=(
                    "SRV-FILESTORE: Remote service installation via SMB "
                    "from EXEC-PC01. Service 'WinMgmtSvc' created."
                ),
                source_ip="10.0.1.100",
                dest_ip="10.0.6.50",
                raw={
                    "hostname": "SRV-FILESTORE",
                    "technique": "T1021.002",
                    "service_name": "WinMgmtSvc",
                    "service_binary": "C:\\Windows\\Temp\\wmisvc.exe",
                },
            ),
            # Phase 6: Collection on file server
            LogEntry(
                timestamp="2024-05-10T12:00:00Z",
                source="endpoint",
                message=(
                    "SRV-FILESTORE: Bulk file access detected. wmisvc.exe "
                    "reading files from D:\\Finance\\Confidential\\ and "
                    "D:\\Legal\\Mergers\\"
                ),
                source_ip="10.0.6.50",
                raw={
                    "hostname": "SRV-FILESTORE",
                    "technique": "T1005",
                    "files_accessed": 347,
                    "directories": [
                        "D:\\Finance\\Confidential\\",
                        "D:\\Legal\\Mergers\\",
                    ],
                },
            ),
            LogEntry(
                timestamp="2024-05-10T13:00:00Z",
                source="endpoint",
                message=(
                    "SRV-FILESTORE: Archive created C:\\Windows\\Temp\\logs.zip "
                    "(compressed 280MB of collected files)"
                ),
                source_ip="10.0.6.50",
                raw={
                    "hostname": "SRV-FILESTORE",
                    "technique": "T1560.001",
                    "archive_size_mb": 280,
                },
            ),
        ],
        # Phase 4: C2 Communication
        "firewall": [
            LogEntry(
                timestamp="2024-05-10T09:16:30Z",
                source="firewall",
                message="ALLOW HTTPS 10.0.1.100 -> 185.220.101.34:443",
                source_ip="10.0.1.100",
                dest_ip="185.220.101.34",
                raw={"action": "allow", "protocol": "TCP", "dest_port": 443},
            ),
            LogEntry(
                timestamp="2024-05-10T11:00:30Z",
                source="firewall",
                message="ALLOW SMB 10.0.1.100 -> 10.0.6.50:445",
                source_ip="10.0.1.100",
                dest_ip="10.0.6.50",
                raw={"action": "allow", "protocol": "TCP", "dest_port": 445},
            ),
        ],
        "ids_ips": [
            LogEntry(
                timestamp="2024-05-10T14:20:00Z",
                source="ids_ips",
                message=(
                    "ALERT: DNS Tunneling detected - SRV-FILESTORE "
                    "high-frequency TXT queries to *.t1cketsystem.net"
                ),
                source_ip="10.0.6.50",
                raw={
                    "sid": 2035789,
                    "category": "exfiltration",
                    "query_count": 7200,
                    "time_window": "60min",
                },
            ),
        ],
        # Phase 7: Exfiltration via DNS
        "dns_logs": [
            LogEntry(
                timestamp="2024-05-10T09:16:25Z",
                source="dns_logs",
                message="EXEC-PC01 queried cdn-resources-lib.com -> 185.220.101.34",
                source_ip="10.0.1.100",
                raw={
                    "query": "cdn-resources-lib.com",
                    "answer": "185.220.101.34",
                },
            ),
            LogEntry(
                timestamp="2024-05-10T13:30:00Z",
                source="dns_logs",
                message=(
                    "SRV-FILESTORE: Anomalous DNS - 120 TXT queries/min to "
                    "*.t1cketsystem.net with Base64-encoded subdomain labels"
                ),
                source_ip="10.0.6.50",
                raw={
                    "query_pattern": "*.t1cketsystem.net",
                    "query_type": "TXT",
                    "rate_per_min": 120,
                    "subdomain_entropy": 4.8,
                },
            ),
            LogEntry(
                timestamp="2024-05-10T14:15:00Z",
                source="dns_logs",
                message=(
                    "SRV-FILESTORE: Continued DNS exfiltration to "
                    "t1cketsystem.net. Estimated 280MB transferred via DNS."
                ),
                source_ip="10.0.6.50",
                raw={
                    "estimated_bytes": 293601280,
                    "total_queries": 43200,
                    "duration_hours": 1.0,
                },
            ),
        ],
        # Authentication trail
        "auth_logs": [
            LogEntry(
                timestamp="2024-05-10T09:00:00Z",
                source="auth_logs",
                message="robert.chen logged into EXEC-PC01 via SSO",
                source_ip="10.0.1.100",
                raw={"user": "robert.chen", "title": "CFO"},
            ),
            LogEntry(
                timestamp="2024-05-10T10:50:00Z",
                source="auth_logs",
                message=(
                    "admin.backup service account authenticated to "
                    "SRV-FILESTORE from EXEC-PC01 (pass-the-hash detected)"
                ),
                source_ip="10.0.1.100",
                dest_ip="10.0.6.50",
                raw={
                    "user": "admin.backup",
                    "auth_type": "NTLM",
                    "technique": "T1550.002",
                    "logon_type": 3,
                },
            ),
        ],
        "proxy_logs": [
            LogEntry(
                timestamp="2024-05-10T09:15:35Z",
                source="proxy_logs",
                message=(
                    "EXEC-PC01: HTTPS download from "
                    "cdn-resources-lib.com/update.exe (185.220.101.34)"
                ),
                source_ip="10.0.1.100",
                dest_ip="185.220.101.34",
                raw={
                    "url": "https://cdn-resources-lib.com/update.exe",
                    "user_agent": "PowerShell/7.4",
                    "bytes": 524288,
                },
            ),
        ],
    }

    threat_intel = [
        ThreatIntelEntry(
            indicator="baker-mckenzi3.com",
            indicator_type="domain",
            threat_type="typosquatting",
            confidence=0.93,
            description="Typosquat of Baker McKenzie law firm domain",
            tags=["APT", "spearphishing", "typosquatting"],
        ),
        ThreatIntelEntry(
            indicator="37.120.198.44",
            indicator_type="ip",
            threat_type="phishing_infrastructure",
            confidence=0.88,
            description="Mail server for APT spearphishing campaigns",
            tags=["APT", "phishing-infra"],
        ),
        ThreatIntelEntry(
            indicator="185.220.101.34",
            indicator_type="ip",
            threat_type="c2_server",
            confidence=0.96,
            description="C2 infrastructure linked to APT group 'SilkTempest'",
            tags=["APT", "SilkTempest", "C2"],
        ),
        ThreatIntelEntry(
            indicator="cdn-resources-lib.com",
            indicator_type="domain",
            threat_type="malware_distribution",
            confidence=0.94,
            description="Payload hosting domain used by SilkTempest",
            tags=["APT", "SilkTempest", "payload-delivery"],
        ),
        ThreatIntelEntry(
            indicator="t1cketsystem.net",
            indicator_type="domain",
            threat_type="dns_tunneling",
            confidence=0.97,
            description="DNS exfiltration infrastructure for SilkTempest APT",
            tags=["APT", "SilkTempest", "DNS-tunnel", "exfiltration"],
        ),
        ThreatIntelEntry(
            indicator="f1e2d3c4b5a6978807060504030201009f8e7d6c",
            indicator_type="hash",
            threat_type="apt_dropper",
            confidence=0.91,
            description="SilkTempest macro dropper variant",
            tags=["APT", "SilkTempest", "dropper"],
        ),
    ]

    file_hashes = {
        "f1e2d3c4b5a6978807060504030201009f8e7d6c": {
            "filename": "NDA_Draft_Confidential.docm",
            "type": "Office Macro Document",
            "malware_family": "SilkTempest Dropper",
            "first_seen": "2024-05-08",
            "detection_rate": "12/72",
            "tags": ["APT", "SilkTempest", "macro"],
        },
    }

    endpoint_data = {
        "EXEC-PC01": {
            "hostname": "EXEC-PC01",
            "ip": "10.0.1.100",
            "os": "Windows 11 Enterprise",
            "user": "robert.chen",
            "department": "Executive / Finance",
            "role": "CFO Workstation",
        },
        "SRV-FILESTORE": {
            "hostname": "SRV-FILESTORE",
            "ip": "10.0.6.50",
            "os": "Windows Server 2022",
            "role": "File Server",
            "shares": [
                "D:\\Finance\\", "D:\\Legal\\", "D:\\HR\\", "D:\\Engineering\\",
            ],
        },
    }

    ground_truth = {
        "classifications": {
            "ALERT-2024-0301": "true_positive",
            "ALERT-2024-0302": "true_positive",
        },
        "kill_chain": {
            "initial_access": {
                "technique": "T1566.001 - Spearphishing Attachment",
                "evidence": [
                    "baker-mckenzi3.com typosquat",
                    "macro-enabled document",
                ],
                "host": "EXEC-PC01",
            },
            "execution": {
                "technique": "T1204.002 - User Execution: Malicious File",
                "evidence": ["WINWORD macro -> cmd -> powershell chain"],
                "host": "EXEC-PC01",
            },
            "persistence": {
                "technique": "T1547.001 - Registry Run Key",
                "evidence": ["SecurityUpdate registry key"],
                "host": "EXEC-PC01",
            },
            "command_and_control": {
                "technique": "T1071.001 - HTTPS C2",
                "evidence": [
                    "185.220.101.34 C2 server",
                    "cdn-resources-lib.com payload domain",
                ],
                "host": "EXEC-PC01",
            },
            "privilege_escalation": {
                "technique": "T1003.001 - LSASS Memory Credential Dump",
                "evidence": [
                    "Mimikatz-like lsass access",
                    "admin.backup hash extracted",
                ],
                "host": "EXEC-PC01",
            },
            "lateral_movement": {
                "technique": "T1021.002 - SMB/Windows Admin Shares",
                "evidence": [
                    "Pass-the-hash to SRV-FILESTORE",
                    "WinMgmtSvc service installed remotely",
                ],
                "host": "SRV-FILESTORE",
            },
            "collection": {
                "technique": "T1005 - Data from Local System",
                "evidence": [
                    "347 files accessed from Finance and Legal shares",
                    "logs.zip archive created",
                ],
                "host": "SRV-FILESTORE",
            },
            "exfiltration": {
                "technique": "T1048.003 - DNS Tunneling Exfiltration",
                "evidence": [
                    "t1cketsystem.net DNS tunnel",
                    "280MB exfiltrated via TXT queries",
                ],
                "host": "SRV-FILESTORE",
            },
        },
        "affected_hosts": ["EXEC-PC01", "SRV-FILESTORE"],
        "compromised_accounts": ["robert.chen", "admin.backup"],
        "iocs": [
            "baker-mckenzi3.com",
            "37.120.198.44",
            "185.220.101.34",
            "cdn-resources-lib.com",
            "t1cketsystem.net",
            "f1e2d3c4b5a6978807060504030201009f8e7d6c",
        ],
        "correct_remediations": [
            "quarantine_host",  # EXEC-PC01
            "quarantine_host",  # SRV-FILESTORE
            "block_ip",         # 185.220.101.34
            "block_domain",     # cdn-resources-lib.com
            "block_domain",     # t1cketsystem.net
            "block_domain",     # baker-mckenzi3.com
            "disable_account",  # admin.backup
            "escalate_to_tier2",
        ],
        "relevant_log_sources": [
            "email_gateway", "endpoint", "firewall", "ids_ips",
            "dns_logs", "auth_logs", "proxy_logs",
        ],
        "apt_group": "SilkTempest",
    }

    return Scenario(
        scenario_id="apt-001-silk-tempest",
        task_type="apt_detection",
        alerts=alerts,
        emails=emails,
        log_database=log_database,
        threat_intel_database=threat_intel,
        file_hashes=file_hashes,
        endpoint_data=endpoint_data,
        ground_truth=ground_truth,
    )


def _scenario_supply_chain() -> Scenario:
    """Supply chain attack: compromised software update with backdoor."""
    alerts = [
        Alert(
            alert_id="ALERT-2024-0303",
            timestamp="2024-05-15T06:00:00Z",
            source="ids_ips",
            title="Unusual outbound HTTPS traffic pattern from multiple hosts",
            severity="high",
            description=(
                "IDS flagged periodic HTTPS beaconing from 5 internal hosts to "
                "203.0.113.77. Fixed 60-second intervals with jitter. "
                "Pattern matches known C2 profiles."
            ),
            indicators={
                "dest_ip": "203.0.113.77",
                "affected_hosts": [
                    "10.0.2.10", "10.0.2.11", "10.0.3.15",
                    "10.0.4.20", "10.0.5.30",
                ],
                "beacon_interval": "60s",
            },
        ),
        Alert(
            alert_id="ALERT-2024-0304",
            timestamp="2024-05-15T08:00:00Z",
            source="endpoint",
            title="Data staging activity on SRV-DB01",
            severity="critical",
            description=(
                "SRV-DB01: Process 'InventoryAgent.exe' executing database "
                "export commands. Unusual behavior for this application. "
                "Large data staging to temp directory."
            ),
            indicators={
                "hostname": "SRV-DB01",
                "process": "InventoryAgent.exe",
                "data_size_mb": 450,
            },
        ),
    ]

    log_database = {
        "endpoint": [
            # Software update compromised
            LogEntry(
                timestamp="2024-05-14T22:00:00Z",
                source="endpoint",
                message=(
                    "WKSTN-DEV05: Auto-update for InventoryAgent v3.2.1 -> "
                    "v3.2.2 from vendor update server. Update hash: "
                    "aabb1122334455667788990011223344aabbccdd"
                ),
                source_ip="10.0.2.10",
                raw={
                    "hostname": "WKSTN-DEV05",
                    "software": "InventoryAgent",
                    "old_version": "3.2.1",
                    "new_version": "3.2.2",
                    "update_source": "updates.inventorysoft.com",
                },
            ),
            LogEntry(
                timestamp="2024-05-14T22:15:00Z",
                source="endpoint",
                message=(
                    "Multiple hosts updated InventoryAgent to v3.2.2. "
                    "5 systems affected."
                ),
                raw={
                    "affected_hosts": [
                        "WKSTN-DEV05", "WKSTN-DEV06", "WKSTN-QA01",
                        "SRV-APP02", "SRV-DB01",
                    ],
                },
            ),
            # Backdoor activation
            LogEntry(
                timestamp="2024-05-15T02:00:00Z",
                source="endpoint",
                message=(
                    "WKSTN-DEV05: InventoryAgent.exe spawned cmd.exe with "
                    "network reconnaissance commands (whoami, ipconfig, "
                    "net group 'domain admins')"
                ),
                source_ip="10.0.2.10",
                raw={
                    "hostname": "WKSTN-DEV05",
                    "technique": "T1059.003",
                    "commands": [
                        "whoami /all", "ipconfig /all",
                        "net group 'domain admins' /domain",
                    ],
                },
            ),
            # Lateral movement to DB server
            LogEntry(
                timestamp="2024-05-15T05:30:00Z",
                source="endpoint",
                message=(
                    "SRV-DB01: InventoryAgent.exe running sqlcmd to export "
                    "customer database to C:\\Temp\\export.bak"
                ),
                source_ip="10.0.5.30",
                raw={
                    "hostname": "SRV-DB01",
                    "technique": "T1005",
                    "command": "sqlcmd -Q 'BACKUP DATABASE CustomerDB TO DISK=...'",
                    "output_size_mb": 450,
                },
            ),
            # Exfiltration staging
            LogEntry(
                timestamp="2024-05-15T07:00:00Z",
                source="endpoint",
                message=(
                    "SRV-DB01: InventoryAgent.exe compressing export.bak "
                    "and uploading via HTTPS to cloud-backup-svc.net"
                ),
                source_ip="10.0.5.30",
                raw={
                    "hostname": "SRV-DB01",
                    "technique": "T1567.002",
                    "dest": "cloud-backup-svc.net",
                },
            ),
        ],
        "firewall": [
            LogEntry(
                timestamp="2024-05-15T02:00:05Z",
                source="firewall",
                message="ALLOW HTTPS 10.0.2.10 -> 203.0.113.77:443 (beacon)",
                source_ip="10.0.2.10",
                dest_ip="203.0.113.77",
                raw={"action": "allow", "bytes_out": 256, "bytes_in": 512},
            ),
            LogEntry(
                timestamp="2024-05-15T07:00:30Z",
                source="firewall",
                message=(
                    "ALLOW HTTPS 10.0.5.30 -> cloud-backup-svc.net "
                    "(large upload: 450MB)"
                ),
                source_ip="10.0.5.30",
                dest_ip="198.51.100.99",
                raw={
                    "action": "allow",
                    "bytes_out": 471859200,
                    "dest_hostname": "cloud-backup-svc.net",
                },
            ),
        ],
        "dns_logs": [
            LogEntry(
                timestamp="2024-05-14T22:00:05Z",
                source="dns_logs",
                message=(
                    "WKSTN-DEV05 queried updates.inventorysoft.com -> "
                    "203.0.113.55 (vendor update server)"
                ),
                source_ip="10.0.2.10",
                raw={
                    "query": "updates.inventorysoft.com",
                    "answer": "203.0.113.55",
                },
            ),
            LogEntry(
                timestamp="2024-05-15T07:00:00Z",
                source="dns_logs",
                message="SRV-DB01 queried cloud-backup-svc.net -> 198.51.100.99",
                source_ip="10.0.5.30",
                raw={
                    "query": "cloud-backup-svc.net",
                    "answer": "198.51.100.99",
                },
            ),
        ],
        "auth_logs": [
            LogEntry(
                timestamp="2024-05-15T05:25:00Z",
                source="auth_logs",
                message=(
                    "Service account svc_inventory authenticated to SRV-DB01 "
                    "with SQL SA privileges. Source: WKSTN-DEV05."
                ),
                source_ip="10.0.2.10",
                dest_ip="10.0.5.30",
                raw={
                    "user": "svc_inventory",
                    "auth_type": "SQL",
                    "privileges": "SA",
                },
            ),
        ],
        "ids_ips": [
            LogEntry(
                timestamp="2024-05-15T06:00:00Z",
                source="ids_ips",
                message=(
                    "ALERT: C2 Beacon pattern - 5 internal hosts beaconing "
                    "to 203.0.113.77 at 60s intervals"
                ),
                source_ip="10.0.2.10",
                dest_ip="203.0.113.77",
                raw={
                    "sid": 2040123,
                    "category": "c2",
                    "hosts_affected": 5,
                },
            ),
        ],
        "proxy_logs": [],
    }

    threat_intel = [
        ThreatIntelEntry(
            indicator="203.0.113.77",
            indicator_type="ip",
            threat_type="c2_server",
            confidence=0.89,
            description="C2 server associated with supply chain attacks",
            tags=["supply-chain", "C2"],
        ),
        ThreatIntelEntry(
            indicator="cloud-backup-svc.net",
            indicator_type="domain",
            threat_type="exfiltration_endpoint",
            confidence=0.85,
            description="Data exfiltration endpoint masquerading as cloud backup",
            tags=["exfiltration", "supply-chain"],
        ),
        ThreatIntelEntry(
            indicator="aabb1122334455667788990011223344aabbccdd",
            indicator_type="hash",
            threat_type="backdoor",
            confidence=0.92,
            description="Backdoored InventoryAgent v3.2.2 update package",
            tags=["supply-chain", "backdoor"],
        ),
    ]

    file_hashes = {
        "aabb1122334455667788990011223344aabbccdd": {
            "filename": "InventoryAgent_v3.2.2_setup.exe",
            "type": "PE32 Executable (Installer)",
            "malware_family": "Supply Chain Backdoor",
            "first_seen": "2024-05-14",
            "detection_rate": "5/72",
            "tags": ["supply-chain", "backdoor", "trojanized-update"],
            "note": (
                "Legitimate InventoryAgent with embedded backdoor. "
                "Vendor update server was compromised."
            ),
        },
    }

    endpoint_data = {
        "WKSTN-DEV05": {
            "hostname": "WKSTN-DEV05",
            "ip": "10.0.2.10",
            "os": "Windows 11 Pro",
            "user": "dev.martinez",
            "department": "Engineering",
        },
        "SRV-DB01": {
            "hostname": "SRV-DB01",
            "ip": "10.0.5.30",
            "os": "Windows Server 2022",
            "role": "Database Server (SQL Server)",
            "databases": ["CustomerDB", "OrdersDB", "InventoryDB"],
        },
    }

    ground_truth = {
        "classifications": {
            "ALERT-2024-0303": "true_positive",
            "ALERT-2024-0304": "true_positive",
        },
        "kill_chain": {
            "initial_access": {
                "technique": "T1195.002 - Supply Chain: Software Supply Chain",
                "evidence": [
                    "Compromised InventoryAgent v3.2.2 update",
                    "Backdoored installer hash",
                ],
                "host": "Multiple (5 hosts)",
            },
            "execution": {
                "technique": "T1059.003 - Command and Scripting: Windows CMD",
                "evidence": ["InventoryAgent spawned cmd for recon"],
                "host": "WKSTN-DEV05",
            },
            "command_and_control": {
                "technique": "T1071.001 - HTTPS C2 Beacon",
                "evidence": [
                    "203.0.113.77 C2 beacon at 60s intervals",
                    "5 hosts beaconing",
                ],
                "host": "Multiple",
            },
            "collection": {
                "technique": "T1005 - Data from Local System",
                "evidence": [
                    "CustomerDB exported via sqlcmd",
                    "450MB database backup",
                ],
                "host": "SRV-DB01",
            },
            "exfiltration": {
                "technique": "T1567.002 - Exfiltration to Cloud Storage",
                "evidence": [
                    "450MB upload to cloud-backup-svc.net",
                ],
                "host": "SRV-DB01",
            },
        },
        "affected_hosts": [
            "WKSTN-DEV05", "WKSTN-DEV06", "WKSTN-QA01",
            "SRV-APP02", "SRV-DB01",
        ],
        "compromised_accounts": ["svc_inventory"],
        "iocs": [
            "203.0.113.77",
            "cloud-backup-svc.net",
            "aabb1122334455667788990011223344aabbccdd",
        ],
        "correct_remediations": [
            "quarantine_host",   # All 5 affected hosts
            "block_ip",          # 203.0.113.77
            "block_domain",      # cloud-backup-svc.net
            "disable_account",   # svc_inventory
            "escalate_to_tier2",
        ],
        "relevant_log_sources": [
            "endpoint", "firewall", "dns_logs", "ids_ips", "auth_logs",
        ],
    }

    return Scenario(
        scenario_id="apt-002-supply-chain",
        task_type="apt_detection",
        alerts=alerts,
        log_database=log_database,
        threat_intel_database=threat_intel,
        file_hashes=file_hashes,
        endpoint_data=endpoint_data,
        ground_truth=ground_truth,
    )


APT_SCENARIOS = [
    _scenario_full_kill_chain(),
    _scenario_supply_chain(),
]
