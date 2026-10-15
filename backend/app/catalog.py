"""Reference data used to build the simulated environment.

CVE identifiers, products, and CVSS scores are real public data so that the
simulated scan results correlate with real-world threat intelligence (CISA KEV,
news). Everything about *our* environment (hosts, owners, vendors) is fictional.
"""

# Technology stack: product keyword -> (vendor, asset role it lives on)
# Keywords double as the watchlist used to flag relevant threat news.
TECH_STACK = {
    "Windows 11": ("Microsoft", "workstation"),
    "macOS": ("Apple", "workstation"),
    "Chrome": ("Google", "workstation"),
    "Microsoft Office": ("Microsoft", "workstation"),
    "Outlook": ("Microsoft", "workstation"),
    "Windows Server": ("Microsoft", "server"),
    "Exchange Server": ("Microsoft", "server"),
    "SharePoint": ("Microsoft", "server"),
    "Active Directory": ("Microsoft", "server"),
    "Print Spooler": ("Microsoft", "server"),
    "Linux kernel": ("Linux", "server"),
    "OpenSSH": ("OpenBSD", "server"),
    "OpenSSL": ("OpenSSL", "server"),
    "glibc": ("GNU", "server"),
    "Log4j": ("Apache", "server"),
    "Jenkins": ("Jenkins", "server"),
    "Confluence": ("Atlassian", "server"),
    "TeamCity": ("JetBrains", "server"),
    "MOVEit Transfer": ("Progress", "server"),
    "ScreenConnect": ("ConnectWise", "server"),
    "ESXi": ("VMware", "server"),
    "PHP": ("PHP", "server"),
    "Spring Framework": ("VMware", "server"),
    "FortiOS": ("Fortinet", "network"),
    "PAN-OS": ("Palo Alto Networks", "network"),
    "IOS XE": ("Cisco", "network"),
    "NetScaler": ("Citrix", "network"),
    "Ivanti Connect Secure": ("Ivanti", "network"),
    "BIG-IP": ("F5", "network"),
    "Kubernetes": ("CNCF", "cloud"),
    "nginx": ("F5", "cloud"),
    "Node.js": ("OpenJS", "cloud"),
}

# (cve, title, product keyword, cvss)
CVES = [
    ("CVE-2021-44228", "Apache Log4j2 JNDI remote code execution (Log4Shell)", "Log4j", 10.0),
    ("CVE-2023-34362", "MOVEit Transfer SQL injection", "MOVEit Transfer", 9.8),
    ("CVE-2023-4966", "Citrix NetScaler session token leak (Citrix Bleed)", "NetScaler", 9.4),
    ("CVE-2023-3519", "Citrix NetScaler ADC unauthenticated RCE", "NetScaler", 9.8),
    ("CVE-2023-46805", "Ivanti Connect Secure authentication bypass", "Ivanti Connect Secure", 8.2),
    ("CVE-2024-21887", "Ivanti Connect Secure command injection", "Ivanti Connect Secure", 9.1),
    ("CVE-2025-0282", "Ivanti Connect Secure stack-based buffer overflow", "Ivanti Connect Secure", 9.0),
    ("CVE-2024-3400", "PAN-OS GlobalProtect command injection", "PAN-OS", 10.0),
    ("CVE-2024-21762", "FortiOS SSL-VPN out-of-bounds write", "FortiOS", 9.8),
    ("CVE-2023-27997", "FortiOS SSL-VPN heap buffer overflow", "FortiOS", 9.8),
    ("CVE-2023-20198", "Cisco IOS XE web UI privilege escalation", "IOS XE", 10.0),
    ("CVE-2023-20273", "Cisco IOS XE web UI command injection", "IOS XE", 7.2),
    ("CVE-2022-1388", "F5 BIG-IP iControl REST authentication bypass", "BIG-IP", 9.8),
    ("CVE-2024-1709", "ScreenConnect authentication bypass", "ScreenConnect", 10.0),
    ("CVE-2023-22515", "Confluence Data Center broken access control", "Confluence", 10.0),
    ("CVE-2022-26134", "Confluence OGNL injection RCE", "Confluence", 9.8),
    ("CVE-2024-23897", "Jenkins CLI arbitrary file read", "Jenkins", 9.8),
    ("CVE-2023-42793", "TeamCity authentication bypass", "TeamCity", 9.8),
    ("CVE-2024-27198", "TeamCity authentication bypass", "TeamCity", 9.8),
    ("CVE-2021-26855", "Exchange Server SSRF (ProxyLogon)", "Exchange Server", 9.8),
    ("CVE-2022-41040", "Exchange Server SSRF (ProxyNotShell)", "Exchange Server", 8.8),
    ("CVE-2023-29357", "SharePoint Server privilege escalation", "SharePoint", 9.8),
    ("CVE-2025-53770", "SharePoint Server deserialization RCE (ToolShell)", "SharePoint", 9.8),
    ("CVE-2020-1472", "Netlogon elevation of privilege (Zerologon)", "Active Directory", 10.0),
    ("CVE-2021-34527", "Windows Print Spooler RCE (PrintNightmare)", "Print Spooler", 8.8),
    ("CVE-2024-38063", "Windows TCP/IP IPv6 remote code execution", "Windows Server", 9.8),
    ("CVE-2024-30088", "Windows kernel elevation of privilege", "Windows Server", 7.0),
    ("CVE-2023-23397", "Outlook elevation of privilege (NTLM relay)", "Outlook", 9.8),
    ("CVE-2024-21413", "Outlook remote code execution (MonikerLink)", "Outlook", 9.8),
    ("CVE-2023-36884", "Office and Windows HTML remote code execution", "Microsoft Office", 8.8),
    ("CVE-2023-36025", "Windows SmartScreen security feature bypass", "Windows 11", 8.8),
    ("CVE-2024-21412", "Internet Shortcut files security feature bypass", "Windows 11", 8.1),
    ("CVE-2024-43451", "NTLM hash disclosure spoofing", "Windows 11", 6.5),
    ("CVE-2023-4863", "Chrome libwebp heap buffer overflow", "Chrome", 8.8),
    ("CVE-2024-4577", "PHP-CGI argument injection", "PHP", 9.8),
    ("CVE-2022-22965", "Spring Framework RCE (Spring4Shell)", "Spring Framework", 9.8),
    ("CVE-2023-4911", "glibc ld.so buffer overflow (Looney Tunables)", "glibc", 7.8),
    ("CVE-2024-2961", "glibc iconv out-of-bounds write", "glibc", 7.3),
    ("CVE-2022-0847", "Linux kernel pipe privilege escalation (Dirty Pipe)", "Linux kernel", 7.8),
    ("CVE-2024-1086", "Linux kernel nf_tables use-after-free", "Linux kernel", 7.8),
    ("CVE-2024-6387", "OpenSSH signal handler race condition (regreSSHion)", "OpenSSH", 8.1),
    ("CVE-2023-48795", "SSH prefix truncation attack (Terrapin)", "OpenSSH", 5.9),
    ("CVE-2023-0464", "OpenSSL policy constraint DoS", "OpenSSL", 7.5),
    ("CVE-2023-2650", "OpenSSL OBJ_obj2txt DoS", "OpenSSL", 6.5),
    ("CVE-2024-0727", "OpenSSL PKCS12 NULL dereference", "OpenSSL", 5.5),
    ("CVE-2023-5678", "OpenSSL DH key check DoS", "OpenSSL", 5.3),
    ("CVE-2024-37085", "ESXi Active Directory authentication bypass", "ESXi", 6.8),
    ("CVE-2021-21974", "ESXi OpenSLP heap overflow", "ESXi", 8.8),
    ("CVE-2023-44487", "HTTP/2 Rapid Reset denial of service", "nginx", 7.5),
    ("CVE-2024-7347", "nginx mp4 module out-of-bounds read", "nginx", 4.7),
    ("CVE-2024-27983", "Node.js HTTP/2 race condition", "Node.js", 8.2),
    ("CVE-2024-22019", "Node.js chunked encoding DoS", "Node.js", 7.5),
    ("CVE-2024-3177", "Kubernetes secrets mountable bypass", "Kubernetes", 2.7),
    ("CVE-2023-5528", "Kubernetes Windows node privilege escalation", "Kubernetes", 7.2),
]

# Findings without a CVE (configuration issues scanners also report)
NON_CVE_FINDINGS = [
    ("SSL certificate self-signed", "medium", 5.0),
    ("TLS 1.0/1.1 protocol enabled", "medium", 5.3),
    ("SMB signing not required", "medium", 5.3),
    ("Weak SSH ciphers enabled", "low", 3.7),
    ("SNMP default community string", "high", 7.5),
    ("Expired SSL certificate", "medium", 4.3),
    ("Unsupported operating system", "critical", 9.0),
]

BUSINESS_UNITS = ["Corporate IT", "Finance", "Engineering", "Sales", "HR", "Operations", "Data Platform"]
OWNER_TEAMS = ["Infrastructure", "Endpoint Engineering", "Cloud Platform", "Network Engineering", "App Security", "DevOps"]
PEOPLE = ["A. Rivera", "J. Chen", "M. Okafor", "S. Patel", "L. Nguyen", "R. Haddad", "K. Johansson", "D. Brooks"]

# MITRE ATT&CK aligned detection templates: (title, tactic, technique, category, severity weights)
ALERT_TEMPLATES = {
    "crowdstrike": [
        ("Suspicious PowerShell encoded command", "Execution", "T1059.001 PowerShell", "malware", "high"),
        ("Credential dumping via LSASS memory access", "Credential Access", "T1003.001 LSASS Memory", "credential_theft", "critical"),
        ("Office document spawned command shell", "Initial Access", "T1566.001 Spearphishing Attachment", "phishing", "high"),
        ("Ransomware-like file encryption behavior blocked", "Impact", "T1486 Data Encrypted for Impact", "ransomware", "critical"),
        ("Process injection into trusted process", "Defense Evasion", "T1055 Process Injection", "malware", "high"),
        ("Scheduled task created for persistence", "Persistence", "T1053.005 Scheduled Task", "persistence", "medium"),
        ("Lateral movement via remote service execution", "Lateral Movement", "T1021.002 SMB/Windows Admin Shares", "lateral_movement", "high"),
        ("Known malicious file quarantined", "Execution", "T1204.002 Malicious File", "malware", "medium"),
        ("AD reconnaissance tool executed", "Discovery", "T1087.002 Domain Account", "recon", "medium"),
        ("Command-and-control beacon pattern detected", "Command and Control", "T1071.001 Web Protocols", "c2", "critical"),
        ("Potentially unwanted program detected", "Execution", "T1204 User Execution", "pup", "low"),
    ],
    "expel": [
        ("Login from impossible-travel location", "Initial Access", "T1078 Valid Accounts", "identity", "high"),
        ("Inbox forwarding rule to external address", "Collection", "T1114.003 Email Forwarding Rule", "bec", "high"),
        ("MFA push-bombing against user account", "Credential Access", "T1621 MFA Request Generation", "identity", "high"),
        ("Suspicious admin role assignment in IdP", "Privilege Escalation", "T1098 Account Manipulation", "identity", "critical"),
        ("User clicked credential-phishing link", "Initial Access", "T1566.002 Spearphishing Link", "phishing", "medium"),
        ("Cloud console login without MFA", "Initial Access", "T1078.004 Cloud Accounts", "identity", "medium"),
        ("EDR malware alert escalated for investigation", "Execution", "T1204.002 Malicious File", "malware", "high"),
    ],
    "wiz": [
        ("Storage bucket made publicly readable", "Collection", "T1530 Data from Cloud Storage", "cloud_exposure", "high"),
        ("Access key used from anomalous IP", "Credential Access", "T1552.005 Cloud Instance Metadata API", "identity", "high"),
        ("Cryptominer process in container", "Impact", "T1496 Resource Hijacking", "cryptomining", "critical"),
        ("Security group opened to 0.0.0.0/0 on SSH", "Defense Evasion", "T1562.007 Disable or Modify Cloud Firewall", "cloud_exposure", "medium"),
        ("Privileged pod created in production cluster", "Privilege Escalation", "T1611 Escape to Host", "container", "high"),
        ("Burst of secret retrieval API calls", "Credential Access", "T1555 Credentials from Password Stores", "identity", "medium"),
    ],
    "qualys": [
        ("New critical vulnerability on internet-facing host", "Initial Access", "T1190 Exploit Public-Facing Application", "vulnerability", "high"),
        ("Unauthorized software detected on server", "Persistence", "T1543 Create or Modify System Process", "policy", "low"),
    ],
}

CLOUD_RULES = [
    ("Storage bucket allows public read access", "exposure", "high", "Bucket"),
    ("VM exposed to internet with critical vulnerability and admin role", "toxic_combination", "critical", "VirtualMachine"),
    ("Internet-facing container with exploitable CVE and secrets mounted", "toxic_combination", "critical", "Container"),
    ("Security group allows SSH from 0.0.0.0/0", "exposure", "high", "SecurityGroup"),
    ("Database instance not encrypted at rest", "misconfiguration", "medium", "Database"),
    ("Root/owner account without MFA", "identity", "critical", "Account"),
    ("Access key older than 90 days", "identity", "medium", "ServiceAccount"),
    ("Cleartext secret found in container image", "secret", "high", "ContainerImage"),
    ("Kubernetes API server publicly accessible", "exposure", "high", "KubernetesCluster"),
    ("Audit logging disabled", "misconfiguration", "medium", "Account"),
    ("Key vault without purge protection", "misconfiguration", "low", "KeyVault"),
    ("Overly permissive IAM role (*:*)", "identity", "high", "Role"),
]

VENDORS = [
    ("Northwind Payroll", "HR / Payroll SaaS", 1, "Employee PII, bank details"),
    ("Cobalt CRM Cloud", "CRM", 1, "Customer PII"),
    ("Meridian Managed Hosting", "Infrastructure", 1, "Production systems"),
    ("Apex Backup Services", "Backup / DR", 1, "All corporate data"),
    ("Lumen Identity", "Identity provider", 1, "Credentials, SSO"),
    ("Harbor Payments", "Payment processing", 1, "Cardholder data"),
    ("Brightline Analytics", "Data analytics", 2, "Customer usage data"),
    ("Sierra Logistics", "Logistics", 2, "Shipping addresses"),
    ("Quill Document Signing", "E-signature", 2, "Contracts"),
    ("Atlas Travel Mgmt", "Travel", 2, "Employee PII"),
    ("Pinnacle Benefits", "Benefits admin", 1, "Employee health data"),
    ("Vector Marketing Cloud", "Marketing automation", 2, "Prospect PII"),
    ("Orbit Helpdesk", "IT service management", 2, "Internal tickets"),
    ("Granite Legal Services", "Legal", 2, "Privileged documents"),
    ("Keystone Recruiting", "Recruiting", 3, "Candidate PII"),
    ("Riverbend Facilities", "Facilities", 3, "Badge data"),
    ("Nimbus Video Conferencing", "Collaboration", 2, "Meeting content"),
    ("Summit Training Portal", "Learning", 3, "Employee names"),
    ("Tidewater Print & Mail", "Print services", 3, "Customer mailing data"),
    ("Evergreen Expense", "Expense management", 2, "Corporate card data"),
    ("Falcon Ridge Consulting", "Professional services", 3, "Project documents"),
    ("Copperline Telecom", "Telecom", 2, "Call metadata"),
]

NIST_CSF = [
    ("GV.OC", "Govern", "Organizational Context"), ("GV.RM", "Govern", "Risk Management Strategy"),
    ("GV.RR", "Govern", "Roles, Responsibilities, and Authorities"), ("GV.PO", "Govern", "Policy"),
    ("GV.OV", "Govern", "Oversight"), ("GV.SC", "Govern", "Cybersecurity Supply Chain Risk Management"),
    ("ID.AM", "Identify", "Asset Management"), ("ID.RA", "Identify", "Risk Assessment"),
    ("ID.IM", "Identify", "Improvement"), ("PR.AA", "Protect", "Identity Management, Authentication, and Access Control"),
    ("PR.AT", "Protect", "Awareness and Training"), ("PR.DS", "Protect", "Data Security"),
    ("PR.PS", "Protect", "Platform Security"), ("PR.IR", "Protect", "Technology Infrastructure Resilience"),
    ("DE.CM", "Detect", "Continuous Monitoring"), ("DE.AE", "Detect", "Adverse Event Analysis"),
    ("RS.MA", "Respond", "Incident Management"), ("RS.AN", "Respond", "Incident Analysis"),
    ("RS.CO", "Respond", "Incident Response Reporting and Communication"), ("RS.MI", "Respond", "Incident Mitigation"),
    ("RC.RP", "Recover", "Incident Recovery Plan Execution"), ("RC.CO", "Recover", "Incident Recovery Communication"),
]

ISO_27001 = [
    ("A.5.1", "Organizational", "Policies for information security"), ("A.5.2", "Organizational", "Information security roles and responsibilities"),
    ("A.5.7", "Organizational", "Threat intelligence"), ("A.5.9", "Organizational", "Inventory of information and other associated assets"),
    ("A.5.15", "Organizational", "Access control"), ("A.5.17", "Organizational", "Authentication information"),
    ("A.5.19", "Organizational", "Information security in supplier relationships"), ("A.5.22", "Organizational", "Monitoring, review and change management of supplier services"),
    ("A.5.23", "Organizational", "Information security for use of cloud services"), ("A.5.24", "Organizational", "Incident management planning and preparation"),
    ("A.5.26", "Organizational", "Response to information security incidents"), ("A.5.29", "Organizational", "Information security during disruption"),
    ("A.5.30", "Organizational", "ICT readiness for business continuity"), ("A.5.34", "Organizational", "Privacy and protection of PII"),
    ("A.6.1", "People", "Screening"), ("A.6.3", "People", "Information security awareness, education and training"),
    ("A.6.7", "People", "Remote working"), ("A.7.1", "Physical", "Physical security perimeters"),
    ("A.7.4", "Physical", "Physical security monitoring"), ("A.8.1", "Technological", "User endpoint devices"),
    ("A.8.2", "Technological", "Privileged access rights"), ("A.8.5", "Technological", "Secure authentication"),
    ("A.8.7", "Technological", "Protection against malware"), ("A.8.8", "Technological", "Management of technical vulnerabilities"),
    ("A.8.9", "Technological", "Configuration management"), ("A.8.13", "Technological", "Information backup"),
    ("A.8.15", "Technological", "Logging"), ("A.8.16", "Technological", "Monitoring activities"),
    ("A.8.20", "Technological", "Networks security"), ("A.8.24", "Technological", "Use of cryptography"),
    ("A.8.28", "Technological", "Secure coding"),
]

GDPR = [
    ("Art. 5", "Principles", "Principles relating to processing of personal data"), ("Art. 6", "Principles", "Lawfulness of processing"),
    ("Art. 7", "Principles", "Conditions for consent"), ("Art. 12-14", "Data subject rights", "Transparent information and notice"),
    ("Art. 15", "Data subject rights", "Right of access"), ("Art. 17", "Data subject rights", "Right to erasure"),
    ("Art. 20", "Data subject rights", "Right to data portability"), ("Art. 25", "Controller obligations", "Data protection by design and by default"),
    ("Art. 28", "Controller obligations", "Processor contracts"), ("Art. 30", "Controller obligations", "Records of processing activities"),
    ("Art. 32", "Security", "Security of processing"), ("Art. 33", "Security", "Breach notification to supervisory authority (72h)"),
    ("Art. 34", "Security", "Communication of breach to data subjects"), ("Art. 35", "Controller obligations", "Data protection impact assessment"),
    ("Art. 37", "Controller obligations", "Designation of data protection officer"),
]

# Controls whose status is evaluated from live dashboard data instead of manual attestation
AUTO_RULES = {
    ("NIST CSF 2.0", "DE.CM"): "edr_coverage",
    ("NIST CSF 2.0", "ID.RA"): "vuln_sla",
    ("NIST CSF 2.0", "ID.AM"): "scan_coverage",
    ("NIST CSF 2.0", "GV.SC"): "vendor_assessments",
    ("NIST CSF 2.0", "RS.MA"): "incident_response",
    ("ISO 27001:2022", "A.8.7"): "edr_coverage",
    ("ISO 27001:2022", "A.8.8"): "vuln_sla",
    ("ISO 27001:2022", "A.5.9"): "scan_coverage",
    ("ISO 27001:2022", "A.5.22"): "vendor_assessments",
    ("ISO 27001:2022", "A.8.9"): "cloud_config",
    ("ISO 27001:2022", "A.5.26"): "incident_response",
    ("GDPR", "Art. 32"): "vuln_sla",
    ("GDPR", "Art. 33"): "incident_response",
}

SLA_DAYS = {"critical": 15, "high": 30, "medium": 90, "low": 180}


def severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"
