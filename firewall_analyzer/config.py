from pathlib import Path

LOG_FILE = Path("/var/log/syslog")
SHOREWALL_RULES = Path("/etc/shorewall/rules")
MARKER = "net-fw DROP"

TOP_COUNT = 20
PROFILE_COUNT = 10

DANGEROUS_SERVICES = {
    "TCP/23": ("Telnet scanner", 60),
    "TCP/445": ("SMB scanner", 70),
    "TCP/3389": ("RDP scanner", 60),
    "UDP/5060": ("SIP scanner", 80),
    "TCP/1433": ("MSSQL scanner", 50),
    "TCP/3306": ("MySQL scanner", 50),
    "TCP/5432": ("PostgreSQL scanner", 50),
    "TCP/6379": ("Redis scanner", 60),
    "TCP/27017": ("MongoDB scanner", 50),
    "TCP/9200": ("Elasticsearch scanner", 50),
}

REVIEW_SERVICES = {
    "TCP/22": ("SSH probing", 30),
    "TCP/2222": ("Published SSH DNAT probing", 50),
    "TCP/25": ("SMTP probing", 20),
    "TCP/465": ("SMTPS probing", 20),
    "TCP/587": ("Submission probing", 20),
    "TCP/993": ("IMAPS probing", 20),
    "UDP/13231": ("Published WireGuard probing", 50),
    "UDP/13232": ("Published WireGuard probing", 50),
}

LIKELY_BENIGN_PREFIXES = (
    "157.240.",
    "31.13.",
    "31.14.",
    "17.253.",
)
