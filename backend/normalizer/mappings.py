"""
ULPF Normalization Mappings & Field Taxonomy
Defines the canonical dictionary mapping vendor-specific keys to standard ULPF namespaces.
"""

from typing import Dict, List, Any
from backend.core.models import ActionEnum, SeverityEnum

# Canonical Action Mapping
ACTION_MAP = {
    # Allow variants
    "allow": ActionEnum.ALLOW,
    "accept": ActionEnum.ALLOW,
    "pass": ActionEnum.ALLOW,
    "permit": ActionEnum.ALLOW,
    "built": ActionEnum.ALLOW,
    "success": ActionEnum.ALLOW,
    "allowed": ActionEnum.ALLOW,
    "0": ActionEnum.ALLOW,
    # Deny / Drop variants
    "deny": ActionEnum.DENY,
    "drop": ActionEnum.DROP,
    "reject": ActionEnum.REJECT,
    "block": ActionEnum.DROP,
    "blocked": ActionEnum.DROP,
    "teardown": ActionEnum.ALLOW,
    "alert": ActionEnum.ALERT,
    "reset": ActionEnum.RESET,
    "reset-both": ActionEnum.RESET,
    "reset-server": ActionEnum.RESET,
    "reset-client": ActionEnum.RESET,
}

# Canonical Severity Mapping
SEVERITY_MAP = {
    "1": SeverityEnum.CRITICAL,
    "critical": SeverityEnum.CRITICAL,
    "crit": SeverityEnum.CRITICAL,
    "emergency": SeverityEnum.CRITICAL,
    "alert": SeverityEnum.CRITICAL,
    "high": SeverityEnum.HIGH,
    "2": SeverityEnum.HIGH,
    "error": SeverityEnum.HIGH,
    "err": SeverityEnum.HIGH,
    "medium": SeverityEnum.MEDIUM,
    "med": SeverityEnum.MEDIUM,
    "warn": SeverityEnum.MEDIUM,
    "warning": SeverityEnum.MEDIUM,
    "3": SeverityEnum.MEDIUM,
    "low": SeverityEnum.LOW,
    "4": SeverityEnum.LOW,
    "notice": SeverityEnum.LOW,
    "info": SeverityEnum.INFORMATIONAL,
    "informational": SeverityEnum.INFORMATIONAL,
    "5": SeverityEnum.INFORMATIONAL,
    "6": SeverityEnum.INFORMATIONAL,
    "7": SeverityEnum.INFORMATIONAL,
    "debug": SeverityEnum.INFORMATIONAL,
}

# Known Port to Service Names
WELL_KNOWN_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-SERVER",
    68: "DHCP-CLIENT",
    80: "HTTP",
    88: "KERBEROS",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    137: "NETBIOS-NS",
    138: "NETBIOS-DGM",
    139: "NETBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "MICROSOFT-DS / SMB",
    465: "SMTPS",
    514: "SYSLOG",
    587: "SMTP-SUBMISSION",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE-DB",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    5900: "VNC",
    6379: "REDIS",
    8080: "HTTP-PROXY / ALT-HTTP",
    8443: "ALT-HTTPS",
    9200: "ELASTICSEARCH",
    27017: "MONGODB",
}

# Standard Field Aliases mapped to Canonical Target Namespaces
FIELD_ALIASES: Dict[str, List[str]] = {
    # Source IP
    "source.ip": [
        "src_ip", "srcip", "src", "source_ip", "c-ip", "SourceIpAddress", "id_orig_h",
        "client_ip", "remote_addr", "Source Address", "IpAddress"
    ],
    # Source Port
    "source.port": [
        "src_port", "srcport", "spt", "source_port", "c-port", "SourcePort", "id_orig_p",
        "client_port", "remote_port", "IpPort"
    ],
    # Destination IP
    "destination.ip": [
        "dst_ip", "dstip", "dst", "dest_ip", "destination_ip", "s-ip", "DestAddress",
        "DestinationIpAddress", "id_resp_h", "server_ip"
    ],
    # Destination Port
    "destination.port": [
        "dst_port", "dstport", "dpt", "dest_port", "destination_port", "s-port", "DestPort",
        "DestinationPort", "id_resp_p", "server_port"
    ],
    # Protocol
    "network.protocol": [
        "protocol", "proto", "transport", "app_proto", "service"
    ],
    # Total Bytes / Packets
    "network.bytes_total": [
        "bytes", "total_bytes", "byte_count", "bytes_total"
    ],
    "source.bytes": [
        "bytes_sent", "orig_bytes", "orig_ip_bytes", "sentbyte", "src_bytes"
    ],
    "destination.bytes": [
        "bytes_received", "resp_bytes", "resp_ip_bytes", "rcvdbyte", "dst_bytes"
    ],
    "network.packets_total": [
        "packets", "total_packets", "packet_count"
    ],
    "source.packets": [
        "pkts_sent", "orig_pkts", "src_packets"
    ],
    "destination.packets": [
        "pkts_received", "resp_pkts", "dst_packets"
    ],
    # Action
    "event.action": [
        "action", "act", "status", "disposition", "result"
    ],
    # Severity
    "event.severity": [
        "severity", "level", "priority", "threat_level"
    ],
    # Session ID / Connection ID
    "network.session_id": [
        "session_id", "connection_id", "uid", "flow_id", "sessionid"
    ],
    # Threat / Signature Details
    "threat.signature": [
        "threat_id", "signature", "signature_name", "threat_name", "alert.signature", "msg"
    ],
    "threat.category": [
        "category", "threat_category", "classification", "alert.category"
    ],
    "threat.indicator": [
        "indicator", "cve", "threat_indicator", "rule_name"
    ],
    # Observer
    "observer.hostname": [
        "observer_hostname", "hostname", "devname", "device_name", "host"
    ],
}
