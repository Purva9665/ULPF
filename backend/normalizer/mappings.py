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
        "bytes_sent", "orig_bytes", "orig_ip_bytes", "sentbyte", "src_bytes",
        # Suricata EVE nests these under "flow"; the parser flattens with dots.
        "flow.bytes_toserver", "bytes_toserver"
    ],
    "destination.bytes": [
        "bytes_received", "resp_bytes", "resp_ip_bytes", "rcvdbyte", "dst_bytes",
        "flow.bytes_toclient", "bytes_toclient"
    ],
    "network.packets_total": [
        "packets", "total_packets", "packet_count"
    ],
    "source.packets": [
        "pkts_sent", "orig_pkts", "src_packets",
        "flow.pkts_toserver", "pkts_toserver"
    ],
    "destination.packets": [
        "pkts_received", "resp_pkts", "dst_packets",
        "flow.pkts_toclient", "pkts_toclient"
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


# ---------------------------------------------------------------------------
# Vendor status-code tables
#
# Several devices never emit a literal action word - they emit a numeric
# message ID or a connection-state code and expect the consumer to know the
# meaning. Without these tables the canonical action stays UNKNOWN and every
# downstream decision (routing, classification, correlation) loses its
# strongest signal.
# ---------------------------------------------------------------------------

#: Cisco ASA syslog mnemonic -> canonical action.
#: Reference: Cisco ASA Series Syslog Messages guide.
ASA_MNEMONIC_ACTION = {
    "106001": ActionEnum.DENY,    # Inbound TCP connection denied
    "106006": ActionEnum.DENY,    # Deny inbound UDP
    "106007": ActionEnum.DENY,    # Deny inbound UDP, DNS response
    "106010": ActionEnum.DENY,    # Deny inbound protocol
    "106014": ActionEnum.DENY,    # Deny inbound ICMP
    "106015": ActionEnum.DENY,    # Deny TCP (no connection)
    "106016": ActionEnum.DENY,    # Deny IP spoof
    "106017": ActionEnum.DENY,    # Deny IP due to Land Attack
    "106021": ActionEnum.DENY,    # Deny reverse path check
    "106023": ActionEnum.DENY,    # Deny by access-group
    "106100": ActionEnum.UNKNOWN, # permitted OR denied - text decides
    "302013": ActionEnum.ALLOW,   # Built inbound TCP connection
    "302014": ActionEnum.ALLOW,   # Teardown TCP connection
    "302015": ActionEnum.ALLOW,   # Built UDP connection
    "302016": ActionEnum.ALLOW,   # Teardown UDP connection
    "302020": ActionEnum.ALLOW,   # Built ICMP connection
    "302021": ActionEnum.ALLOW,   # Teardown ICMP connection
    "313001": ActionEnum.DENY,    # Denied ICMP type
    "313008": ActionEnum.DENY,    # Denied ICMPv6 type
    "710003": ActionEnum.DENY,    # Access denied to device service
    "733100": ActionEnum.ALERT,   # Threat detection rate exceeded
}

#: Zeek conn.log conn_state -> (canonical action, human meaning).
#: Reference: Zeek base/protocols/conn documentation.
ZEEK_CONN_STATE = {
    "S0":     (ActionEnum.DROP,   "Connection attempt seen, no reply"),
    "S1":     (ActionEnum.ALLOW,  "Connection established, not terminated"),
    "SF":     (ActionEnum.ALLOW,  "Normal establishment and termination"),
    "REJ":    (ActionEnum.REJECT, "Connection attempt rejected"),
    "S2":     (ActionEnum.ALLOW,  "Established, originator close attempt only"),
    "S3":     (ActionEnum.ALLOW,  "Established, responder close attempt only"),
    "RSTO":   (ActionEnum.RESET,  "Established, originator aborted"),
    "RSTR":   (ActionEnum.RESET,  "Established, responder aborted"),
    "RSTOS0": (ActionEnum.RESET,  "Originator SYN then RST, no responder SYN-ACK"),
    "RSTRH":  (ActionEnum.RESET,  "Responder SYN-ACK then RST, no originator SYN"),
    "SH":     (ActionEnum.DROP,   "Originator SYN then FIN, no responder SYN-ACK"),
    "SHR":    (ActionEnum.DROP,   "Responder SYN-ACK then FIN, no originator SYN"),
    "OTH":    (ActionEnum.UNKNOWN, "No SYN seen, midstream traffic"),
}

#: Zeek conn_states that indicate scanning behaviour when seen from one source.
ZEEK_SCAN_STATES = frozenset({"S0", "REJ", "RSTOS0", "SH"})

#: IANA IP protocol numbers to canonical names.
#: FortiGate, Palo Alto and NetFlow-derived sources report the protocol as an
#: IANA number, not a name. Without this table the normalizer stores the string
#: "6" as the protocol, which silently breaks every downstream consumer that
#: compares against "TCP" - including the taxonomy classifier and the SIEM
#: routing rules.
#: Reference: IANA Assigned Internet Protocol Numbers.
IP_PROTOCOL_NUMBERS = {
    0: "HOPOPT", 1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPV6",
    47: "GRE", 50: "ESP", 51: "AH", 58: "IPV6-ICMP", 89: "OSPF", 132: "SCTP",
}
