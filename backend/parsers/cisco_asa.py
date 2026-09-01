"""
Cisco ASA / FTD Log Parser
Handles Cisco Adaptive Security Appliance (ASA) syslog events (%ASA-X-XXXXXX).
"""

import re
from typing import Tuple, Dict, Any, List
from backend.core.base_parser import BaseParser
from backend.core.models import ULPFRawEvent, ULPFParsedEvent


class CiscoASAParser(BaseParser):
    name = "cisco_asa"
    vendor = "Cisco"
    product = "ASA Firewall"
    supported_formats = ["syslog", "cisco_asa", "%ASA-"]
    description = "Parses Cisco ASA / Firepower Threat Defense (FTD) syslog messages"

    # Regex patterns for various Cisco ASA message types
    PATTERNS = [
        # %ASA-4-106023: Deny tcp src outside:203.0.113.45/49152 dst inside:10.0.1.20/445 by access-group 'OUTSIDE-IN' [0x0, 0x0]
        {
            "id": "106023_deny",
            "regex": re.compile(
                r"%ASA-(?P<severity>\d)-(?P<mnemonic>106023):\s+(?P<action>Deny)\s+(?P<protocol>\w+)\s+src\s+(?P<src_interface>[\w.-]+):(?P<src_ip>[\d.]+)/(?P<src_port>\d+)\s+dst\s+(?P<dst_interface>[\w.-]+):(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+)(?:\s+by\s+access-group\s+'(?P<access_group>[^']+)')?(?:\s+\[(?P<extra_code>[^\]]+)\])?",
                re.IGNORECASE,
            ),
        },
        # %ASA-6-302013: Built inbound TCP connection 993821 for outside:203.0.113.45/49152 (203.0.113.45/49152) to inside:10.0.1.20/80 (10.0.1.20/80)
        {
            "id": "302013_built_tcp",
            "regex": re.compile(
                r"%ASA-(?P<severity>\d)-(?P<mnemonic>302013|302015):\s+Built\s+(?P<direction>\w+)\s+(?P<protocol>TCP|UDP)\s+connection\s+(?P<connection_id>\d+)\s+for\s+(?P<src_interface>[\w.-]+):(?P<src_ip>[\d.]+)/(?P<src_port>\d+)(?:\s+\([^)]+\))?\s+to\s+(?P<dst_interface>[\w.-]+):(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+)",
                re.IGNORECASE,
            ),
        },
        # %ASA-6-302014: Teardown TCP connection 993821 for outside:203.0.113.45/49152 to inside:10.0.1.20/80 duration 0:00:30 bytes 14500 TCP FINs
        {
            "id": "302014_teardown_tcp",
            "regex": re.compile(
                r"%ASA-(?P<severity>\d)-(?P<mnemonic>302014|302016):\s+Teardown\s+(?P<protocol>TCP|UDP)\s+connection\s+(?P<connection_id>\d+)\s+for\s+(?P<src_interface>[\w.-]+):(?P<src_ip>[\d.]+)/(?P<src_port>\d+)\s+to\s+(?P<dst_interface>[\w.-]+):(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+)\s+duration\s+(?P<duration>[\d:]+)\s+bytes\s+(?P<bytes>\d+)(?:\s+(?P<reason>.*))?",
                re.IGNORECASE,
            ),
        },
        # %ASA-1-106021: Deny protocol reverse path check from 203.0.113.45 to 10.0.1.20 on interface outside
        {
            "id": "106021_rpf_deny",
            "regex": re.compile(
                r"%ASA-(?P<severity>\d)-(?P<mnemonic>106021):\s+Deny\s+(?P<protocol>protocol|\w+)\s+reverse\s+path\s+check\s+from\s+(?P<src_ip>[\d.]+)\s+to\s+(?P<dst_ip>[\d.]+)\s+on\s+interface\s+(?P<src_interface>[\w.-]+)",
                re.IGNORECASE,
            ),
        },
        # Generic ASA Fallback Regex: %ASA-LEVEL-MNEMONIC: message
        {
            "id": "generic_asa",
            "regex": re.compile(
                r"%ASA-(?P<severity>\d)-(?P<mnemonic>\d+):\s+(?P<message>.*)",
                re.IGNORECASE,
            ),
        },
    ]

    def can_parse(self, raw_event: ULPFRawEvent) -> Tuple[bool, float]:
        text = raw_event.raw.payload
        if "%ASA-" in text or "%FTD-" in text:
            return True, 0.95
        if re.search(r"cisco|asa|firepower", text, re.IGNORECASE) and re.search(r"\b(src|dst|connection)\b", text, re.IGNORECASE):
            return True, 0.70
        return False, 0.0

    def parse(self, raw_event: ULPFRawEvent) -> ULPFParsedEvent:
        text = raw_event.raw.payload.strip()
        extracted: Dict[str, Any] = {}
        tokens: List[Dict[str, Any]] = []

        # Find prefix timestamp/hostname if present
        # e.g., "Sep 01 01:00:00 fw-edge01 %ASA-4-106023: ..."
        prefix_match = re.match(r"^([A-Z][a-z]{2}\s+\d+\s+[\d:]+|\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:\d{2}))?\s*([\w.-]+)?\s*(%ASA.*)$", text)
        if prefix_match:
            timestamp, hostname, asa_body = prefix_match.groups()
            if timestamp:
                extracted["syslog_timestamp"] = timestamp.strip()
            if hostname:
                extracted["observer_hostname"] = hostname.strip()
            text = asa_body

        matched_pattern_id = "unknown"
        for pattern in self.PATTERNS:
            match = pattern["regex"].search(text)
            if match:
                matched_pattern_id = pattern["id"]
                groups = match.groupdict()
                for k, v in groups.items():
                    if v is not None:
                        # Convert numeric fields
                        if k in ("src_port", "dst_port", "bytes", "connection_id", "severity"):
                            try:
                                extracted[k] = int(v) if k != "severity" else v
                            except ValueError:
                                extracted[k] = v
                        else:
                            extracted[k] = v
                break

        # Generate token breakdown
        for k, v in extracted.items():
            tokens.append({"key": k, "value": v, "type": type(v).__name__})

        extracted["cisco_message_type"] = matched_pattern_id
        extracted["vendor"] = self.vendor
        extracted["product"] = self.product

        return ULPFParsedEvent(
            event_id=raw_event.event_id,
            raw=raw_event.raw,
            parser_name=self.name,
            parser_vendor=self.vendor,
            parser_product=self.product,
            confidence_score=0.95,
            extracted_fields=extracted,
            tokens=tokens,
        )
