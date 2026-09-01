"""
Windows Security Event Log Parser
Handles Windows Security Events (EventID 4624 Logon, 4625 Failed Logon, 4688 Process, 5156 Connection).
"""

import re
from typing import Tuple, Dict, Any, List
from backend.core.base_parser import BaseParser
from backend.core.models import ULPFRawEvent, ULPFParsedEvent


class WindowsEventParser(BaseParser):
    name = "windows_security_event"
    vendor = "Microsoft"
    product = "Windows Security Event Log"
    supported_formats = ["windows_event", "evtx_xml", "win_sec_event"]
    description = "Parses Windows Security and Filtering Platform Event logs"

    # EventID regex
    EVENT_ID_REGEX = re.compile(r"(?:EventID|Event ID|Event\[\s*ID\s*\])[:=\s]+(?P<event_id>\d+)", re.IGNORECASE)
    
    # Common Windows field patterns
    FIELD_PATTERNS = {
        "account_name": re.compile(r"(?:Account Name|TargetUserName|SubjectUserName)[:=\s]+([^\r\n,]+)", re.IGNORECASE),
        "account_domain": re.compile(r"(?:Account Domain|TargetDomainName|SubjectDomainName)[:=\s]+([^\r\n,]+)", re.IGNORECASE),
        "logon_type": re.compile(r"(?:Logon Type|LogonType)[:=\s]+(\d+)", re.IGNORECASE),
        "src_ip": re.compile(r"(?:Source Network Address|Source Address|IpAddress|SourceIpAddress)[:=\s]+([0-9.]+)", re.IGNORECASE),
        "src_port": re.compile(r"(?:Source Port|SourcePort|IpPort)[:=\s]+(\d+)", re.IGNORECASE),
        "dst_ip": re.compile(r"(?:Destination Address|DestAddress|DestinationIpAddress)[:=\s]+([0-9.]+)", re.IGNORECASE),
        "dst_port": re.compile(r"(?:Destination Port|DestPort)[:=\s]+(\d+)", re.IGNORECASE),
        "process_name": re.compile(r"(?:Process Name|NewProcessName|Application)[:=\s]+([^\r\n,]+)", re.IGNORECASE),
        "status_code": re.compile(r"(?:Status|Failure Reason|SubStatus)[:=\s]+(0x[0-9a-fA-F]+)", re.IGNORECASE),
    }

    def can_parse(self, raw_event: ULPFRawEvent) -> Tuple[bool, float]:
        text = raw_event.raw.payload
        if "Microsoft-Windows-Security-Auditing" in text or "EventID" in text or "Event ID: 4624" in text or "Event ID: 4625" in text or "Event ID: 5156" in text:
            return True, 0.95
        if "Security-Auditing" in text and ("Account Name:" in text or "Logon Type:" in text):
            return True, 0.90
        return False, 0.0

    def parse(self, raw_event: ULPFRawEvent) -> ULPFParsedEvent:
        text = raw_event.raw.payload.strip()
        extracted: Dict[str, Any] = {}
        tokens: List[Dict[str, Any]] = []

        # Find Event ID
        event_id_match = self.EVENT_ID_REGEX.search(text)
        if event_id_match:
            extracted["windows_event_id"] = int(event_id_match.group("event_id"))
        else:
            extracted["windows_event_id"] = 0

        # Extract fields
        for field_name, regex in self.FIELD_PATTERNS.items():
            m = regex.search(text)
            if m:
                val = m.group(1).strip()
                if val not in ("-", "%%1793", "%%1795"):
                    if field_name in ("src_port", "dst_port", "logon_type"):
                        try:
                            extracted[field_name] = int(val)
                        except ValueError:
                            extracted[field_name] = val
                    else:
                        extracted[field_name] = val

        # Set human description based on Event ID
        event_descriptions = {
            4624: ("SUCCESSFUL_LOGON", "INFORMATIONAL", "ALLOW"),
            4625: ("FAILED_LOGON", "HIGH", "DENY"),
            4688: ("PROCESS_CREATION", "INFORMATIONAL", "ALLOW"),
            5156: ("FILTERING_CONNECTION_ALLOWED", "INFORMATIONAL", "ALLOW"),
            5157: ("FILTERING_CONNECTION_BLOCKED", "MEDIUM", "DROP"),
        }

        eid = extracted.get("windows_event_id", 0)
        if eid in event_descriptions:
            event_type, severity, action = event_descriptions[eid]
            extracted["event_type_name"] = event_type
            extracted["severity"] = severity
            extracted["action"] = action

        for k, v in extracted.items():
            tokens.append({"key": k, "value": v, "type": type(v).__name__})

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
