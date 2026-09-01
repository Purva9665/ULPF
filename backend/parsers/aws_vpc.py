"""
AWS VPC Flow Log Parser
Handles AWS VPC Flow Log default and custom formats (v2 through v5).
"""

import re
from typing import Tuple, Dict, Any, List
from datetime import datetime, timezone
from backend.core.base_parser import BaseParser
from backend.core.models import ULPFRawEvent, ULPFParsedEvent


class AWSVPCFlowParser(BaseParser):
    name = "aws_vpc_flow"
    vendor = "Amazon Web Services"
    product = "VPC Flow Logs"
    supported_formats = ["vpc_flow_v2", "vpc_flow_v3", "vpc_flow_v5"]
    description = "Parses AWS VPC Flow Logs space-delimited records"

    # Default v2 format: version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
    V2_FIELDS = [
        "version", "account_id", "interface_id", "src_ip", "dst_ip",
        "src_port", "dst_port", "protocol_num", "packets", "bytes",
        "start_time", "end_time", "action", "log_status"
    ]

    # IANA Protocol number to name mapping
    PROTO_MAP = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        47: "GRE",
        50: "ESP",
        51: "AH",
        58: "IPv6-ICMP",
    }

    def can_parse(self, raw_event: ULPFRawEvent) -> Tuple[bool, float]:
        text = raw_event.raw.payload.strip()
        parts = text.split()
        # Typical VPC Flow starts with version number (e.g. 2, 3, 5) and has interface-id eni-XXXX
        if len(parts) >= 14 and parts[0] in ("2", "3", "4", "5") and parts[2].startswith("eni-"):
            return True, 0.98
        if re.search(r"^\d+\s+\d{12}\s+eni-[0-9a-f]+\s+[\d.]+\s+[\d.]+", text):
            return True, 0.99
        return False, 0.0

    def parse(self, raw_event: ULPFRawEvent) -> ULPFParsedEvent:
        text = raw_event.raw.payload.strip()
        parts = text.split()
        extracted: Dict[str, Any] = {}
        tokens: List[Dict[str, Any]] = []

        for idx, val in enumerate(parts):
            if idx < len(self.V2_FIELDS):
                key = self.V2_FIELDS[idx]
                if val != "-":
                    if key in ("version", "src_port", "dst_port", "protocol_num", "packets", "bytes", "start_time", "end_time"):
                        try:
                            extracted[key] = int(val)
                        except ValueError:
                            extracted[key] = val
                    else:
                        extracted[key] = val

        # Map protocol number to string if present
        if "protocol_num" in extracted and isinstance(extracted["protocol_num"], int):
            extracted["protocol"] = self.PROTO_MAP.get(extracted["protocol_num"], f"PROTO_{extracted['protocol_num']}")

        # Convert epoch timestamps to ISO strings
        if "start_time" in extracted and isinstance(extracted["start_time"], int):
            try:
                extracted["start_iso"] = datetime.fromtimestamp(extracted["start_time"], timezone.utc).isoformat()
            except Exception:
                pass

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
            confidence_score=0.99,
            extracted_fields=extracted,
            tokens=tokens,
        )
