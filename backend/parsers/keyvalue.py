"""
Key-Value Log Parser
Handles Fortinet FortiGate, SonicWall, CheckPoint, and generic key=value / k="v" formats.
"""

import re
from typing import Tuple, Dict, Any, List
from backend.core.base_parser import BaseParser
from backend.core.models import ULPFRawEvent, ULPFParsedEvent


class KeyValueParser(BaseParser):
    name = "generic_keyvalue"
    vendor = "Generic / Fortinet / SonicWall"
    product = "Key-Value Formatted Device"
    supported_formats = ["keyvalue", "kv", "fortigate_kv", "sonicwall_kv"]
    description = "Parses key=value and key=\"value\" delimited log events"

    # Regex extracting key="value with spaces" or key=value_without_spaces
    KV_REGEX = re.compile(r'(?P<key>[\w.-]+)=(?:"(?P<quoted_val>[^"]*)"|(?P<raw_val>[^\s,]+))')

    def can_parse(self, raw_event: ULPFRawEvent) -> Tuple[bool, float]:
        text = raw_event.raw.payload
        # Count key=value patterns
        matches = self.KV_REGEX.findall(text)
        if len(matches) >= 4:
            if "devname=" in text or "srcip=" in text or "dstip=" in text or "action=" in text:
                return True, 0.92
            return True, 0.75
        return False, 0.0

    def parse(self, raw_event: ULPFRawEvent) -> ULPFParsedEvent:
        text = raw_event.raw.payload.strip()
        extracted: Dict[str, Any] = {}
        tokens: List[Dict[str, Any]] = []

        # Find prefix (e.g. timestamp or hostname before first key=value)
        first_eq = text.find("=")
        if first_eq > 0:
            first_key_match = re.search(r'[\w.-]+=', text)
            if first_key_match and first_key_match.start() > 0:
                prefix = text[:first_key_match.start()].strip()
                if prefix:
                    extracted["syslog_prefix"] = prefix

        for match in self.KV_REGEX.finditer(text):
            k = match.group("key")
            v = match.group("quoted_val") if match.group("quoted_val") is not None else match.group("raw_val")
            
            # Numeric conversion
            if k in ("srcport", "dstport", "src_port", "dst_port", "spt", "dpt", "port", "sentbyte", "rcvdbyte", "bytes", "duration"):
                try:
                    extracted[k] = int(v)
                except ValueError:
                    extracted[k] = v
            else:
                extracted[k] = v

        # Standardize common fields
        if "srcip" in extracted and "src_ip" not in extracted:
            extracted["src_ip"] = extracted["srcip"]
        if "dstip" in extracted and "dst_ip" not in extracted:
            extracted["dst_ip"] = extracted["dstip"]
        if "srcport" in extracted and "src_port" not in extracted:
            extracted["src_port"] = extracted["srcport"]
        if "dstport" in extracted and "dst_port" not in extracted:
            extracted["dst_port"] = extracted["dstport"]
        if "proto" in extracted and "protocol" not in extracted:
            extracted["protocol"] = str(extracted["proto"]).upper()

        vendor = self.vendor
        if "devname" in extracted or "type" in extracted and "fortigate" in str(extracted.get("devname", "")).lower():
            vendor = "Fortinet"
            product = "FortiGate Firewall"
        else:
            product = self.product

        extracted["vendor"] = vendor
        extracted["product"] = product

        for k, v in extracted.items():
            tokens.append({"key": k, "value": v, "type": type(v).__name__})

        return ULPFParsedEvent(
            event_id=raw_event.event_id,
            raw=raw_event.raw,
            parser_name=self.name,
            parser_vendor=vendor,
            parser_product=product,
            confidence_score=0.85,
            extracted_fields=extracted,
            tokens=tokens,
        )
