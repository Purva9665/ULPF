"""
Suricata & Snort IDS EVE Log Parser
Handles Suricata EVE JSON and Snort Fast Alert formats.
"""

import json
import re
from typing import Tuple, Dict, Any, List
from backend.core.base_parser import BaseParser
from backend.core.models import ULPFRawEvent, ULPFParsedEvent


class SuricataParser(BaseParser):
    name = "suricata_eve"
    vendor = "Suricata / Snort"
    product = "EVE Network IDS/IPS"
    supported_formats = ["eve_json", "suricata_json", "snort_fast_log"]
    description = "Parses Suricata EVE JSON records and Snort Fast Alert logs"

    # Snort Fast Alert format: [**] [1:2000001:1] ET SCAN ... [**] [Classification: ...] [Priority: 1] {TCP} 1.2.3.4:1234 -> 5.6.7.8:80
    SNORT_ALERT_REGEX = re.compile(
        r"\[\*\*\]\s+\[(?P<generator_id>\d+):(?P<signature_id>\d+):(?P<revision>\d+)\]\s+(?P<signature_name>[^\[]+)\s+\[\*\*\]"
        r"(?:\s+\[Classification:\s+(?P<classification>[^\]]+)\])?"
        r"(?:\s+\[Priority:\s+(?P<priority>\d+)\])?"
        r"\s*\{(?P<protocol>\w+)\}\s+(?P<src_ip>[\d.]+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)",
        re.IGNORECASE,
    )

    def can_parse(self, raw_event: ULPFRawEvent) -> Tuple[bool, float]:
        text = raw_event.raw.payload.strip()
        if text.startswith("{") and text.endswith("}"):
            if '"event_type"' in text or '"suricata"' in text or ('"src_ip"' in text and '"dest_ip"' in text):
                return True, 0.98
        if "[**]" in text and ("Classification:" in text or "Priority:" in text or "{" in text):
            return True, 0.90
        return False, 0.0

    def parse(self, raw_event: ULPFRawEvent) -> ULPFParsedEvent:
        text = raw_event.raw.payload.strip()
        extracted: Dict[str, Any] = {}
        tokens: List[Dict[str, Any]] = []

        # 1. Try JSON (EVE format)
        if text.startswith("{") and text.endswith("}"):
            try:
                data = json.loads(text)
                extracted = self._flatten_json(data)
                extracted["log_format"] = "suricata_eve_json"
            except json.JSONDecodeError:
                pass

        # 2. Try Snort Fast Alert regex if not parsed as JSON
        if not extracted:
            match = self.SNORT_ALERT_REGEX.search(text)
            if match:
                groups = match.groupdict()
                for k, v in groups.items():
                    if v is not None:
                        if k in ("src_port", "dst_port", "priority", "signature_id", "revision"):
                            try:
                                extracted[k] = int(v)
                            except ValueError:
                                extracted[k] = v
                        else:
                            extracted[k] = v.strip() if isinstance(v, str) else v
                extracted["log_format"] = "snort_fast_alert"

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
            confidence_score=0.98,
            extracted_fields=extracted,
            tokens=tokens,
        )

    def _flatten_json(self, d: Dict[str, Any], parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
        items: List[Tuple[str, Any]] = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_json(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)
