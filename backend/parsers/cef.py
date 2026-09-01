"""
ArcSight Common Event Format (CEF) Parser
Handles CEF standard logs: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
"""

import re
from typing import Tuple, Dict, Any, List
from backend.core.base_parser import BaseParser
from backend.core.models import ULPFRawEvent, ULPFParsedEvent


class CEFParser(BaseParser):
    name = "arcsight_cef"
    vendor = "ArcSight / Multi-Vendor"
    product = "Common Event Format (CEF)"
    supported_formats = ["cef", "arcsight_cef", "cef:0"]
    description = "Parses ArcSight Common Event Format (CEF) structured log strings"

    CEF_HEADER_REGEX = re.compile(
        r"CEF:(?P<cef_version>\d+)\|(?P<device_vendor>[^\\|]*)\|(?P<device_product>[^\\|]*)\|(?P<device_version>[^\\|]*)\|(?P<device_event_class_id>[^\\|]*)\|(?P<name>[^\\|]*)\|(?P<severity>[^\\|]*)\|(P<extension>.*)?",
        re.DOTALL
    )

    # Simplified parser splitting on unescaped pipes
    def can_parse(self, raw_event: ULPFRawEvent) -> Tuple[bool, float]:
        text = raw_event.raw.payload
        if "CEF:" in text:
            return True, 0.99
        return False, 0.0

    def parse(self, raw_event: ULPFRawEvent) -> ULPFParsedEvent:
        text = raw_event.raw.payload.strip()
        extracted: Dict[str, Any] = {}
        tokens: List[Dict[str, Any]] = []

        cef_pos = text.find("CEF:")
        if cef_pos != -1:
            syslog_prefix = text[:cef_pos].strip()
            if syslog_prefix:
                extracted["syslog_prefix"] = syslog_prefix
            text = text[cef_pos:]

        # Split on '|' with care for escapes
        parts = []
        current = []
        escaped = False
        pipe_count = 0
        for idx, ch in enumerate(text):
            if escaped:
                current.append(ch)
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == "|" and pipe_count < 7:
                parts.append("".join(current))
                current = []
                pipe_count += 1
            else:
                current.append(ch)
        parts.append("".join(current))

        if len(parts) >= 8:
            extracted["cef_version"] = parts[0].replace("CEF:", "")
            extracted["device_vendor"] = parts[1]
            extracted["device_product"] = parts[2]
            extracted["device_version"] = parts[3]
            extracted["device_event_class_id"] = parts[4]
            extracted["name"] = parts[5]
            extracted["severity"] = parts[6]
            extension_str = parts[7]
            
            # Parse extension key-value pairs
            # e.g., src=1.2.3.4 dst=5.6.7.8 spt=1234 dpt=80 act=drop msg=Blocked
            kv_pairs = self._parse_extension(extension_str)
            for k, v in kv_pairs.items():
                extracted[k] = v
        else:
            extracted["raw_cef"] = text

        # Map common CEF abbreviations
        if "src" in extracted:
            extracted["src_ip"] = extracted["src"]
        if "dst" in extracted:
            extracted["dst_ip"] = extracted["dst"]
        if "spt" in extracted:
            try:
                extracted["src_port"] = int(extracted["spt"])
            except ValueError:
                pass
        if "dpt" in extracted:
            try:
                extracted["dst_port"] = int(extracted["dpt"])
            except ValueError:
                pass
        if "proto" in extracted:
            extracted["protocol"] = str(extracted["proto"]).upper()
        if "act" in extracted:
            extracted["action"] = extracted["act"]

        for k, v in extracted.items():
            tokens.append({"key": k, "value": v, "type": type(v).__name__})

        vendor = extracted.get("device_vendor") or self.vendor
        product = extracted.get("device_product") or self.product

        return ULPFParsedEvent(
            event_id=raw_event.event_id,
            raw=raw_event.raw,
            parser_name=self.name,
            parser_vendor=str(vendor),
            parser_product=str(product),
            confidence_score=0.99,
            extracted_fields=extracted,
            tokens=tokens,
        )

    def _parse_extension(self, ext: str) -> Dict[str, Any]:
        """Parses CEF key=value extension string respecting spaces within quotes/values."""
        res: Dict[str, Any] = {}
        pattern = re.compile(r'(\w+)=((?:\\=|[^=])*)(?:\s+(?=\w+=)|$)')
        for match in pattern.finditer(ext):
            k = match.group(1).strip()
            v = match.group(2).strip()
            res[k] = v
        return res
