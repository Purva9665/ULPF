"""
Syslog & Linux / NGINX Log Parser
Handles RFC 5424 / RFC 3164 standard syslog, Linux iptables, and NGINX/Apache HTTP logs.
"""

import re
from typing import Tuple, Dict, Any, List
from backend.core.base_parser import BaseParser
from backend.core.models import ULPFRawEvent, ULPFParsedEvent


class SyslogGenericParser(BaseParser):
    name = "syslog_generic"
    vendor = "Linux / BSD / Generic"
    product = "Syslog Daemon"
    supported_formats = ["rfc5424", "rfc3164", "iptables", "nginx_combined"]
    description = "Parses standard RFC5424/3164 Syslog, Linux Netfilter/iptables, and Web Server logs"

    # RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
    RFC5424_REGEX = re.compile(
        r"^<(?P<pri>\d+)>(?P<version>\d+)\s+(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<app_name>\S+)\s+(?P<proc_id>\S+)\s+(?P<msg_id>\S+)\s*(?:\[(?P<structured_data>[^\]]+)\])?\s*(?P<msg>.*)$"
    )

    # RFC 3164: <PRI>Mmm dd hh:mm:ss hostname tag[pid]: message
    RFC3164_REGEX = re.compile(
        r"^<(?P<pri>\d+)>(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+[\d:]+)\s+(?P<hostname>[\w.-]+)\s+(?P<app_name>[\w.-]+)(?:\[(?P<proc_id>\d+)\])?:\s*(?P<msg>.*)$"
    )

    # Linux iptables: IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=... DPT=...
    IPTABLES_REGEX = re.compile(
        r"(?:\[\s*\d+\.\d+\]\s+)?(?:[\w.-]+:\s+)?(?P<prefix>[A-Za-z0-9_-]+:)?\s*IN=(?P<in_iface>[\w.-]*)\s+OUT=(?P<out_iface>[\w.-]*).*(?:SRC=(?P<src_ip>[\d.]+))\s+(?:DST=(?P<dst_ip>[\d.]+)).*(?:PROTO=(?P<protocol>\w+))(?:\s+SPT=(?P<src_port>\d+))?(?:\s+DPT=(?P<dst_port>\d+))?",
        re.IGNORECASE
    )

    # NGINX Combined Log: 1.2.3.4 - - [01/Sep/2026:01:00:00 +0000] "GET /api/v1/data HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
    NGINX_REGEX = re.compile(
        r'^(?P<src_ip>[\d.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<http_method>[A-Z]+)\s+(?P<http_uri>\S+)\s+(?P<http_version>[^"]+)"\s+(?P<status_code>\d+)\s+(?P<bytes>\d+)\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
    )

    def can_parse(self, raw_event: ULPFRawEvent) -> Tuple[bool, float]:
        text = raw_event.raw.payload.strip()
        if self.RFC5424_REGEX.match(text) or self.RFC3164_REGEX.match(text):
            return True, 0.90
        if "IN=" in text and "SRC=" in text and "DST=" in text:
            return True, 0.95
        if self.NGINX_REGEX.match(text):
            return True, 0.95
        if re.match(r"^[A-Z][a-z]{2}\s+\d+\s+[\d:]+\s+[\w.-]+", text):
            return True, 0.70
        return False, 0.0

    def parse(self, raw_event: ULPFRawEvent) -> ULPFParsedEvent:
        text = raw_event.raw.payload.strip()
        extracted: Dict[str, Any] = {}
        tokens: List[Dict[str, Any]] = []

        # 1. Test NGINX
        nginx_match = self.NGINX_REGEX.match(text)
        if nginx_match:
            extracted = nginx_match.groupdict()
            extracted["log_format"] = "nginx_combined"
            extracted["protocol"] = "HTTP"
            extracted["dst_port"] = 80 if extracted.get("http_uri", "").startswith("http:") else 443
            try:
                extracted["status_code"] = int(extracted["status_code"])
                extracted["bytes"] = int(extracted["bytes"])
            except ValueError:
                pass

        # 2. Test iptables
        elif "IN=" in text and "SRC=" in text and "DST=" in text:
            iptables_match = self.IPTABLES_REGEX.search(text)
            if iptables_match:
                extracted = {k: v for k, v in iptables_match.groupdict().items() if v is not None}
                extracted["log_format"] = "linux_iptables"
                extracted["action"] = "DROP" if "DROP" in text.upper() or "REJECT" in text.upper() else "ALLOW"
                if "src_port" in extracted:
                    extracted["src_port"] = int(extracted["src_port"])
                if "dst_port" in extracted:
                    extracted["dst_port"] = int(extracted["dst_port"])

        # 3. Test RFC 5424
        elif self.RFC5424_REGEX.match(text):
            m = self.RFC5424_REGEX.match(text)
            extracted = {k: v for k, v in m.groupdict().items() if v is not None}
            extracted["log_format"] = "rfc5424_syslog"

        # 4. Test RFC 3164
        elif self.RFC3164_REGEX.match(text):
            m = self.RFC3164_REGEX.match(text)
            extracted = {k: v for k, v in m.groupdict().items() if v is not None}
            extracted["log_format"] = "rfc3164_syslog"

        # Fallback: extract IPs and ports via regex
        else:
            ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
            if len(ip_matches) >= 2:
                extracted["src_ip"] = ip_matches[0]
                extracted["dst_ip"] = ip_matches[1]
            elif len(ip_matches) == 1:
                extracted["src_ip"] = ip_matches[0]
            extracted["raw_text"] = text

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
            confidence_score=0.85,
            extracted_fields=extracted,
            tokens=tokens,
        )
