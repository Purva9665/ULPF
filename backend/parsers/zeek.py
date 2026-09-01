"""
Zeek (Bro) Network Monitor Log Parser
Handles Zeek TSV / JSON logs for conn, dns, http, and ssl analyzers.
"""

import json
from typing import Tuple, Dict, Any, List
from datetime import datetime, timezone
from backend.core.base_parser import BaseParser
from backend.core.models import ULPFRawEvent, ULPFParsedEvent


class ZeekParser(BaseParser):
    name = "zeek_network_security"
    vendor = "Zeek / Bro"
    product = "Network Security Monitor"
    supported_formats = ["zeek_tsv", "zeek_json", "conn.log", "dns.log"]
    description = "Parses Zeek (Bro) connection, DNS, HTTP, and SSL records"

    # Default conn.log fields
    CONN_FIELDS = [
        "ts", "uid", "id_orig_h", "id_orig_p", "id_resp_h", "id_resp_p",
        "proto", "service", "duration", "orig_bytes", "resp_bytes",
        "conn_state", "local_orig", "local_resp", "missed_bytes",
        "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
        "tunnel_parents"
    ]

    def can_parse(self, raw_event: ULPFRawEvent) -> Tuple[bool, float]:
        text = raw_event.raw.payload.strip()
        # Check for tab separation
        tabs = text.count("\t")
        if tabs >= 6:
            parts = text.split("\t")
            # Check for float timestamp as first field (e.g. 1620000000.123456)
            try:
                float(parts[0])
                if len(parts[1]) >= 8:  # Zeek UID like CAbcDeFgHiJkLmNo
                    return True, 0.95
            except ValueError:
                pass
        if text.startswith("{") and '"id.orig_h"' in text:
            return True, 0.98
        return False, 0.0

    def parse(self, raw_event: ULPFRawEvent) -> ULPFParsedEvent:
        text = raw_event.raw.payload.strip()
        extracted: Dict[str, Any] = {}
        tokens: List[Dict[str, Any]] = []

        if text.startswith("{") and text.endswith("}"):
            try:
                data = json.loads(text)
                for k, v in data.items():
                    clean_k = k.replace(".", "_")
                    extracted[clean_k] = v
            except Exception:
                pass
        else:
            parts = text.split("\t")
            for idx, val in enumerate(parts):
                if idx < len(self.CONN_FIELDS):
                    key = self.CONN_FIELDS[idx]
                    if val != "-":
                        if key in ("id_orig_p", "id_resp_p", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes"):
                            try:
                                extracted[key] = int(val)
                            except ValueError:
                                extracted[key] = val
                        elif key in ("ts", "duration"):
                            try:
                                extracted[key] = float(val)
                            except ValueError:
                                extracted[key] = val
                        else:
                            extracted[key] = val

        # Standardize source / dest key names
        if "id_orig_h" in extracted:
            extracted["src_ip"] = extracted["id_orig_h"]
        if "id_orig_p" in extracted:
            extracted["src_port"] = extracted["id_orig_p"]
        if "id_resp_h" in extracted:
            extracted["dst_ip"] = extracted["id_resp_h"]
        if "id_resp_p" in extracted:
            extracted["dst_port"] = extracted["id_resp_p"]
        if "proto" in extracted:
            extracted["protocol"] = str(extracted["proto"]).upper()

        if "ts" in extracted and isinstance(extracted["ts"], (int, float)):
            try:
                extracted["timestamp_iso"] = datetime.fromtimestamp(extracted["ts"], timezone.utc).isoformat()
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
            confidence_score=0.95,
            extracted_fields=extracted,
            tokens=tokens,
        )
