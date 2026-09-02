"""
Palo Alto Networks PAN-OS Log Parser
Handles PAN-OS CSV and Syslog formats for TRAFFIC, THREAT, and SYSTEM logs.
"""

import csv
import io
import re
from typing import Tuple, Dict, Any, List
from backend.core.base_parser import BaseParser
from backend.core.models import ULPFRawEvent, ULPFParsedEvent


def row_len_ok(actual: int, expected: int) -> bool:
    """PAN-OS only ever appends columns across releases, so extra trailing
    fields are expected; missing ones are not."""
    return actual >= expected


class PaloAltoParser(BaseParser):
    name = "palo_alto_panos"
    vendor = "Palo Alto Networks"
    product = "PAN-OS Next-Gen Firewall"
    supported_formats = ["panos_csv", "syslog_panos", "panos_threat", "panos_traffic"]
    description = "Parses Palo Alto Networks PAN-OS CSV and Syslog log streams"

    # PAN-OS 9.x/10.x Traffic Log Header specification
    TRAFFIC_FIELDS = [
        "future_use_1", "receive_time", "serial_number", "type", "threat_content_type",
        "future_use_2", "generated_time", "src_ip", "dst_ip", "nat_src_ip", "nat_dst_ip",
        "rule_name", "src_user", "dst_user", "app", "vsys", "from_zone", "to_zone",
        "ingress_interface", "egress_interface", "log_forwarding_profile", "future_use_3",
        "session_id", "repeat_count", "src_port", "dst_port", "nat_src_port", "nat_dst_port",
        "flags", "protocol", "action", "bytes", "bytes_sent", "bytes_received", "packets",
        "start_time", "elapsed_time", "category", "future_use_4", "seqno", "action_flags",
        "src_location", "dst_location", "future_use_5", "pkts_sent", "pkts_received",
        "session_end_reason", "device_group_hierarchy_level_1", "device_group_hierarchy_level_2",
        "device_group_hierarchy_level_3", "device_group_hierarchy_level_4", "vsys_name",
        "device_name", "action_source"
    ]

    # PAN-OS Threat Log Header specification
    THREAT_FIELDS = [
        "future_use_1", "receive_time", "serial_number", "type", "threat_content_type",
        "future_use_2", "generated_time", "src_ip", "dst_ip", "nat_src_ip", "nat_dst_ip",
        "rule_name", "src_user", "dst_user", "app", "vsys", "from_zone", "to_zone",
        "ingress_interface", "egress_interface", "log_forwarding_profile", "future_use_3",
        "session_id", "repeat_count", "src_port", "dst_port", "nat_src_port", "nat_dst_port",
        "flags", "protocol", "action", "misc", "threat_id", "category", "severity",
        "direction", "seqno", "action_flags", "src_location", "dst_location", "future_use_4",
        "content_type", "pcap_id", "filedigest", "cloud", "url_idx", "user_agent",
        "file_type", "xff", "referer", "sender", "subject", "recipient", "report_id",
        "device_group_hierarchy_level_1", "device_group_hierarchy_level_2",
        "device_group_hierarchy_level_3", "device_group_hierarchy_level_4", "vsys_name",
        "device_name"
    ]

    #: Minimum column count PAN-OS emits per log type. PAN-OS appends fields in
    #: later releases, so a longer row is fine; a shorter one means the row is
    #: truncated or a column is missing and positions cannot be trusted.
    EXPECTED_ARITY = {"TRAFFIC": 47, "THREAT": 53}

    def can_parse(self, raw_event: ULPFRawEvent) -> Tuple[bool, float]:
        text = raw_event.raw.payload
        if "TRAFFIC," in text or "THREAT," in text or "SYSTEM," in text:
            # Check for comma density
            if text.count(",") >= 15:
                return True, 0.95
        if re.search(r"\b1,\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2},\d+,(?:TRAFFIC|THREAT|SYSTEM)", text):
            return True, 0.98
        return False, 0.0

    def parse(self, raw_event: ULPFRawEvent) -> ULPFParsedEvent:
        text = raw_event.raw.payload.strip()
        extracted: Dict[str, Any] = {}
        tokens: List[Dict[str, Any]] = []

        # Strip any syslog prefix if present (e.g. "<14>1 2026-09-01T... PA-5220 1,2026/09/01...")
        csv_start = text.find("1,20")
        if csv_start == -1:
            csv_start = text.find("TRAFFIC,")
            if csv_start != -1:
                # Find start of line
                prev_comma = text[:csv_start].rfind(",")
                csv_start = 0 if prev_comma == -1 else prev_comma + 1
        if csv_start == -1:
            # Check for generic comma split
            csv_payload = text
        else:
            csv_payload = text[csv_start:]

        try:
            reader = csv.reader(io.StringIO(csv_payload))
            row = next(reader)
        except Exception:
            row = [f.strip() for f in csv_payload.split(",")]

        # Determine log type (TRAFFIC vs THREAT)
        log_type = "TRAFFIC"
        if len(row) > 3 and row[3].upper() in ("THREAT", "TRAFFIC", "SYSTEM", "CONFIG"):
            log_type = row[3].upper()
        elif any("THREAT" in str(x).upper() for x in row[:6]):
            log_type = "THREAT"

        fields_spec = self.THREAT_FIELDS if log_type == "THREAT" else self.TRAFFIC_FIELDS

        # Positional CSV parsing is only safe if the row arity is what the spec
        # expects. A single missing column silently shifts every field after it,
        # so a PAN-OS traffic log can report the byte count as the action. Detect
        # that here and degrade confidence rather than emit plausible-looking
        # but wrong values.
        expected = self.EXPECTED_ARITY.get(log_type)
        arity_ok = expected is None or row_len_ok(len(row), expected)
        if not arity_ok:
            extracted["_parse_warning"] = (
                "PAN-OS {} row has {} columns; expected {}. Field alignment is "
                "not trustworthy.".format(log_type, len(row), expected)
            )

        for idx, val in enumerate(row):
            if idx < len(fields_spec):
                key = fields_spec[idx]
                val_clean = val.strip() if isinstance(val, str) else str(val)
                if not key.startswith("future_use") and val_clean != "":
                    # Cast integer fields
                    if key in ("src_port", "dst_port", "nat_src_port", "nat_dst_port", "bytes", "bytes_sent", "bytes_received", "packets", "pkts_sent", "pkts_received", "elapsed_time", "session_id"):
                        try:
                            extracted[key] = int(val_clean)
                        except ValueError:
                            extracted[key] = val_clean
                    else:
                        extracted[key] = val_clean

        extracted["panos_log_type"] = log_type
        extracted["_field_alignment_verified"] = arity_ok
        extracted["vendor"] = self.vendor
        extracted["product"] = self.product

        for k, v in extracted.items():
            tokens.append({"key": k, "value": v, "type": type(v).__name__})

        return ULPFParsedEvent(
            event_id=raw_event.event_id,
            raw=raw_event.raw,
            parser_name=self.name,
            parser_vendor=self.vendor,
            parser_product=self.product,
            confidence_score=0.98 if arity_ok else 0.45,
            extracted_fields=extracted,
            tokens=tokens,
        )
