"""
ULPF Normalization Engine (Stage 3)
Transforms heterogeneous extracted dictionary tokens into canonical ULPF schema without data loss.
"""

import time
import ipaddress
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timezone
from backend.core.models import (
    ULPFParsedEvent,
    ULPFNormalizedEvent,
    EventMetadata,
    NetworkEndpoint,
    NetworkDetails,
    ThreatDetails,
    ObserverDetails,
    ActionEnum,
    SeverityEnum,
)
from backend.normalizer.mappings import ACTION_MAP, SEVERITY_MAP, WELL_KNOWN_PORTS, FIELD_ALIASES


class NormalizationEngine:
    """
    Stage 3: NORMALIZATION
    Maps vendor-specific parsed keys into canonical schema namespaces.
    Unmapped vendor fields are retained in `unmapped_fields` for complete zero-loss preservation.
    """

    def __init__(self):
        pass

    def normalize(self, parsed_event: ULPFParsedEvent) -> ULPFNormalizedEvent:
        t0 = time.perf_counter_ns()
        fields = dict(parsed_event.extracted_fields)
        consumed_keys = set()

        # 1. Event Metadata
        action_val = self._find_first(fields, FIELD_ALIASES["event.action"], consumed_keys)
        canonical_action = self._normalize_action(action_val)

        severity_val = self._find_first(fields, FIELD_ALIASES["event.severity"], consumed_keys)
        canonical_severity = self._normalize_severity(severity_val)

        timestamp_val = self._extract_timestamp(fields, consumed_keys)

        event_meta = EventMetadata(
            id=parsed_event.event_id,
            ingested_at=datetime.now(timezone.utc).isoformat(),
            timestamp=timestamp_val,
            category=str(fields.get("category", "NETWORK_TRAFFIC")).upper(),
            type=str(fields.get("panos_log_type", fields.get("cisco_message_type", "FIREWALL_EVENT"))),
            action=canonical_action,
            severity=canonical_severity,
            status="NORMALIZED",
        )

        # 2. Source Endpoint
        src_ip = self._find_first(fields, FIELD_ALIASES["source.ip"], consumed_keys)
        src_port = self._find_first(fields, FIELD_ALIASES["source.port"], consumed_keys)
        src_pkts = self._find_first(fields, FIELD_ALIASES["source.packets"], consumed_keys)
        src_bytes = self._find_first(fields, FIELD_ALIASES["source.bytes"], consumed_keys)
        
        src_port_int = self._to_int(src_port)
        src_is_private = self._is_private_ip(src_ip)
        
        source = NetworkEndpoint(
            ip=str(src_ip) if src_ip else None,
            port=src_port_int,
            packets=self._to_int(src_pkts),
            bytes=self._to_int(src_bytes),
            service=WELL_KNOWN_PORTS.get(src_port_int) if src_port_int else None,
            geo={"is_private": src_is_private} if src_ip else {},
        )

        # 3. Destination Endpoint
        dst_ip = self._find_first(fields, FIELD_ALIASES["destination.ip"], consumed_keys)
        dst_port = self._find_first(fields, FIELD_ALIASES["destination.port"], consumed_keys)
        dst_pkts = self._find_first(fields, FIELD_ALIASES["destination.packets"], consumed_keys)
        dst_bytes = self._find_first(fields, FIELD_ALIASES["destination.bytes"], consumed_keys)

        dst_port_int = self._to_int(dst_port)
        dst_is_private = self._is_private_ip(dst_ip)

        destination = NetworkEndpoint(
            ip=str(dst_ip) if dst_ip else None,
            port=dst_port_int,
            packets=self._to_int(dst_pkts),
            bytes=self._to_int(dst_bytes),
            domain=fields.get("domain") or fields.get("query"),
            service=WELL_KNOWN_PORTS.get(dst_port_int) if dst_port_int else None,
            geo={"is_private": dst_is_private} if dst_ip else {},
        )

        # 4. Network Details
        protocol = self._find_first(fields, FIELD_ALIASES["network.protocol"], consumed_keys) or "TCP"
        session_id = self._find_first(fields, FIELD_ALIASES["network.session_id"], consumed_keys)
        total_bytes = self._find_first(fields, FIELD_ALIASES["network.bytes_total"], consumed_keys)
        total_pkts = self._find_first(fields, FIELD_ALIASES["network.packets_total"], consumed_keys)

        direction = self._calculate_direction(src_is_private, dst_is_private, fields.get("direction"))

        network = NetworkDetails(
            protocol=str(protocol).upper(),
            transport="IP",
            direction=direction,
            bytes_total=self._to_int(total_bytes) or ((source.bytes or 0) + (destination.bytes or 0) or None),
            packets_total=self._to_int(total_pkts) or ((source.packets or 0) + (destination.packets or 0) or None),
            session_id=str(session_id) if session_id else None,
            flags=str(fields.get("flags", "")) if "flags" in fields else None,
        )

        # 5. Threat Details
        threat_sig = self._find_first(fields, FIELD_ALIASES["threat.signature"], consumed_keys)
        threat_cat = self._find_first(fields, FIELD_ALIASES["threat.category"], consumed_keys)
        threat_ind = self._find_first(fields, FIELD_ALIASES["threat.indicator"], consumed_keys)
        
        threat: Optional[ThreatDetails] = None
        if threat_sig or threat_cat or threat_ind or canonical_severity in (SeverityEnum.HIGH, SeverityEnum.CRITICAL):
            threat = ThreatDetails(
                signature=str(threat_sig) if threat_sig else None,
                category=str(threat_cat) if threat_cat else "SECURITY_EVENT",
                indicator=str(threat_ind) if threat_ind else None,
                confidence=0.90 if threat_sig else 0.50,
            )

        # 6. Observer Details
        obs_host = self._find_first(fields, FIELD_ALIASES["observer.hostname"], consumed_keys)
        raw_ver = fields.get("device_version") or fields.get("version")
        observer = ObserverDetails(
            vendor=parsed_event.parser_vendor,
            product=parsed_event.parser_product,
            hostname=str(obs_host) if obs_host else None,
            version=str(raw_ver) if raw_ver is not None else None,
        )

        # 7. Unmapped fields container (Preserves every other vendor field)
        consumed_keys.update(["vendor", "product", "raw_text", "log_format"])
        unmapped = {k: v for k, v in fields.items() if k not in consumed_keys}

        t1 = time.perf_counter_ns()
        duration_us = (t1 - t0) // 1000

        return ULPFNormalizedEvent(
            event_id=parsed_event.event_id,
            raw=parsed_event.raw,
            event=event_meta,
            source=source,
            destination=destination,
            network=network,
            threat=threat,
            observer=observer,
            unmapped_fields=unmapped,
            mapping_rule_used="canonical_ulpf_v1",
            normalization_duration_us=duration_us,
        )

    def _find_first(self, fields: Dict[str, Any], candidate_keys: list, consumed_keys: set) -> Any:
        for k in candidate_keys:
            if k in fields and fields[k] is not None:
                consumed_keys.add(k)
                return fields[k]
        return None

    def _normalize_action(self, action_val: Any) -> ActionEnum:
        if not action_val:
            return ActionEnum.UNKNOWN
        clean = str(action_val).lower().strip()
        return ACTION_MAP.get(clean, ActionEnum.UNKNOWN)

    def _normalize_severity(self, severity_val: Any) -> SeverityEnum:
        if not severity_val:
            return SeverityEnum.INFORMATIONAL
        clean = str(severity_val).lower().strip()
        return SEVERITY_MAP.get(clean, SeverityEnum.INFORMATIONAL)

    def _to_int(self, val: Any) -> Optional[int]:
        if val is None:
            return None
        try:
            return int(val)
        except (ValueError, TypeError):
            return None

    def _is_private_ip(self, ip_str: Any) -> Optional[bool]:
        if not ip_str or not isinstance(ip_str, str):
            return None
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            return ip.is_private
        except ValueError:
            return None

    def _calculate_direction(self, src_priv: Optional[bool], dst_priv: Optional[bool], explicit_dir: Any) -> str:
        if explicit_dir and str(explicit_dir).upper() in ("INBOUND", "OUTBOUND", "INTERNAL"):
            return str(explicit_dir).upper()
        if src_priv is False and dst_priv is True:
            return "INBOUND"
        if src_priv is True and dst_priv is False:
            return "OUTBOUND"
        if src_priv is True and dst_priv is True:
            return "INTERNAL"
        return "EXTERNAL"

    def _extract_timestamp(self, fields: Dict[str, Any], consumed_keys: set) -> str:
        for k in ("timestamp_iso", "start_iso", "generated_time", "receive_time", "syslog_timestamp", "time", "date"):
            if k in fields and fields[k]:
                consumed_keys.add(k)
                return str(fields[k])
        return datetime.now(timezone.utc).isoformat()
