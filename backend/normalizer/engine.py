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
    ExtractionMethod,
    FieldProvenance,
)
from backend.normalizer.mappings import (
    ACTION_MAP, SEVERITY_MAP, WELL_KNOWN_PORTS, FIELD_ALIASES,
    ASA_MNEMONIC_ACTION, ZEEK_CONN_STATE, IP_PROTOCOL_NUMBERS,
)
from backend.normalizer.taxonomy import default_classifier
from backend.normalizer.netscope import default_scope


class ProvenanceRecorder:
    """Accumulates per-field origin and confidence during one normalization.

    Confidence is not a single number for the event. It is per field, because
    a parser can be certain about the source IP it matched on a named capture
    group and uncertain about a port it recovered from a positional token.
    Collapsing those into one event-level score - which is all any wire format
    between a pipeline and a SIEM can carry - is exactly the information loss
    this class exists to prevent.

    Confidence is derived from two things:

    * **The parser's own confidence in the event.** A low-confidence parse
      cannot yield high-confidence fields.
    * **Alias specificity.** `FIELD_ALIASES` lists candidate keys in order of
      decreasing specificity: the first entries are the vendor's own field
      names, later ones are generic fallbacks. A value matched on `src_ip` is
      better evidence than the same value matched on a generic `ip`, and the
      match position is a free, honest measure of that.
    """

    #: Confidence floor from alias fallback alone. A late-alias match is
    #: weaker evidence, not worthless evidence.
    MIN_ALIAS_CONFIDENCE = 0.75

    def __init__(self, parser_name: str, parser_confidence: float):
        self.parser_name = parser_name
        self.parser_confidence = max(0.0, min(1.0, float(parser_confidence)))
        self.records: Dict[str, FieldProvenance] = {}

    def extracted(self, path: str, source_key: str, alias_rank: int = 0) -> None:
        penalty = max(self.MIN_ALIAS_CONFIDENCE, 1.0 - 0.05 * alias_rank)
        note = None
        if alias_rank > 0:
            note = (f"matched on fallback alias '{source_key}' "
                    f"(rank {alias_rank}), not the vendor's primary field name")
        self.records[path] = FieldProvenance(
            source_key=source_key,
            parser=self.parser_name,
            method=ExtractionMethod.EXTRACTED,
            confidence=round(self.parser_confidence * penalty, 4),
            note=note,
        )

    def derived(self, path: str, note: str, confidence: float = 0.9) -> None:
        self.records[path] = FieldProvenance(
            source_key=None,
            parser=self.parser_name,
            method=ExtractionMethod.DERIVED,
            confidence=round(self.parser_confidence * confidence, 4),
            note=note,
        )

    def inferred(self, path: str, note: str, confidence: float = 0.6) -> None:
        self.records[path] = FieldProvenance(
            source_key=None,
            parser=self.parser_name,
            method=ExtractionMethod.INFERRED,
            confidence=round(self.parser_confidence * confidence, 4),
            note=note,
        )

    def defaulted(self, path: str, note: str, confidence: float = 0.3) -> None:
        """Record that the source carried nothing and a default was applied.

        This is the case that matters most. A field silently defaulted looks
        identical downstream to one the device actually reported, and a
        detector relying on it is reasoning about an assumption made in our
        own code rather than about anything the device observed.
        """
        self.records[path] = FieldProvenance(
            source_key=None,
            parser=self.parser_name,
            method=ExtractionMethod.DEFAULTED,
            confidence=round(confidence, 4),
            note=note,
        )


class NormalizationEngine:
    """
    Stage 3: NORMALIZATION
    Maps vendor-specific parsed keys into canonical schema namespaces.
    Unmapped vendor fields are retained in `unmapped_fields` for complete zero-loss preservation.
    Per-field origin and confidence are recorded in `field_provenance`.
    """

    def __init__(self):
        pass

    def normalize(self, parsed_event: ULPFParsedEvent) -> ULPFNormalizedEvent:
        t0 = time.perf_counter_ns()
        fields = dict(parsed_event.extracted_fields)
        consumed_keys = set()
        rec = ProvenanceRecorder(
            parser_name=parsed_event.parser_name,
            parser_confidence=parsed_event.confidence_score,
        )

        # 1. Event Metadata
        action_val = self._find(fields, "event.action", consumed_keys, rec)
        canonical_action = self._normalize_action(action_val)
        if canonical_action is ActionEnum.UNKNOWN:
            canonical_action = self._action_from_vendor_code(fields, consumed_keys)

        severity_val = self._find(fields, "event.severity", consumed_keys, rec)
        canonical_severity = self._normalize_severity(severity_val)

        timestamp_val = self._extract_timestamp(fields, consumed_keys)

        event_meta = EventMetadata(
            id=parsed_event.event_id,
            ingested_at=datetime.now(timezone.utc).isoformat(),
            timestamp=timestamp_val,
            category="unclassified",  # replaced below by the taxonomy classifier
            type=str(fields.get("panos_log_type", fields.get("cisco_message_type", "FIREWALL_EVENT"))),
            action=canonical_action,
            severity=canonical_severity,
            status="NORMALIZED",
        )

        # 2. Source Endpoint
        src_ip = self._find(fields, "source.ip", consumed_keys, rec)
        src_port = self._find(fields, "source.port", consumed_keys, rec)
        src_pkts = self._find(fields, "source.packets", consumed_keys, rec)
        src_bytes = self._find(fields, "source.bytes", consumed_keys, rec)
        
        src_port_int = self._to_int(src_port)
        src_is_private = default_scope.is_internal(src_ip)
        
        source = NetworkEndpoint(
            ip=str(src_ip) if src_ip else None,
            port=src_port_int,
            packets=self._to_int(src_pkts),
            bytes=self._to_int(src_bytes),
            service=WELL_KNOWN_PORTS.get(src_port_int) if src_port_int else None,
            geo={"is_internal": src_is_private, "scope": default_scope.scope_of(src_ip)} if src_ip else {},
        )

        # 3. Destination Endpoint
        dst_ip = self._find(fields, "destination.ip", consumed_keys, rec)
        dst_port = self._find(fields, "destination.port", consumed_keys, rec)
        dst_pkts = self._find(fields, "destination.packets", consumed_keys, rec)
        dst_bytes = self._find(fields, "destination.bytes", consumed_keys, rec)

        dst_port_int = self._to_int(dst_port)
        dst_is_private = default_scope.is_internal(dst_ip)

        destination = NetworkEndpoint(
            ip=str(dst_ip) if dst_ip else None,
            port=dst_port_int,
            packets=self._to_int(dst_pkts),
            bytes=self._to_int(dst_bytes),
            domain=fields.get("domain") or fields.get("query"),
            service=WELL_KNOWN_PORTS.get(dst_port_int) if dst_port_int else None,
            geo={"is_internal": dst_is_private, "scope": default_scope.scope_of(dst_ip)} if dst_ip else {},
        )

        # 4. Network Details
        protocol = self._find(fields, "network.protocol", consumed_keys, rec)
        # FortiGate, PAN-OS and NetFlow-derived sources report the protocol as
        # an IANA number. Stored verbatim it becomes the literal string "6",
        # which matches nothing downstream - not the taxonomy classifier, not
        # the routing rules, not an analyst's query.
        if protocol is not None:
            resolved = self._protocol_from_number(protocol)
            if resolved is not None:
                rec.derived(
                    "network.protocol",
                    f"resolved IANA protocol number {protocol} to {resolved}",
                    confidence=0.98,
                )
                protocol = resolved
        if not protocol:
            # The source carried no protocol. TCP is the right guess for
            # perimeter traffic but it remains a guess, and a detector that
            # keys on protocol deserves to know that.
            protocol = "TCP"
            rec.defaulted(
                "network.protocol",
                "source carried no protocol field; defaulted to TCP",
            )
        session_id = self._find(fields, "network.session_id", consumed_keys, rec)
        total_bytes = self._find(fields, "network.bytes_total", consumed_keys, rec)
        total_pkts = self._find(fields, "network.packets_total", consumed_keys, rec)

        explicit_direction = fields.get("direction")
        direction = default_scope.direction(src_ip, dst_ip, explicit_direction)
        if explicit_direction:
            rec.extracted("network.direction", source_key="direction")
        elif src_ip and dst_ip:
            rec.derived(
                "network.direction",
                "computed from source and destination address scope",
            )
        else:
            rec.inferred(
                "network.direction",
                "one or both addresses missing; direction is a partial inference",
                confidence=0.4,
            )

        bytes_total = self._to_int(total_bytes)
        if not bytes_total:
            bytes_total = (source.bytes or 0) + (destination.bytes or 0) or None
            if bytes_total:
                rec.derived("network.bytes_total",
                            "summed from source and destination byte counts")
        packets_total = self._to_int(total_pkts)
        if not packets_total:
            packets_total = (source.packets or 0) + (destination.packets or 0) or None
            if packets_total:
                rec.derived("network.packets_total",
                            "summed from source and destination packet counts")

        # A service name resolved from a port number is an inference about what
        # is listening, not an observation of it. Port 8080 is very often not
        # HTTP proxy traffic.
        if destination.service:
            rec.inferred("destination.service",
                         f"inferred from destination port {destination.port}")
        if source.service:
            rec.inferred("source.service",
                         f"inferred from source port {source.port}")

        network = NetworkDetails(
            protocol=str(protocol).upper(),
            transport="IP",
            direction=direction,
            bytes_total=bytes_total,
            packets_total=packets_total,
            session_id=str(session_id) if session_id else None,
            flags=str(fields.get("flags", "")) if "flags" in fields else None,
        )

        # 5. Threat Details
        threat_sig = self._find(fields, "threat.signature", consumed_keys, rec)
        threat_cat = self._find(fields, "threat.category", consumed_keys, rec)
        threat_ind = self._find(fields, "threat.indicator", consumed_keys, rec)
        
        threat: Optional[ThreatDetails] = None
        if threat_sig or threat_cat or threat_ind or canonical_severity in (SeverityEnum.HIGH, SeverityEnum.CRITICAL):
            threat = ThreatDetails(
                signature=str(threat_sig) if threat_sig else None,
                category=str(threat_cat) if threat_cat else "SECURITY_EVENT",
                indicator=str(threat_ind) if threat_ind else None,
                confidence=0.90 if threat_sig else 0.50,
            )

        # 5b. Canonical taxonomy classification (requirement c)
        classification = default_classifier.classify(
            action=canonical_action.value,
            severity=canonical_severity.value,
            dst_port=destination.port,
            src_port=source.port,
            protocol=network.protocol,
            direction=network.direction,
            app=str(fields.get("app") or fields.get("service") or destination.service or ""),
            threat_signature=str(threat_sig) if threat_sig else "",
            threat_category=str(threat_cat) if threat_cat else "",
            vendor_event_type=str(
                fields.get("panos_log_type")
                or fields.get("threat_content_type")
                or fields.get("mnemonic")
                or fields.get("event_type")
                or ""
            ),
            uri=str(
                fields.get("http_uri") or fields.get("url") or fields.get("request")
                or fields.get("uri") or fields.get("request_url") or ""
            ),
            windows_event_id=self._to_int(fields.get("windows_event_id")),
            src_is_internal=src_is_private,
            dst_is_internal=dst_is_private,
        )
        event_meta.category = classification.threat_class.value
        if classification.mitre_techniques and threat is not None:
            threat.mitre_technique_id = classification.mitre_techniques[0]

        # 6. Observer Details
        obs_host = self._find(fields, "observer.hostname", consumed_keys, rec)
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
            classification=classification.as_dict(),
            source=source,
            destination=destination,
            network=network,
            threat=threat,
            observer=observer,
            unmapped_fields=unmapped,
            field_provenance=rec.records,
            mapping_rule_used="canonical_ulpf_v1",
            normalization_duration_us=duration_us,
        )

    @staticmethod
    def _protocol_from_number(value: Any) -> Optional[str]:
        """Resolve an IANA protocol number to its canonical name.

        Returns None when the value is not a bare number, so a source that
        already reports "TCP" passes through untouched.
        """
        text = str(value).strip()
        if not text.isdigit():
            return None
        return IP_PROTOCOL_NUMBERS.get(int(text))

    def _find(
        self,
        fields: Dict[str, Any],
        path: str,
        consumed_keys: set,
        rec: "ProvenanceRecorder",
    ) -> Any:
        """Alias-resolving lookup that records where the value came from.

        Identical resolution behaviour to `_find_first`; the difference is that
        it knows the canonical path it is filling and the rank of the alias it
        matched, which is what makes per-field confidence computable.
        """
        for rank, k in enumerate(FIELD_ALIASES[path]):
            if k in fields and fields[k] is not None:
                consumed_keys.add(k)
                rec.extracted(path, source_key=k, alias_rank=rank)
                return fields[k]
        return None

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
        """Deprecated alias. Use netscope.default_scope.is_internal - Python's
        ipaddress.is_private counts RFC 5737 documentation ranges as private,
        which mislabels external hosts in almost every vendor sample log."""
        return default_scope.is_internal(ip_str)

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

    def _action_from_vendor_code(self, fields: Dict[str, Any], consumed_keys: set) -> ActionEnum:
        """Recover the action from vendor status codes for devices that never
        emit a literal action word (Cisco ASA mnemonics, Zeek conn_state)."""
        mnemonic = str(fields.get("mnemonic", "")).strip()
        if mnemonic in ASA_MNEMONIC_ACTION:
            resolved = ASA_MNEMONIC_ACTION[mnemonic]
            if resolved is not ActionEnum.UNKNOWN:
                consumed_keys.add("mnemonic")
                return resolved

        conn_state = str(fields.get("conn_state", "")).strip().upper()
        if conn_state in ZEEK_CONN_STATE:
            consumed_keys.add("conn_state")
            return ZEEK_CONN_STATE[conn_state][0]

        return ActionEnum.UNKNOWN

    def _extract_timestamp(self, fields: Dict[str, Any], consumed_keys: set) -> str:
        for k in ("timestamp_iso", "start_iso", "generated_time", "receive_time", "syslog_timestamp", "time", "date"):
            if k in fields and fields[k]:
                consumed_keys.add(k)
                return str(fields[k])
        return datetime.now(timezone.utc).isoformat()
