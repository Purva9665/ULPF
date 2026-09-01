"""
ULPF Validation & Data Quality Engine (Stage 4)
Performs schema conformance checks, constraint rules, integrity hash verification, and data quality scoring.
"""

import time
import ipaddress
import hashlib
from typing import List, Tuple
from backend.core.models import (
    ULPFNormalizedEvent,
    ULPFValidatedEvent,
    ValidationCheckResult,
)


class ValidationEngine:
    """
    Stage 4: VALIDATION
    Evaluates schema constraints, data types, cryptographic integrity, and computes Data Quality Index (DQI).
    """

    def __init__(self):
        pass

    def validate(self, normalized_event: ULPFNormalizedEvent) -> ULPFValidatedEvent:
        t0 = time.perf_counter_ns()
        checks: List[ValidationCheckResult] = []
        
        # 1. Cryptographic Raw Hash Integrity Check
        recomputed_hash = hashlib.sha256(normalized_event.raw.payload.encode("utf-8")).hexdigest()
        hash_verified = recomputed_hash == normalized_event.raw.sha256_hash
        checks.append(
            ValidationCheckResult(
                rule_name="crypto_raw_integrity_check",
                field_checked="raw.sha256_hash",
                passed=hash_verified,
                message="SHA-256 raw payload digest verified without corruption" if hash_verified else "Digest mismatch: potential payload mutation",
                severity="CRITICAL" if not hash_verified else "INFO",
            )
        )

        # 2. Source IP Validation
        src_ip = normalized_event.source.ip
        if src_ip:
            is_valid_ip = self._validate_ip(src_ip)
            checks.append(
                ValidationCheckResult(
                    rule_name="valid_source_ip_format",
                    field_checked="source.ip",
                    passed=is_valid_ip,
                    message=f"Source IP '{src_ip}' is valid" if is_valid_ip else f"Invalid IP format '{src_ip}'",
                    severity="HIGH" if not is_valid_ip else "INFO",
                )
            )
        else:
            checks.append(
                ValidationCheckResult(
                    rule_name="source_ip_presence",
                    field_checked="source.ip",
                    passed=False,
                    message="Source IP is absent in raw log",
                    severity="LOW",
                )
            )

        # 3. Destination IP Validation
        dst_ip = normalized_event.destination.ip
        if dst_ip:
            is_valid_ip = self._validate_ip(dst_ip)
            checks.append(
                ValidationCheckResult(
                    rule_name="valid_destination_ip_format",
                    field_checked="destination.ip",
                    passed=is_valid_ip,
                    message=f"Destination IP '{dst_ip}' is valid" if is_valid_ip else f"Invalid IP format '{dst_ip}'",
                    severity="HIGH" if not is_valid_ip else "INFO",
                )
            )
        else:
            checks.append(
                ValidationCheckResult(
                    rule_name="destination_ip_presence",
                    field_checked="destination.ip",
                    passed=False,
                    message="Destination IP is absent in raw log",
                    severity="LOW",
                )
            )

        # 4. Port Bounds Validation (0 - 65535)
        for field_name, port in [("source.port", normalized_event.source.port), ("destination.port", normalized_event.destination.port)]:
            if port is not None:
                valid_port = 0 <= port <= 65535
                checks.append(
                    ValidationCheckResult(
                        rule_name="port_range_bound_check",
                        field_checked=field_name,
                        passed=valid_port,
                        message=f"Port {port} is within valid 0-65535 range" if valid_port else f"Port {port} out of bounds",
                        severity="HIGH" if not valid_port else "INFO",
                    )
                )

        # 5. Non-negative Bytes and Packets
        for field_name, count in [
            ("network.bytes_total", normalized_event.network.bytes_total),
            ("network.packets_total", normalized_event.network.packets_total),
        ]:
            if count is not None:
                valid_count = count >= 0
                checks.append(
                    ValidationCheckResult(
                        rule_name="non_negative_metric_check",
                        field_checked=field_name,
                        passed=valid_count,
                        message=f"{field_name} value {count} is valid" if valid_count else f"Negative value {count} encountered",
                        severity="MEDIUM" if not valid_count else "INFO",
                    )
                )

        # 6. Action Enum Conformance
        action_valid = normalized_event.event.action.value != "UNKNOWN"
        checks.append(
            ValidationCheckResult(
                rule_name="action_enum_conformance",
                field_checked="event.action",
                passed=action_valid,
                message=f"Action '{normalized_event.event.action.value}' normalized" if action_valid else "Action is UNKNOWN",
                severity="LOW" if not action_valid else "INFO",
            )
        )

        # Calculate Data Quality Score (DQI)
        total_checks = len(checks)
        passed_checks = sum(1 for c in checks if c.passed)
        dqi_score = round((passed_checks / total_checks) * 100.0, 1) if total_checks > 0 else 100.0
        
        is_overall_valid = hash_verified and dqi_score >= 50.0

        t1 = time.perf_counter_ns()
        duration_us = (t1 - t0) // 1000

        return ULPFValidatedEvent(
            event_id=normalized_event.event_id,
            normalized=normalized_event,
            is_valid=is_overall_valid,
            data_quality_score=dqi_score,
            hash_verified=hash_verified,
            validation_checks=checks,
            validation_duration_us=duration_us,
        )

    def _validate_ip(self, ip_str: str) -> bool:
        try:
            ipaddress.ip_address(ip_str.strip())
            return True
        except ValueError:
            return False
