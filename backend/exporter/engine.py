"""
ULPF SIEM & Data Lake Exporter Engine (Stage 7)
Translates standardized ULPF events into Elastic ECS 8.x, Splunk HEC, OCSF v1.1, and Columnar Parquet schemas.
"""

from typing import Dict, Any
from backend.core.models import ULPFFinalEvent


class ExporterEngine:
    """
    Stage 7: EXPORT & SIEM / DATA-LAKE GATEWAY
    Produces production-ready SIEM, OCSF, and columnar outputs from canonical ULPF events.
    """

    def export_all(self, final_event: ULPFFinalEvent) -> Dict[str, Any]:
        """Export event to all standard enterprise schema formats."""
        return {
            "ulpf_standard": final_event.model_dump(),
            "elastic_ecs": self.to_elastic_ecs(final_event),
            "splunk_hec": self.to_splunk_hec(final_event),
            "ocsf_v1": self.to_ocsf(final_event),
            "columnar_flat": self.to_columnar_flat(final_event),
        }

    def to_elastic_ecs(self, fe: ULPFFinalEvent) -> Dict[str, Any]:
        """Transforms to Elastic Common Schema (ECS 8.x)."""
        ecs = {
            "@timestamp": fe.event.timestamp or fe.event.ingested_at,
            "ecs": {"version": "8.11.0"},
            "event": {
                "id": fe.event_id,
                "category": [fe.event.category.lower()],
                "type": ["connection"],
                "action": fe.event.action.value.lower(),
                "severity": self._severity_to_num(fe.event.severity.value),
                "outcome": "failure" if fe.event.action.value in ("DENY", "DROP", "REJECT") else "success",
            },
            "source": {
                "ip": fe.source.ip,
                "port": fe.source.port,
                "bytes": fe.source.bytes,
                "packets": fe.source.packets,
            },
            "destination": {
                "ip": fe.destination.ip,
                "port": fe.destination.port,
                "bytes": fe.destination.bytes,
                "packets": fe.destination.packets,
                "domain": fe.destination.domain,
            },
            "network": {
                "transport": fe.network.protocol.lower(),
                "direction": fe.network.direction.lower(),
                "bytes": fe.network.bytes_total,
                "packets": fe.network.packets_total,
            },
            "observer": {
                "vendor": fe.observer.vendor,
                "product": fe.observer.product,
                "hostname": fe.observer.hostname,
            },
            "labels": {
                "ulpf_anomaly_score": str(fe.ml_analysis.anomaly_score),
                "ulpf_risk_level": fe.ml_analysis.risk_level.value,
                "ulpf_data_quality_score": str(fe.validation.get("data_quality_score", 100)),
            },
            "message": fe.raw_event.payload,
        }
        if fe.threat:
            ecs["threat"] = {
                "indicator": {"name": fe.threat.indicator},
                "technique": {"id": fe.threat.mitre_technique_id} if fe.threat.mitre_technique_id else None,
            }
        return ecs

    def to_splunk_hec(self, fe: ULPFFinalEvent) -> Dict[str, Any]:
        """Transforms to Splunk HTTP Event Collector (HEC) JSON envelope."""
        return {
            "time": fe.event.timestamp or fe.event.ingested_at,
            "host": fe.observer.hostname or "ulpf-sensor-01",
            "source": f"ulpf:{fe.observer.product.lower().replace(' ', '_')}",
            "sourcetype": f"ulpf:{fe.observer.vendor.lower()}:{fe.observer.product.lower().replace(' ', '_')}",
            "index": "security_perimeter",
            "event": {
                "event_id": fe.event_id,
                "action": fe.event.action.value,
                "severity": fe.event.severity.value,
                "src_ip": fe.source.ip,
                "src_port": fe.source.port,
                "dest_ip": fe.destination.ip,
                "dest_port": fe.destination.port,
                "protocol": fe.network.protocol,
                "bytes": fe.network.bytes_total,
                "anomaly_score": fe.ml_analysis.anomaly_score,
                "is_anomalous": fe.ml_analysis.is_anomalous,
                "raw_hash": fe.raw_event.sha256_hash,
                "unmapped": fe.unmapped_fields,
            }
        }

    def to_ocsf(self, fe: ULPFFinalEvent) -> Dict[str, Any]:
        """Transforms to Open Cybersecurity Schema Framework (OCSF v1.1 Network Activity)."""
        return {
            "class_uid": 4001,
            "class_name": "Network Activity",
            "category_uid": 4,
            "category_name": "Network Activity",
            "time": fe.event.timestamp or fe.event.ingested_at,
            "activity_id": 1 if fe.event.action.value == "ALLOW" else 2,
            "severity_id": self._severity_to_ocsf_id(fe.event.severity.value),
            "status": fe.event.action.value,
            "src_endpoint": {
                "ip": fe.source.ip,
                "port": fe.source.port,
                "intermediate": False,
            },
            "dst_endpoint": {
                "ip": fe.destination.ip,
                "port": fe.destination.port,
                "hostname": fe.destination.domain,
            },
            "connection_info": {
                "protocol_name": fe.network.protocol,
                "direction": fe.network.direction,
                "uid": fe.network.session_id,
            },
            "traffic": {
                "bytes": fe.network.bytes_total,
                "packets": fe.network.packets_total,
            },
            "device": {
                "vendor_name": fe.observer.vendor,
                "product_name": fe.observer.product,
                "hostname": fe.observer.hostname,
            },
            "enrichments": [
                {
                    "name": "ULPF Machine Learning Analytics",
                    "value": f"Anomaly Score: {fe.ml_analysis.anomaly_score:.2f}, Risk: {fe.ml_analysis.risk_level.value}",
                }
            ],
            "raw_data": fe.raw_event.payload,
        }

    def to_columnar_flat(self, fe: ULPFFinalEvent) -> Dict[str, Any]:
        """Produces a flat dictionary ready for Parquet / Arrow / DuckDB columnar ingestion."""
        return {
            "event_id": fe.event_id,
            "timestamp": fe.event.timestamp or fe.event.ingested_at,
            "ingested_at": fe.event.ingested_at,
            "vendor": fe.observer.vendor,
            "product": fe.observer.product,
            "action": fe.event.action.value,
            "severity": fe.event.severity.value,
            "src_ip": fe.source.ip,
            "src_port": fe.source.port,
            "src_bytes": fe.source.bytes,
            "dst_ip": fe.destination.ip,
            "dst_port": fe.destination.port,
            "dst_bytes": fe.destination.bytes,
            "protocol": fe.network.protocol,
            "direction": fe.network.direction,
            "bytes_total": fe.network.bytes_total,
            "anomaly_score": fe.ml_analysis.anomaly_score,
            "is_anomalous": 1 if fe.ml_analysis.is_anomalous else 0,
            "shannon_entropy": fe.ml_analysis.shannon_entropy,
            "data_quality_score": fe.validation.get("data_quality_score", 100.0),
            "raw_sha256": fe.raw_event.sha256_hash,
            "raw_bytes": fe.raw_event.length_bytes,
        }

    def _severity_to_num(self, sev: str) -> int:
        return {"INFORMATIONAL": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}.get(sev, 1)

    def _severity_to_ocsf_id(self, sev: str) -> int:
        return {"INFORMATIONAL": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}.get(sev, 1)
