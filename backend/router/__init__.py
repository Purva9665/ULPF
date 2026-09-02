"""ULPF Event Router - classifies events as SIEM-bound or Data Lake only."""
from .event_router import EventRouter, RoutingDecision, default_router

__all__ = ["EventRouter", "RoutingDecision", "default_router"]
