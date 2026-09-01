"""
Base Parser Interface for Plug-and-Play Architecture
"""

from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any, List
import time
from backend.core.models import ULPFRawEvent, ULPFParsedEvent


class BaseParser(ABC):
    """
    Abstract base class for all log parsers in ULPF.
    Enables plug-and-play addition of new parsers without modifying core pipeline code.
    """
    
    name: str = "base_parser"
    vendor: str = "Generic"
    product: str = "Generic Log"
    supported_formats: List[str] = ["text"]
    description: str = "Base parser interface"

    @abstractmethod
    def can_parse(self, raw_event: ULPFRawEvent) -> Tuple[bool, float]:
        """
        Evaluate if this parser can handle the given raw event.
        
        Returns:
            Tuple[bool, float]: (can_parse, confidence_score between 0.0 and 1.0)
        """
        pass

    @abstractmethod
    def parse(self, raw_event: ULPFRawEvent) -> ULPFParsedEvent:
        """
        Parse the raw event into structured extracted fields and AST tokens.
        
        Returns:
            ULPFParsedEvent containing all extracted fields, tokens, and parser metadata.
        """
        pass

    def execute_parse(self, raw_event: ULPFRawEvent) -> ULPFParsedEvent:
        """
        Wrapper around parse() measuring microsecond duration and guaranteeing contract adherence.
        """
        t0 = time.perf_counter_ns()
        parsed = self.parse(raw_event)
        t1 = time.perf_counter_ns()
        duration_us = (t1 - t0) // 1000
        parsed.parsing_duration_us = duration_us
        return parsed
