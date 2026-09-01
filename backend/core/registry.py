"""
Parser Registry for Dynamic Plug-and-Play Extensibility
"""

from typing import Dict, List, Type, Tuple, Optional, Any, Union
from backend.core.base_parser import BaseParser
from backend.core.models import ULPFRawEvent, ULPFParsedEvent


class ParserRegistry:
    """
    Central registry managing all log parsers.
    Supports auto-detection, priority resolution, and dynamic parser registration.
    """
    
    def __init__(self):
        self._parsers: Dict[str, BaseParser] = {}

    def register(self, parser_instance_or_class: Union[BaseParser, Type[BaseParser]]) -> None:
        """Register a parser plugin."""
        if isinstance(parser_instance_or_class, type):
            parser = parser_instance_or_class()
        else:
            parser = parser_instance_or_class
        
        self._parsers[parser.name] = parser

    def get_parser(self, name: str) -> Optional[BaseParser]:
        """Get a parser by its unique name."""
        return self._parsers.get(name)

    def list_parsers(self) -> List[Dict[str, Any]]:
        """List metadata for all registered parsers."""
        return [
            {
                "name": p.name,
                "vendor": p.vendor,
                "product": p.product,
                "supported_formats": p.supported_formats,
                "description": p.description,
            }
            for p in self._parsers.values()
        ]

    def auto_detect(self, raw_event: ULPFRawEvent) -> Tuple[Optional[BaseParser], float]:
        """
        Probe all registered parsers against the raw event.
        Returns the parser with the highest confidence score.
        """
        best_parser: Optional[BaseParser] = None
        best_confidence: float = 0.0

        for parser in self._parsers.values():
            try:
                can_parse, confidence = parser.can_parse(raw_event)
                if can_parse and confidence > best_confidence:
                    best_confidence = confidence
                    best_parser = parser
            except Exception:
                continue

        return best_parser, best_confidence

    def auto_detect_and_parse(self, raw_event: ULPFRawEvent) -> Tuple[ULPFParsedEvent, BaseParser, float]:
        """
        Auto-detect the matching parser and execute parsing.
        Falls back to generic parser if no high-confidence parser matches.
        """
        best_parser, confidence = self.auto_detect(raw_event)
        
        if best_parser is None or confidence < 0.1:
            # Fallback to generic key-value or raw fallback parser
            fallback = self.get_parser("generic_keyvalue") or self.get_parser("syslog_generic")
            if fallback:
                best_parser = fallback
                confidence = 0.2
            else:
                raise ValueError("No matching parser found and no fallback parser available in registry")

        parsed_event = best_parser.execute_parse(raw_event)
        parsed_event.confidence_score = confidence
        return parsed_event, best_parser, confidence

    def parse_with(self, raw_event: ULPFRawEvent, parser_name: str) -> ULPFParsedEvent:
        """Execute a specific parser explicitly by name."""
        parser = self.get_parser(parser_name)
        if not parser:
            raise ValueError(f"Parser '{parser_name}' is not registered in ParserRegistry")
        return parser.execute_parse(raw_event)


# Global default registry instance
default_registry = ParserRegistry()

def init_default_registry():
    """Ensures built-in parsers are loaded into default_registry."""
    from backend.parsers import register_all_builtin_parsers
    register_all_builtin_parsers()

# Lazy auto-initialize on first parser lookup if empty
_orig_get_parser = default_registry.get_parser
def _wrapped_get_parser(name: str):
    if not default_registry._parsers:
        init_default_registry()
    return _orig_get_parser(name)
default_registry.get_parser = _wrapped_get_parser

_orig_auto_detect = default_registry.auto_detect
def _wrapped_auto_detect(raw_event):
    if not default_registry._parsers:
        init_default_registry()
    return _orig_auto_detect(raw_event)
default_registry.auto_detect = _wrapped_auto_detect

_orig_list_parsers = default_registry.list_parsers
def _wrapped_list_parsers():
    if not default_registry._parsers:
        init_default_registry()
    return _orig_list_parsers()
default_registry.list_parsers = _wrapped_list_parsers
