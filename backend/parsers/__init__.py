"""
ULPF Built-in Parser Plugin Suite
Registers all plug-and-play parsers into the default ParserRegistry.
"""

from backend.core.registry import default_registry
from backend.parsers.cisco_asa import CiscoASAParser
from backend.parsers.palo_alto import PaloAltoParser
from backend.parsers.suricata import SuricataParser
from backend.parsers.aws_vpc import AWSVPCFlowParser
from backend.parsers.zeek import ZeekParser
from backend.parsers.cef import CEFParser
from backend.parsers.keyvalue import KeyValueParser
from backend.parsers.syslog import SyslogGenericParser
from backend.parsers.windows import WindowsEventParser


def register_all_builtin_parsers() -> None:
    """Registers all standard perimeter network parsers into the global registry."""
    default_registry.register(CiscoASAParser())
    default_registry.register(PaloAltoParser())
    default_registry.register(SuricataParser())
    default_registry.register(AWSVPCFlowParser())
    default_registry.register(ZeekParser())
    default_registry.register(CEFParser())
    default_registry.register(KeyValueParser())
    default_registry.register(SyslogGenericParser())
    default_registry.register(WindowsEventParser())


# Auto-register on import
register_all_builtin_parsers()

__all__ = [
    "CiscoASAParser",
    "PaloAltoParser",
    "SuricataParser",
    "AWSVPCFlowParser",
    "ZeekParser",
    "CEFParser",
    "KeyValueParser",
    "SyslogGenericParser",
    "WindowsEventParser",
    "register_all_builtin_parsers",
]
