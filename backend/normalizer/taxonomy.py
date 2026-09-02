"""
ULPF Canonical Event Taxonomy (requirement c)

Maps heterogeneous vendor events onto two aligned classification axes:

  1. OCSF class  - what KIND of activity this is (Network Activity, DNS Activity,
     Authentication, ...). Aligned to the Open Cybersecurity Schema Framework so
     exported events can be consumed by OCSF-native platforms.

  2. ULPF threat class - what SECURITY MEANING the event carries (reconnaissance,
     credential attack, web exploit, benign traffic, ...). OCSF deliberately does
     not encode this; downstream routing and correlation need it, so ULPF derives
     it as a separate, explicitly-scored axis.

Design constraints:
  * Deterministic - identical input always yields identical classification.
  * Explainable   - every classification returns the evidence that produced it.
  * Declarative   - new sources are onboarded by adding rules to the tables below,
                    not by editing control flow (requirement e / i).
  * Honest        - when no rule matches with sufficient support the result is
                    UNCLASSIFIED with confidence 0.0, never a confident guess.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


# ----------------------------------------------------------------------------
# OCSF alignment
# ----------------------------------------------------------------------------

class OCSFCategory(int, Enum):
    """OCSF top-level category_uid values."""
    SYSTEM_ACTIVITY = 1
    FINDINGS = 2
    IAM = 3
    NETWORK_ACTIVITY = 4
    DISCOVERY = 5
    APPLICATION_ACTIVITY = 6


class OCSFClass(int, Enum):
    """OCSF class_uid values used by ULPF.

    Only the classes ULPF can actually populate from perimeter-device logs are
    listed. Adding a class here is safe; emitting one we cannot fill is not.
    """
    # Findings (2xxx)
    DETECTION_FINDING = 2004
    # IAM (3xxx)
    AUTHENTICATION = 3002
    # Network Activity (4xxx)
    NETWORK_ACTIVITY = 4001
    HTTP_ACTIVITY = 4002
    DNS_ACTIVITY = 4003
    DHCP_ACTIVITY = 4004
    RDP_ACTIVITY = 4005
    SMB_ACTIVITY = 4006
    SSH_ACTIVITY = 4007
    FTP_ACTIVITY = 4008
    EMAIL_ACTIVITY = 4009
    TUNNEL_ACTIVITY = 4013

    @property
    def category(self) -> OCSFCategory:
        return _CLASS_TO_CATEGORY[self]

    @property
    def label(self) -> str:
        return _CLASS_LABELS[self]


_CLASS_TO_CATEGORY: Dict[OCSFClass, OCSFCategory] = {
    OCSFClass.DETECTION_FINDING: OCSFCategory.FINDINGS,
    OCSFClass.AUTHENTICATION: OCSFCategory.IAM,
    OCSFClass.NETWORK_ACTIVITY: OCSFCategory.NETWORK_ACTIVITY,
    OCSFClass.HTTP_ACTIVITY: OCSFCategory.NETWORK_ACTIVITY,
    OCSFClass.DNS_ACTIVITY: OCSFCategory.NETWORK_ACTIVITY,
    OCSFClass.DHCP_ACTIVITY: OCSFCategory.NETWORK_ACTIVITY,
    OCSFClass.RDP_ACTIVITY: OCSFCategory.NETWORK_ACTIVITY,
    OCSFClass.SMB_ACTIVITY: OCSFCategory.NETWORK_ACTIVITY,
    OCSFClass.SSH_ACTIVITY: OCSFCategory.NETWORK_ACTIVITY,
    OCSFClass.FTP_ACTIVITY: OCSFCategory.NETWORK_ACTIVITY,
    OCSFClass.EMAIL_ACTIVITY: OCSFCategory.NETWORK_ACTIVITY,
    OCSFClass.TUNNEL_ACTIVITY: OCSFCategory.NETWORK_ACTIVITY,
}

_CLASS_LABELS: Dict[OCSFClass, str] = {
    OCSFClass.DETECTION_FINDING: "Detection Finding",
    OCSFClass.AUTHENTICATION: "Authentication",
    OCSFClass.NETWORK_ACTIVITY: "Network Activity",
    OCSFClass.HTTP_ACTIVITY: "HTTP Activity",
    OCSFClass.DNS_ACTIVITY: "DNS Activity",
    OCSFClass.DHCP_ACTIVITY: "DHCP Activity",
    OCSFClass.RDP_ACTIVITY: "RDP Activity",
    OCSFClass.SMB_ACTIVITY: "SMB Activity",
    OCSFClass.SSH_ACTIVITY: "SSH Activity",
    OCSFClass.FTP_ACTIVITY: "FTP Activity",
    OCSFClass.EMAIL_ACTIVITY: "Email Activity",
    OCSFClass.TUNNEL_ACTIVITY: "Tunnel Activity",
}


# ----------------------------------------------------------------------------
# ULPF threat taxonomy
# ----------------------------------------------------------------------------

class ThreatClass(str, Enum):
    """Security meaning of an event. Drives SIEM/Data-Lake routing."""
    UNCLASSIFIED = "unclassified"
    BENIGN_TRAFFIC = "benign_traffic"
    ADMINISTRATIVE = "administrative"
    POLICY_VIOLATION = "policy_violation"
    RECONNAISSANCE = "reconnaissance"
    NETWORK_ATTACK = "network_attack"
    AUTHENTICATION_ATTACK = "authentication_attack"
    WEB_EXPLOIT = "web_exploit"
    MALWARE = "malware"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    COMMAND_AND_CONTROL = "command_and_control"
    DENIAL_OF_SERVICE = "dos"


#: Threat classes that are security-relevant enough to warrant SIEM routing.
SECURITY_RELEVANT: frozenset = frozenset({
    ThreatClass.RECONNAISSANCE,
    ThreatClass.NETWORK_ATTACK,
    ThreatClass.AUTHENTICATION_ATTACK,
    ThreatClass.WEB_EXPLOIT,
    ThreatClass.MALWARE,
    ThreatClass.DATA_EXFILTRATION,
    ThreatClass.LATERAL_MOVEMENT,
    ThreatClass.PRIVILEGE_ESCALATION,
    ThreatClass.COMMAND_AND_CONTROL,
    ThreatClass.DENIAL_OF_SERVICE,
    ThreatClass.POLICY_VIOLATION,
})


@dataclass
class Evidence:
    """One observation that contributed to a classification."""
    signal: str          # which input produced this
    observed: Any        # the value seen
    contributes: str     # what it argues for
    weight: float        # 0.0 - 1.0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "signal": self.signal,
            "observed": self.observed,
            "contributes": self.contributes,
            "weight": round(self.weight, 3),
        }


@dataclass
class Classification:
    """Result of taxonomy classification for a single event."""
    ocsf_class: OCSFClass = OCSFClass.NETWORK_ACTIVITY
    threat_class: ThreatClass = ThreatClass.UNCLASSIFIED
    confidence: float = 0.0
    mitre_techniques: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)

    @property
    def ocsf_class_uid(self) -> int:
        return int(self.ocsf_class.value)

    @property
    def ocsf_category_uid(self) -> int:
        return int(self.ocsf_class.category.value)

    @property
    def is_security_relevant(self) -> bool:
        return self.threat_class in SECURITY_RELEVANT

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ocsf_class_uid": self.ocsf_class_uid,
            "ocsf_class_name": self.ocsf_class.label,
            "ocsf_category_uid": self.ocsf_category_uid,
            "ocsf_category_name": self.ocsf_class.category.name.replace("_", " ").title(),
            "threat_class": self.threat_class.value,
            "confidence": round(self.confidence, 3),
            "mitre_techniques": list(self.mitre_techniques),
            "is_security_relevant": self.is_security_relevant,
            "evidence": [e.as_dict() for e in self.evidence],
        }


# ----------------------------------------------------------------------------
# Declarative rule tables - onboarding a new source means editing these
# ----------------------------------------------------------------------------

#: Destination port -> (OCSF class, service label). Used for protocol identification.
PORT_TO_CLASS: Dict[int, Tuple[OCSFClass, str]] = {
    21:    (OCSFClass.FTP_ACTIVITY, "FTP"),
    22:    (OCSFClass.SSH_ACTIVITY, "SSH"),
    25:    (OCSFClass.EMAIL_ACTIVITY, "SMTP"),
    53:    (OCSFClass.DNS_ACTIVITY, "DNS"),
    67:    (OCSFClass.DHCP_ACTIVITY, "DHCP"),
    68:    (OCSFClass.DHCP_ACTIVITY, "DHCP"),
    80:    (OCSFClass.HTTP_ACTIVITY, "HTTP"),
    139:   (OCSFClass.SMB_ACTIVITY, "NetBIOS Session"),
    143:   (OCSFClass.EMAIL_ACTIVITY, "IMAP"),
    443:   (OCSFClass.HTTP_ACTIVITY, "HTTPS"),
    445:   (OCSFClass.SMB_ACTIVITY, "SMB"),
    465:   (OCSFClass.EMAIL_ACTIVITY, "SMTPS"),
    587:   (OCSFClass.EMAIL_ACTIVITY, "SMTP Submission"),
    993:   (OCSFClass.EMAIL_ACTIVITY, "IMAPS"),
    995:   (OCSFClass.EMAIL_ACTIVITY, "POP3S"),
    3389:  (OCSFClass.RDP_ACTIVITY, "RDP"),
    8080:  (OCSFClass.HTTP_ACTIVITY, "HTTP Alt"),
    8443:  (OCSFClass.HTTP_ACTIVITY, "HTTPS Alt"),
}

#: Application/service name (as reported by the device) -> OCSF class.
APP_TO_CLASS: Dict[str, OCSFClass] = {
    "dns":        OCSFClass.DNS_ACTIVITY,
    "http":       OCSFClass.HTTP_ACTIVITY,
    "https":      OCSFClass.HTTP_ACTIVITY,
    "web-browsing": OCSFClass.HTTP_ACTIVITY,
    "ssl":        OCSFClass.HTTP_ACTIVITY,
    "ssh":        OCSFClass.SSH_ACTIVITY,
    "smb":        OCSFClass.SMB_ACTIVITY,
    "ms-ds-smb":  OCSFClass.SMB_ACTIVITY,
    "netbios-ss": OCSFClass.SMB_ACTIVITY,
    "ms-rdp":     OCSFClass.RDP_ACTIVITY,
    "rdp":        OCSFClass.RDP_ACTIVITY,
    "ftp":        OCSFClass.FTP_ACTIVITY,
    "smtp":       OCSFClass.EMAIL_ACTIVITY,
    "imap":       OCSFClass.EMAIL_ACTIVITY,
    "pop3":       OCSFClass.EMAIL_ACTIVITY,
    "dhcp":       OCSFClass.DHCP_ACTIVITY,
    "ipsec":      OCSFClass.TUNNEL_ACTIVITY,
    "gre":        OCSFClass.TUNNEL_ACTIVITY,
}

#: Substrings found in vendor threat/signature/category text -> threat class.
#: Ordered most-specific first; the first match wins.
SIGNATURE_PATTERNS: List[Tuple[Tuple[str, ...], ThreatClass, List[str]]] = [
    (("sql injection", "sqli", "sql-injection"),
     ThreatClass.WEB_EXPLOIT, ["T1190"]),
    (("cross-site scripting", "xss"),
     ThreatClass.WEB_EXPLOIT, ["T1059.007"]),
    (("directory traversal", "path traversal", "lfi", "rfi"),
     ThreatClass.WEB_EXPLOIT, ["T1190"]),
    (("command injection", "code execution", "rce", "deserializ"),
     ThreatClass.WEB_EXPLOIT, ["T1190"]),
    (("brute force", "brute-force", "password guess", "credential stuffing",
      "failed login", "authentication failure"),
     ThreatClass.AUTHENTICATION_ATTACK, ["T1110"]),
    (("dns tunnel", "dns-tunnel", "dns exfil", "excessive dns", "iodine",
      "dnscat", "dns query subdomain", "high entropy base64", "txt record abuse"),
     ThreatClass.DATA_EXFILTRATION, ["T1071.004", "T1048.003"]),
    (("exfiltrat", "data leak", "large upload"),
     ThreatClass.DATA_EXFILTRATION, ["T1048"]),
    (("beacon", "command and control", "cobalt strike", "cobaltstrike",
      "sliver", "metasploit", "meterpreter", "empire", "havoc"),
     ThreatClass.COMMAND_AND_CONTROL, ["T1071"]),
    (("trojan", "malware", "ransomware", "virus", "backdoor", "worm",
      "spyware", "cryptominer", "coinminer"),
     ThreatClass.MALWARE, ["T1204"]),
    (("port scan", "port-scan", "portscan", "port sweep", "host sweep",
      "network scan", "reconnaissance", "nmap"),
     ThreatClass.RECONNAISSANCE, ["T1046"]),
    (("privilege escalation", "priv esc", "sudo abuse", "token theft"),
     ThreatClass.PRIVILEGE_ESCALATION, ["T1068"]),
    (("lateral movement", "pass-the-hash", "psexec", "wmi exec"),
     ThreatClass.LATERAL_MOVEMENT, ["T1021"]),
    (("denial of service", "dos attack", "ddos", "syn flood", "flood"),
     ThreatClass.DENIAL_OF_SERVICE, ["T1498"]),
]

#: Substrings in a request URI/URL that indicate an exploitation attempt.
URI_ATTACK_PATTERNS: List[Tuple[Tuple[str, ...], ThreatClass, List[str]]] = [
    (("../", "..%2f", "..%5c", "%2e%2e%2f", "/etc/passwd", "/etc/shadow",
      "boot.ini", "win.ini"),
     ThreatClass.WEB_EXPLOIT, ["T1083", "T1190"]),
    (("union select", "' or '1'='1", "or 1=1", "'--", "/**/", "information_schema",
      "sleep(", "benchmark(", "xp_cmdshell"),
     ThreatClass.WEB_EXPLOIT, ["T1190"]),
    (("<script", "javascript:", "onerror=", "onload=", "%3cscript"),
     ThreatClass.WEB_EXPLOIT, ["T1059.007"]),
    (("${jndi:", "jndi:ldap", "jndi:rmi"),
     ThreatClass.WEB_EXPLOIT, ["T1190"]),
    ((";wget ", ";curl ", "|sh", "$(", "%24%28", "`id`", "/bin/bash"),
     ThreatClass.WEB_EXPLOIT, ["T1059"]),
    (("/.env", "/.git/", "wp-config", "/phpmyadmin", "/.aws/credentials"),
     ThreatClass.RECONNAISSANCE, ["T1595"]),
]

#: Windows Security event IDs -> (OCSF class, threat class, techniques).
WINDOWS_EVENT_IDS: Dict[int, Tuple[OCSFClass, ThreatClass, List[str]]] = {
    4624: (OCSFClass.AUTHENTICATION, ThreatClass.BENIGN_TRAFFIC, []),
    4625: (OCSFClass.AUTHENTICATION, ThreatClass.AUTHENTICATION_ATTACK, ["T1110"]),
    4634: (OCSFClass.AUTHENTICATION, ThreatClass.BENIGN_TRAFFIC, []),
    4648: (OCSFClass.AUTHENTICATION, ThreatClass.LATERAL_MOVEMENT, ["T1078"]),
    4672: (OCSFClass.AUTHENTICATION, ThreatClass.PRIVILEGE_ESCALATION, ["T1078.002"]),
    4720: (OCSFClass.AUTHENTICATION, ThreatClass.PRIVILEGE_ESCALATION, ["T1136.001"]),
    4732: (OCSFClass.AUTHENTICATION, ThreatClass.PRIVILEGE_ESCALATION, ["T1098"]),
    4740: (OCSFClass.AUTHENTICATION, ThreatClass.AUTHENTICATION_ATTACK, ["T1110"]),
    4768: (OCSFClass.AUTHENTICATION, ThreatClass.BENIGN_TRAFFIC, []),
    4769: (OCSFClass.AUTHENTICATION, ThreatClass.BENIGN_TRAFFIC, []),
    4771: (OCSFClass.AUTHENTICATION, ThreatClass.AUTHENTICATION_ATTACK, ["T1110"]),
}

#: Ports that indicate lateral movement / remote administration when *blocked*
#: from an untrusted source. Kept separate from PORT_TO_CLASS on purpose:
#: the same port means different things depending on action and direction.
LATERAL_MOVEMENT_PORTS: frozenset = frozenset({135, 139, 445, 3389, 5985, 5986, 5900})

#: Ports whose exposure to untrusted networks is itself a policy concern.
SENSITIVE_SERVICE_PORTS: frozenset = frozenset({
    22, 23, 1433, 3306, 5432, 6379, 27017, 2375, 2376, 9200, 11211,
})

#: Blocking/denying actions - the device itself asserted this was unwanted.
BLOCKING_ACTIONS: frozenset = frozenset({
    "DENY", "DROP", "REJECT", "RESET", "BLOCK", "QUARANTINE",
})


# ----------------------------------------------------------------------------
# Classifier
# ----------------------------------------------------------------------------

class TaxonomyClassifier:
    """Maps a normalized event onto the canonical ULPF taxonomy.

    The classifier consumes only already-normalized signals (action, ports,
    protocol, threat text) so it is parser-agnostic: a new log source that
    normalizes correctly is classified correctly with no classifier change.
    """

    #: Below this, the event is reported UNCLASSIFIED rather than guessed at.
    MIN_CONFIDENCE = 0.30

    def classify(
        self,
        *,
        action: str = "",
        severity: str = "",
        dst_port: Optional[int] = None,
        src_port: Optional[int] = None,
        protocol: str = "",
        direction: str = "",
        app: str = "",
        threat_signature: str = "",
        threat_category: str = "",
        vendor_event_type: str = "",
        uri: str = "",
        windows_event_id: Optional[int] = None,
        src_is_internal: Optional[bool] = None,
        dst_is_internal: Optional[bool] = None,
    ) -> Classification:
        evidence: List[Evidence] = []

        # Windows Security event IDs are an exact, documented mapping - no
        # heuristic can beat them, so they short-circuit everything else.
        if windows_event_id in WINDOWS_EVENT_IDS:
            ocsf_cls, threat_cls, techniques = WINDOWS_EVENT_IDS[windows_event_id]
            evidence.append(Evidence(
                signal="windows.event_id",
                observed=windows_event_id,
                contributes=f"{threat_cls.value} (documented Windows Security event ID)",
                weight=1.0,
            ))
            return Classification(
                ocsf_class=ocsf_cls,
                threat_class=threat_cls,
                confidence=0.98,
                mitre_techniques=list(techniques),
                evidence=evidence,
            )

        ocsf_class = self._classify_ocsf(dst_port, src_port, app, protocol, evidence)
        threat_class, techniques, confidence = self._classify_threat(
            action=action,
            severity=severity,
            dst_port=dst_port,
            direction=direction,
            threat_text=" ".join(
                str(x) for x in (threat_signature, threat_category, vendor_event_type) if x
            ).lower(),
            uri=uri,
            src_is_internal=src_is_internal,
            dst_is_internal=dst_is_internal,
            evidence=evidence,
        )

        # A vendor signature strong enough to name a technique is also a finding.
        if threat_signature and threat_class in SECURITY_RELEVANT and                 threat_class is not ThreatClass.POLICY_VIOLATION:
            ocsf_class = OCSFClass.DETECTION_FINDING
            evidence.append(Evidence(
                signal="threat.signature",
                observed=threat_signature,
                contributes="OCSF Detection Finding (device asserted a detection)",
                weight=0.9,
            ))

        if confidence < self.MIN_CONFIDENCE:
            threat_class = ThreatClass.UNCLASSIFIED
            techniques = []

        evidence.sort(key=lambda e: e.weight, reverse=True)
        return Classification(
            ocsf_class=ocsf_class,
            threat_class=threat_class,
            confidence=confidence,
            mitre_techniques=techniques,
            evidence=evidence,
        )

    # -- OCSF axis ----------------------------------------------------------

    def _classify_ocsf(
        self,
        dst_port: Optional[int],
        src_port: Optional[int],
        app: str,
        protocol: str,
        evidence: List[Evidence],
    ) -> OCSFClass:
        """Identify the activity class. Application name beats port number,
        because a device that names the application has already done L7
        inspection and is more trustworthy than a port heuristic."""
        app_key = (app or "").strip().lower()
        if app_key in APP_TO_CLASS:
            cls = APP_TO_CLASS[app_key]
            evidence.append(Evidence(
                signal="network.application",
                observed=app,
                contributes=f"OCSF {cls.label} (L7 identification by device)",
                weight=0.85,
            ))
            return cls

        for port, side in ((dst_port, "destination"), (src_port, "source")):
            if port in PORT_TO_CLASS:
                cls, service = PORT_TO_CLASS[port]
                evidence.append(Evidence(
                    signal=f"{side}.port",
                    observed=port,
                    contributes=f"OCSF {cls.label} (well-known {service} port)",
                    weight=0.55 if side == "destination" else 0.35,
                ))
                return cls

        evidence.append(Evidence(
            signal="network.protocol",
            observed=protocol or "unknown",
            contributes="OCSF Network Activity (no L7 identification available)",
            weight=0.20,
        ))
        return OCSFClass.NETWORK_ACTIVITY

    # -- Threat axis --------------------------------------------------------

    def _classify_threat(
        self,
        *,
        action: str,
        severity: str,
        dst_port: Optional[int],
        direction: str,
        threat_text: str,
        uri: str,
        src_is_internal: Optional[bool],
        dst_is_internal: Optional[bool],
        evidence: List[Evidence],
    ) -> Tuple[ThreatClass, List[str], float]:
        action_u = (action or "").upper()
        blocked = action_u in BLOCKING_ACTIONS
        inbound = (direction or "").upper() == "INBOUND" or (
            src_is_internal is False and dst_is_internal is True
        )

        # 1. Highest-trust signal: the device named a specific threat.
        if threat_text:
            for needles, tclass, techniques in SIGNATURE_PATTERNS:
                for needle in needles:
                    if needle in threat_text:
                        evidence.append(Evidence(
                            signal="threat.signature",
                            observed=needle,
                            contributes=f"{tclass.value} (vendor signature match)",
                            weight=0.95,
                        ))
                        return tclass, list(techniques), 0.95

        # 1b. Exploit payload visible in the request URI.
        if uri:
            uri_l = uri.lower()
            for needles, tclass, techniques in URI_ATTACK_PATTERNS:
                for needle in needles:
                    if needle in uri_l:
                        evidence.append(Evidence(
                            signal="http.uri",
                            observed=needle,
                            contributes=f"{tclass.value} (attack pattern in request path)",
                            weight=0.90,
                        ))
                        return tclass, list(techniques), 0.90

        # 2. Device blocked traffic to a lateral-movement port from outside.
        if blocked and dst_port in LATERAL_MOVEMENT_PORTS:
            tclass = ThreatClass.RECONNAISSANCE if inbound else ThreatClass.LATERAL_MOVEMENT
            technique = "T1046" if inbound else "T1021"
            evidence.append(Evidence(
                signal="action + destination.port",
                observed=f"{action_u} to port {dst_port}",
                contributes=f"{tclass.value} (blocked remote-administration port)",
                weight=0.75,
            ))
            return tclass, [technique], 0.75

        # 3. Device blocked traffic to a sensitive service port.
        if blocked and dst_port in SENSITIVE_SERVICE_PORTS:
            evidence.append(Evidence(
                signal="action + destination.port",
                observed=f"{action_u} to port {dst_port}",
                contributes="reconnaissance (blocked probe of sensitive service)",
                weight=0.65,
            ))
            return ThreatClass.RECONNAISSANCE, ["T1046"], 0.65

        # 4. Device blocked, but nothing more specific is known. The block is a
        #    policy decision - report it as such rather than inventing a threat.
        if blocked:
            evidence.append(Evidence(
                signal="event.action",
                observed=action_u,
                contributes="policy_violation (device enforced a rule)",
                weight=0.55,
            ))
            return ThreatClass.POLICY_VIOLATION, [], 0.55

        # 5. Vendor severity is high but no signature - trust it partially.
        if (severity or "").upper() in ("HIGH", "CRITICAL"):
            evidence.append(Evidence(
                signal="event.severity",
                observed=severity,
                contributes="unclassified security event (vendor severity only)",
                weight=0.40,
            ))
            return ThreatClass.UNCLASSIFIED, [], 0.40

        # 6. Explicitly allowed traffic on a known service.
        if action_u in ("ALLOW", "ACCEPT", "PERMIT"):
            evidence.append(Evidence(
                signal="event.action",
                observed=action_u,
                contributes="benign_traffic (permitted by policy)",
                weight=0.60,
            ))
            return ThreatClass.BENIGN_TRAFFIC, [], 0.60

        evidence.append(Evidence(
            signal="(none)",
            observed=None,
            contributes="insufficient signal to classify",
            weight=0.0,
        ))
        return ThreatClass.UNCLASSIFIED, [], 0.0


#: Shared default instance.
default_classifier = TaxonomyClassifier()
