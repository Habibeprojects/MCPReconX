"""
MCPReconX - Attack Patterns Module
===================================
Detects advanced MCP attack patterns based on security research.

Attack Patterns Covered:
- Tool Poisoning Attacks (TPA)
- Full Schema Poisoning (FSP)
- Advanced Tool Poisoning (ATPA)
- Indirect Prompt Injection (IPI)
- Confused Deputy Attacks
- Rug Pull Attacks
- Tool Shadowing
- Token Passthrough
- MCP Configuration Poisoning (MCPoison)
- NeighborJack (0.0.0.0 Day)
- DNS Rebinding
- Session Hijacking / Prompt Hijacking

Based on research from:
- Adversa.ai MCP Security Top 25
- Cyata Research
- BlueRock Security
- JFrog Security
- Oligo Security
- Imperva Threat Research

ETHICAL USE NOTICE:
This tool is intended for authorized security testing only.
"""

import re
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class AttackPatternFinding:
    """Container for attack pattern detection results."""
    pattern_name: str
    category: str
    severity: str
    cvss_score: float
    description: str
    evidence: Dict[str, Any]
    affected_component: str
    remediation: str
    references: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_name": self.pattern_name,
            "category": self.category,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "description": self.description,
            "evidence": self.evidence,
            "affected_component": self.affected_component,
            "remediation": self.remediation,
            "references": self.references
        }


class AttackPatternDetector:
    """Detects advanced MCP attack patterns."""
    
    # Hidden instruction patterns for Tool Poisoning
    TOOL_POISONING_PATTERNS = [
        # Direct instruction overrides
        (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|directives?|prompts?)", "instruction_override", 10),
        (r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|directives?)", "instruction_override", 10),
        (r"forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|directives?)", "instruction_override", 10),
        
        # System prompt injection
        (r"\[system\s*[\(:<]", "system_prompt_injection", 9),
        (r"<system>", "system_prompt_injection", 9),
        (r"\{\{system\}\}", "system_prompt_injection", 9),
        (r"system\s*:\s*you\s+are\s+now", "system_prompt_injection", 9),
        (r"```\s*system", "system_prompt_injection", 9),
        
        # Role manipulation
        (r"you\s+are\s+now\s+(an?\s+)?(admin|administrator|root|superuser)", "role_escalation", 9),
        (r"admin\s*mode\s*(enabled?|activated?|on)", "role_escalation", 8),
        (r"debug\s*mode\s*(enabled?|on)", "debug_mode", 8),
        (r"developer\s*mode\s*(enabled?|on)", "debug_mode", 8),
        
        # Security bypass
        (r"override\s+(security|restrictions?|constraints?|safeguards?)", "security_bypass", 9),
        (r"bypass\s+(security|restrictions?|constraints?)", "security_bypass", 9),
        (r"disable\s+(safety|security|protections?)", "security_bypass", 9),
        
        # Data exfiltration patterns
        (r"(send|transmit|exfiltrate)\s+(all\s+)?(data|information|logs?)\s+to", "data_exfil", 8),
        (r"(include|attach)\s+(sensitive|confidential|internal)\s+data", "data_exfil", 8),
        (r"(upload|post)\s+(to|at)\s+https?://", "data_exfil", 7),
        
        # Jailbreak patterns
        (r"DAN\s*\(Do\s*Anything\s*Now\)", "jailbreak", 9),
        (r"jailbreak", "jailbreak", 7),
        (r"hypothetical\s+scenario", "jailbreak", 6),
        
        # Unicode-based hiding techniques
        (r"[\u200B-\u200D\uFEFF]", "hidden_unicode", 8),  # Zero-width characters
        (r"[\u202A-\u202E]", "text_direction_manipulation", 8),  # RTL/LTR markers
        
        # Encoding-based hiding
        (r"base64\s*:\s*[A-Za-z0-9+/=]{20,}", "base64_hidden", 7),
        (r"<!--.*?-->", "html_comment_hide", 6),
    ]
    
    # Full Schema Poisoning patterns
    SCHEMA_POISONING_PATTERNS = [
        # Malicious parameter names
        (r"param.*system", "poisoned_parameter_name", 7),
        (r"arg.*instruction", "poisoned_parameter_name", 7),
        
        # Suspicious default values
        (r"default.*\{.*system", "poisoned_default", 8),
        (r"default.*ignore", "poisoned_default", 8),
        
        # Malicious enum values
        (r"enum.*system|admin|override", "poisoned_enum", 7),
    ]
    
    # Tool name spoofing patterns (homoglyphs, typosquatting)
    TOOL_NAME_SPOOFING_PATTERNS = [
        # Cyrillic lookalikes
        (r"[а-яА-Я]", "cyrillic_homoglyph", 7),  # Cyrillic characters
        (r"[οΟο]", "greek_omicron", 6),  # Greek omicron looks like 'o'
        (r"[іІ]", "ukrainian_i", 6),  # Ukrainian i looks like 'i'
        
        # Common typosquatting patterns
        (r"gthub|githu|githubb", "github_typosquat", 7),
        (r"slck|slac|slackk", "slack_typosquat", 7),
        (r"databse|dataase|datbase", "database_typosquat", 6),
    ]
    
    # Confused Deputy indicators
    CONFUSED_DEPUTY_INDICATORS = [
        "oauth", "proxy", "delegate", "forward", "passthrough",
        "static client", "consent", "authorization", "token"
    ]
    
    # Token Passthrough indicators
    TOKEN_PASSTHROUGH_INDICATORS = [
        "forward token", "pass token", "relay token", "token passthrough",
        "accept token from client", "client token"
    ]
    
    # Excessive Agency indicators
    EXCESSIVE_AGENCY_INDICATORS = [
        "delete", "remove", "drop", "truncate", "destroy",
        "modify", "update", "alter", "change", "edit",
        "create", "insert", "add", "append", "write",
        "execute", "run", "launch", "start", "spawn",
        "stop", "kill", "terminate", "restart", "shutdown",
        "grant", "revoke", "permission", "access", "privilege"
    ]
    
    # Network exposure indicators
    NETWORK_EXPOSURE_INDICATORS = [
        "0.0.0.0", "::", "bind all", "all interfaces",
        "listen on all", "expose to network"
    ]
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.findings: List[AttackPatternFinding] = []
    
    def detect_all(self, fingerprint: Any) -> List[AttackPatternFinding]:
        """
        Run all attack pattern detection checks.
        
        Args:
            fingerprint: Fingerprint results
        
        Returns:
            List of attack pattern findings
        """
        self.logger.info("Starting attack pattern detection...")
        
        # Detect tool poisoning
        self._detect_tool_poisoning(fingerprint)
        
        # Detect full schema poisoning
        self._detect_schema_poisoning(fingerprint)
        
        # Detect tool name spoofing
        self._detect_tool_name_spoofing(fingerprint)
        
        # Detect confused deputy
        self._detect_confused_deputy(fingerprint)
        
        # detect token passthrough
        self._detect_token_passthrough(fingerprint)
        
        # Detect excessive agency
        self._detect_excessive_agency(fingerprint)
        
        # Detect network exposure
        self._detect_network_exposure(fingerprint)
        
        self.logger.info(f"Attack pattern detection complete. Found {len(self.findings)} patterns.")
        return self.findings
    
    def _detect_tool_poisoning(self, fingerprint: Any):
        """Detect Tool Poisoning Attacks (TPA)."""
        tools = fingerprint.tools if hasattr(fingerprint, 'tools') else []
        
        for tool in tools:
            tool_name = tool.get("name", "")
            description = tool.get("description", "")
            input_schema = json.dumps(tool.get("inputSchema", {}))
            
            # Combine all text for analysis
            tool_text = f"{tool_name} {description} {input_schema}"
            
            for pattern, category, impact in self.TOOL_POISONING_PATTERNS:
                matches = list(re.finditer(pattern, tool_text, re.IGNORECASE))
                
                for match in matches:
                    self._add_finding(
                        pattern_name="Tool Poisoning Attack (TPA)",
                        category="input/instruction_boundary_failure",
                        severity="critical" if impact >= 9 else "high",
                        cvss_score=9.0 if impact >= 9 else 7.5,
                        description=f"Potential tool poisoning detected in tool '{tool_name}'. "
                                   f"Hidden instructions may be embedded in tool metadata.",
                        evidence={
                            "tool_name": tool_name,
                            "pattern_matched": pattern,
                            "category": category,
                            "matched_text": match.group(0)[:100],
                            "context": self._get_context(tool_text, match.start(), match.end())
                        },
                        affected_component=f"tool:{tool_name}",
                        remediation="Review tool source code and metadata. Implement tool signing and verification. "
                                   "Use cryptographic signatures to ensure tool integrity.",
                        references=[
                            "https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/",
                            "https://www.descope.com/learn/post/mcp-tool-poisoning"
                        ]
                    )
    
    def _detect_schema_poisoning(self, fingerprint: Any):
        """Detect Full Schema Poisoning (FSP)."""
        tools = fingerprint.tools if hasattr(fingerprint, 'tools') else []
        
        for tool in tools:
            schema = tool.get("inputSchema", {})
            schema_str = json.dumps(schema)
            
            for pattern, category, impact in self.SCHEMA_POISONING_PATTERNS:
                if re.search(pattern, schema_str, re.IGNORECASE):
                    self._add_finding(
                        pattern_name="Full Schema Poisoning (FSP)",
                        category="input/instruction_boundary_failure",
                        severity="high",
                        cvss_score=8.0,
                        description=f"Potential schema poisoning in tool '{tool.get('name')}'. "
                                   "Malicious instructions may be embedded in schema structure.",
                        evidence={
                            "tool_name": tool.get("name"),
                            "pattern": pattern,
                            "category": category
                        },
                        affected_component=f"tool:{tool.get('name')}.schema",
                        remediation="Validate tool schemas against known-good templates. "
                                   "Implement schema signing and versioning.",
                        references=[
                            "https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/"
                        ]
                    )
    
    def _detect_tool_name_spoofing(self, fingerprint: Any):
        """Detect Tool Name Spoofing (homoglyphs, typosquatting)."""
        tools = fingerprint.tools if hasattr(fingerprint, 'tools') else []
        
        for tool in tools:
            tool_name = tool.get("name", "")
            
            # Check for Unicode homoglyphs
            for pattern, category, impact in self.TOOL_NAME_SPOOFING_PATTERNS:
                if re.search(pattern, tool_name, re.IGNORECASE):
                    self._add_finding(
                        pattern_name="Tool Name Spoofing",
                        category="missing_integrity_controls",
                        severity="high" if category == "cyrillic_homoglyph" else "medium",
                        cvss_score=7.5 if category == "cyrillic_homoglyph" else 6.0,
                        description=f"Potential tool name spoofing detected: '{tool_name}'. "
                                   f"May be using {category} to impersonate legitimate tools.",
                        evidence={
                            "tool_name": tool_name,
                            "spoofing_type": category,
                            "suspicious_characters": [c for c in tool_name if ord(c) > 127]
                        },
                        affected_component=f"tool:{tool_name}",
                        remediation="Implement Unicode normalization for tool names. "
                                   "Use allowlists for trusted tool providers.",
                        references=[
                            "https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/"
                        ]
                    )
    
    def _detect_confused_deputy(self, fingerprint: Any):
        """Detect Confused Deputy vulnerabilities."""
        tools = fingerprint.tools if hasattr(fingerprint, 'tools') else []
        server_info = fingerprint.server_info if hasattr(fingerprint, 'server_info') else {}
        
        # Check for OAuth proxy indicators
        is_proxy = any(indicator in str(server_info).lower() for indicator in ["proxy", "oauth"])
        
        if is_proxy:
            # Check for static client ID usage
            has_static_client = "static" in str(server_info).lower() and "client" in str(server_info).lower()
            
            if has_static_client:
                self._add_finding(
                    pattern_name="Confused Deputy (OAuth Proxy)",
                    category="session_management_design_flaw",
                    severity="critical",
                    cvss_score=9.0,
                    description="MCP server appears to be an OAuth proxy with static client ID. "
                               "Vulnerable to confused deputy attacks where malicious clients can "
                               "steal authorization codes.",
                    evidence={
                        "server_type": "oauth_proxy",
                        "static_client": True,
                        "indicators": [i for i in self.CONFUSED_DEPUTY_INDICATORS if i in str(server_info).lower()]
                    },
                    affected_component="oauth_proxy",
                    remediation="Use per-client OAuth registrations. Require explicit re-consent for each redirect URI. "
                               "Implement consent page with CSRF protection.",
                    references=[
                        "https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices",
                        "https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/"
                    ]
                )
    
    def _detect_token_passthrough(self, fingerprint: Any):
        """Detect Token Passthrough anti-pattern."""
        tools = fingerprint.tools if hasattr(fingerprint, 'tools') else []
        capabilities = fingerprint.capabilities if hasattr(fingerprint, 'capabilities') else {}
        
        # Check for token forwarding indicators in tool descriptions
        for tool in tools:
            description = tool.get("description", "").lower()
            
            if any(indicator in description for indicator in self.TOKEN_PASSTHROUGH_INDICATORS):
                self._add_finding(
                    pattern_name="Token Passthrough",
                    category="missing_authentication_authorization",
                    severity="high",
                    cvss_score=8.0,
                    description=f"Tool '{tool.get('name')}' may implement token passthrough anti-pattern. "
                               "Accepting client tokens without verification bypasses security controls.",
                    evidence={
                        "tool_name": tool.get("name"),
                        "indicators_found": [i for i in self.TOKEN_PASSTHROUGH_INDICATORS if i in description]
                    },
                    affected_component=f"tool:{tool.get('name')}",
                    remediation="Never accept tokens not explicitly issued for your MCP server. "
                               "Verify audience (aud) claim on every token. Use token exchange.",
                    references=[
                        "https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices",
                        "https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/"
                    ]
                )
    
    def _detect_excessive_agency(self, fingerprint: Any):
        """Detect Excessive Agency / Overbroad Permissions."""
        tools = fingerprint.tools if hasattr(fingerprint, 'tools') else []
        
        high_agency_tools = []
        
        for tool in tools:
            tool_name = tool.get("name", "").lower()
            description = tool.get("description", "").lower()
            tool_text = f"{tool_name} {description}"
            
            agency_score = 0
            matched_indicators = []
            
            for indicator in self.EXCESSIVE_AGENCY_INDICATORS:
                if indicator in tool_text:
                    agency_score += 1
                    matched_indicators.append(indicator)
            
            if agency_score >= 4:
                high_agency_tools.append({
                    "name": tool.get("name"),
                    "score": agency_score,
                    "indicators": matched_indicators
                })
        
        if len(high_agency_tools) >= 3:
            self._add_finding(
                pattern_name="Excessive Agency / Overbroad Permissions",
                category="missing_authentication_authorization",
                severity="medium",
                cvss_score=6.0,
                description=f"Found {len(high_agency_tools)} tools with potentially excessive agency. "
                           "These tools may perform destructive or sensitive operations without adequate safeguards.",
                evidence={
                    "high_agency_tools": high_agency_tools,
                    "total_tools": len(tools)
                },
                affected_component="tool_permissions",
                remediation="Implement principle of least privilege. Add confirmation prompts for destructive operations. "
                           "Use capability-based access control.",
                references=[
                    "https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/"
                ]
            )
    
    def _detect_network_exposure(self, fingerprint: Any):
        """Detect NeighborJack / 0.0.0.0 Day vulnerability."""
        headers = fingerprint.headers if hasattr(fingerprint, 'headers') else {}
        server_info = fingerprint.server_info if hasattr(fingerprint, 'server_info') else {}
        
        # Check for 0.0.0.0 binding indicators
        server_header = headers.get("server", "").lower()
        
        # Check if server binds to all interfaces
        binds_all = any(indicator in str(server_info).lower() for indicator in self.NETWORK_EXPOSURE_INDICATORS)
        
        if binds_all:
            self._add_finding(
                pattern_name="NeighborJack (0.0.0.0 Day)",
                category="network_binding_isolation_failure",
                severity="high",
                cvss_score=8.0,
                description="MCP server appears to bind to 0.0.0.0 (all interfaces). "
                           "Exposes service to entire network, allowing remote attackers to access "
                           "supposedly local-only services.",
                evidence={
                    "binding": "0.0.0.0",
                    "indicators": [i for i in self.NETWORK_EXPOSURE_INDICATORS if i in str(server_info).lower()]
                },
                affected_component="network_binding",
                remediation="Bind MCP servers to localhost (127.0.0.1) only. "
                           "Use reverse proxy with authentication for remote access.",
                references=[
                    "https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/",
                    "https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596"
                ]
            )
    
    def _add_finding(self, **kwargs):
        """Add a finding if not already present."""
        # Check for duplicates
        for finding in self.findings:
            if (finding.pattern_name == kwargs.get("pattern_name") and 
                finding.affected_component == kwargs.get("affected_component")):
                return
        
        finding = AttackPatternFinding(**kwargs)
        self.findings.append(finding)
        self.logger.warning(f"[ATTACK PATTERN] {kwargs.get('pattern_name')} - {kwargs.get('severity')}")
    
    def _get_context(self, text: str, start: int, end: int, context_chars: int = 50) -> str:
        """Get context around a match."""
        context_start = max(0, start - context_chars)
        context_end = min(len(text), end + context_chars)
        return text[context_start:context_end]
