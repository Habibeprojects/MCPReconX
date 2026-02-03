"""
MCPReconX - Poison Detection Module
====================================
Detects tool poisoning, hidden instructions, and malicious payloads.

ETHICAL USE NOTICE:
This tool is intended for authorized security testing only.
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin

import aiohttp
import websockets


@dataclass
class Finding:
    """Container for security findings."""
    title: str
    description: str
    severity: str  # info, low, medium, high, critical
    category: str
    evidence: Dict[str, Any]
    remediation: str
    cvss_score: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score
        }


class PoisonDetector:
    """Detects tool poisoning and hidden instructions in MCP servers."""
    
    # Hidden instruction patterns (prompt injection indicators)
    HIDDEN_INSTRUCTION_PATTERNS = [
        # Direct instruction overrides
        (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|directives?|prompts?)", "instruction_override"),
        (r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|directives?)", "instruction_override"),
        (r"forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|directives?)", "instruction_override"),
        
        # System prompt injection
        (r"\[system\s*[\(:<]", "system_prompt_injection"),
        (r"<system>", "system_prompt_injection"),
        (r"\{\{system\}\}", "system_prompt_injection"),
        (r"system\s*:\s*you\s+are\s+now", "system_prompt_injection"),
        
        # Role manipulation
        (r"you\s+are\s+now\s+(an?\s+)?(admin|administrator|root|superuser)", "role_escalation"),
        (r"admin\s*mode\s*(enabled?|activated?|on)", "role_escalation"),
        (r"debug\s*mode\s*(enabled?|on)", "debug_mode"),
        (r"developer\s*mode\s*(enabled?|on)", "debug_mode"),
        
        # Security bypass
        (r"override\s+(security|restrictions?|constraints?|safeguards?)", "security_bypass"),
        (r"bypass\s+(security|restrictions?|constraints?)", "security_bypass"),
        (r"disable\s+(safety|security|protections?)", "security_bypass"),
        
        # Data exfiltration
        (r"(send|transmit|exfiltrate)\s+(all\s+)?(data|information|logs?)\s+to", "data_exfil"),
        (r"(include|attach)\s+(sensitive|confidential|internal)\s+data", "data_exfil"),
        
        # Jailbreak patterns
        (r"DAN\s*\(Do\s*Anything\s*Now\)", "jailbreak"),
        (r"jailbreak", "jailbreak"),
        (r"hypothetical\s+scenario", "jailbreak"),
    ]
    
    # Suspicious tool patterns
    SUSPICIOUS_TOOL_PATTERNS = [
        (r"exec\s*\(", "code_execution"),
        (r"eval\s*\(", "code_execution"),
        (r"system\s*\(", "system_command"),
        (r"subprocess", "subprocess_spawn"),
        (r"os\.system", "system_command"),
        (r"os\.popen", "command_execution"),
        (r"shell", "shell_access"),
        (r"bash\s+-c", "shell_command"),
        (r"cmd\.exe", "windows_shell"),
        (r"powershell", "powershell_execution"),
        (r"__import__", "dynamic_import"),
        (r"importlib", "dynamic_import"),
        (r"compile\s*\(", "code_compilation"),
        (r"execfile", "file_execution"),
        (r"open\s*\([^)]*['\"](w|a)", "file_write"),
        (r"file:\/\/", "file_protocol"),
        (r"http:\/\/", "insecure_http"),
        (r"ftp:\/\/", "insecure_ftp"),
    ]
    
    # Excessive agency indicators
    AGENCY_INDICATORS = [
        "delete", "remove", "drop", "truncate",
        "modify", "update", "alter", "change",
        "create", "insert", "add", "append",
        "execute", "run", "launch", "start",
        "stop", "kill", "terminate", "restart",
        "grant", "revoke", "permission", "access"
    ]
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger, args: Any):
        self.config = config
        self.logger = logger
        self.args = args
        self.timeout = config.get("scan", {}).get("timeout", 30)
        
        # Load patterns from config
        config_patterns = config.get("detection", {}).get("hidden_instruction_patterns", [])
        if config_patterns:
            self.HIDDEN_INSTRUCTION_PATTERNS = [(p, "config") for p in config_patterns]
    
    async def passive_analysis(self, fingerprint: Any) -> List[Finding]:
        """
        Perform passive analysis on fingerprint data.
        
        Args:
            fingerprint: FingerprintResult object
        
        Returns:
            List of findings
        """
        self.logger.info("Starting passive analysis...")
        findings = []
        
        # Analyze tool descriptions
        for tool in fingerprint.tools:
            tool_findings = self._analyze_tool(tool)
            findings.extend(tool_findings)
        
        # Analyze resource descriptions
        for resource in fingerprint.resources:
            resource_findings = self._analyze_resource(resource)
            findings.extend(resource_findings)
        
        # Analyze prompts
        for prompt in fingerprint.prompts:
            prompt_findings = self._analyze_prompt(prompt)
            findings.extend(prompt_findings)
        
        # Check for excessive agency
        agency_finding = self._check_excessive_agency(fingerprint.tools)
        if agency_finding:
            findings.append(agency_finding)
        
        # Check for capability mismatches
        mismatch_findings = self._check_capability_mismatches(fingerprint)
        findings.extend(mismatch_findings)
        
        self.logger.info(f"Passive analysis complete. Found {len(findings)} issues.")
        return findings
    
    def _analyze_tool(self, tool: Dict[str, Any]) -> List[Finding]:
        """Analyze a single tool for suspicious content."""
        findings = []
        
        tool_name = tool.get("name", "unknown")
        description = tool.get("description", "")
        input_schema = json.dumps(tool.get("inputSchema", {}))
        
        # Combine all text for analysis
        tool_text = f"{tool_name} {description} {input_schema}".lower()
        
        # Check for hidden instructions
        for pattern, category in self.HIDDEN_INSTRUCTION_PATTERNS:
            matches = re.finditer(pattern, tool_text, re.IGNORECASE)
            for match in matches:
                finding = Finding(
                    title=f"Hidden Instruction Detected in Tool '{tool_name}'",
                    description=f"Potential prompt injection pattern detected in tool {tool_name}. "
                               f"This could indicate tool poisoning or malicious instruction injection.",
                    severity="critical" if category in ["instruction_override", "system_prompt_injection"] else "high",
                    category="tool_poisoning",
                    evidence={
                        "tool_name": tool_name,
                        "pattern_matched": pattern,
                        "category": category,
                        "matched_text": match.group(0)[:100],
                        "context": self._get_context(tool_text, match.start(), match.end())
                    },
                    remediation="Review tool source code and description. Remove any hidden instructions. "
                               "Implement input validation and sanitization for tool descriptions.",
                    cvss_score=9.0 if category in ["instruction_override", "system_prompt_injection"] else 7.5
                )
                findings.append(finding)
                self.logger.warning(f"Hidden instruction in tool '{tool_name}': {category}")
        
        # Check for suspicious code patterns
        for pattern, category in self.SUSPICIOUS_TOOL_PATTERNS:
            matches = re.finditer(pattern, tool_text, re.IGNORECASE)
            for match in matches:
                finding = Finding(
                    title=f"Suspicious Code Pattern in Tool '{tool_name}'",
                    description=f"Potentially dangerous code pattern detected in tool {tool_name}. "
                               f"Pattern category: {category}",
                    severity="high" if category in ["code_execution", "system_command", "shell_access"] else "medium",
                    category="dangerous_capability",
                    evidence={
                        "tool_name": tool_name,
                        "pattern_matched": pattern,
                        "category": category,
                        "matched_text": match.group(0)[:100]
                    },
                    remediation="Review tool implementation for security. Ensure proper sandboxing and "
                               "input validation. Consider restricting tool capabilities.",
                    cvss_score=8.0 if category in ["code_execution", "system_command"] else 5.0
                )
                findings.append(finding)
        
        return findings
    
    def _analyze_resource(self, resource: Dict[str, Any]) -> List[Finding]:
        """Analyze a resource for suspicious content."""
        findings = []
        
        resource_uri = resource.get("uri", "")
        resource_name = resource.get("name", "unknown")
        description = resource.get("description", "")
        
        resource_text = f"{resource_uri} {resource_name} {description}".lower()
        
        # Check for hidden instructions
        for pattern, category in self.HIDDEN_INSTRUCTION_PATTERNS:
            if re.search(pattern, resource_text, re.IGNORECASE):
                finding = Finding(
                    title=f"Hidden Instruction in Resource '{resource_name}'",
                    description=f"Potential prompt injection detected in resource description.",
                    severity="high",
                    category="resource_poisoning",
                    evidence={
                        "resource_name": resource_name,
                        "resource_uri": resource_uri,
                        "pattern": pattern
                    },
                    remediation="Review resource metadata and remove suspicious content.",
                    cvss_score=7.0
                )
                findings.append(finding)
        
        return findings
    
    def _analyze_prompt(self, prompt: Dict[str, Any]) -> List[Finding]:
        """Analyze a prompt for suspicious content."""
        findings = []
        
        prompt_name = prompt.get("name", "unknown")
        description = prompt.get("description", "")
        
        # Get prompt content if available
        prompt_text = f"{prompt_name} {description}".lower()
        
        # Check for hidden instructions
        for pattern, category in self.HIDDEN_INSTRUCTION_PATTERNS:
            if re.search(pattern, prompt_text, re.IGNORECASE):
                finding = Finding(
                    title=f"Hidden Instruction in Prompt '{prompt_name}'",
                    description=f"Potential prompt injection detected in prompt template.",
                    severity="critical",
                    category="prompt_injection",
                    evidence={
                        "prompt_name": prompt_name,
                        "pattern": pattern
                    },
                    remediation="Review prompt template for injected instructions.",
                    cvss_score=9.0
                )
                findings.append(finding)
        
        return findings
    
    def _check_excessive_agency(self, tools: List[Dict[str, Any]]) -> Optional[Finding]:
        """Check for tools with excessive agency."""
        high_agency_tools = []
        
        for tool in tools:
            tool_name = tool.get("name", "").lower()
            description = tool.get("description", "").lower()
            tool_text = f"{tool_name} {description}"
            
            agency_score = 0
            matched_indicators = []
            
            for indicator in self.AGENCY_INDICATORS:
                if indicator in tool_text:
                    agency_score += 1
                    matched_indicators.append(indicator)
            
            if agency_score >= 3:
                high_agency_tools.append({
                    "name": tool.get("name"),
                    "score": agency_score,
                    "indicators": matched_indicators
                })
        
        if high_agency_tools:
            return Finding(
                title="Excessive Agency Detected",
                description=f"Found {len(high_agency_tools)} tools with potentially excessive agency. "
                           "These tools may perform destructive or sensitive operations without adequate safeguards.",
                severity="medium",
                category="excessive_agency",
                evidence={
                    "high_agency_tools": high_agency_tools,
                    "total_tools": len(tools)
                },
                remediation="Review tool capabilities and implement principle of least privilege. "
                           "Add confirmation prompts for destructive operations.",
                cvss_score=5.0
            )
        
        return None
    
    def _check_capability_mismatches(self, fingerprint: Any) -> List[Finding]:
        """Check for mismatches between declared and actual capabilities."""
        findings = []
        
        server_caps = fingerprint.capabilities
        tools = fingerprint.tools
        
        # Check if server declares experimental features
        experimental = server_caps.get("experimental", {})
        if experimental:
            findings.append(Finding(
                title="Experimental Features Enabled",
                description="Server has experimental features enabled which may have security implications.",
                severity="info",
                category="configuration",
                evidence={"experimental_features": experimental},
                remediation="Review experimental features and disable if not required.",
                cvss_score=0.0
            ))
        
        return findings
    
    def _get_context(self, text: str, start: int, end: int, context_chars: int = 50) -> str:
        """Get context around a match."""
        context_start = max(0, start - context_chars)
        context_end = min(len(text), end + context_chars)
        return text[context_start:context_end]
    
    async def active_detection(self, target_info: Any, fingerprint: Any) -> List[Finding]:
        """
        Perform active detection (requires tool invocation).
        
        This is done in safe mode - only sends benign test payloads.
        """
        findings = []
        
        # Test for tool poisoning via parameter injection
        poison_findings = await self._test_tool_poisoning(target_info, fingerprint)
        findings.extend(poison_findings)
        
        return findings
    
    async def _test_tool_poisoning(self, target_info: Any, fingerprint: Any) -> List[Finding]:
        """Test for tool poisoning via safe payload injection."""
        findings = []
        
        # Safe test payloads that should NOT execute
        test_payloads = [
            "MCPReconX_TEST_12345",
            "__mcpreconx_test__",
            "<!-- TEST_POISON -->"
        ]
        
        for tool in fingerprint.tools:
            tool_name = tool.get("name")
            input_schema = tool.get("inputSchema", {})
            
            # Check if tool accepts string parameters
            properties = input_schema.get("properties", {})
            
            for param_name, param_spec in properties.items():
                if param_spec.get("type") == "string":
                    # This tool accepts string input - potential injection point
                    finding = Finding(
                        title=f"Potential Injection Point in Tool '{tool_name}'",
                        description=f"Tool '{tool_name}' accepts string parameter '{param_name}' "
                                   "which could be vulnerable to injection attacks.",
                        severity="low",
                        category="injection_vector",
                        evidence={
                            "tool_name": tool_name,
                            "parameter": param_name,
                            "schema": param_spec
                        },
                        remediation="Implement strict input validation and sanitization. "
                                   "Use parameterized queries where applicable.",
                        cvss_score=3.0
                    )
                    findings.append(finding)
        
        return findings
