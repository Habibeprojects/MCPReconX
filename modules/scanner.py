"""
MCPReconX - Active Scanner Module (Enhanced)
=============================================
Performs active security scanning against MCP servers.

Enhanced with real-world vulnerability patterns from:
- CVE-2025-49596: MCP Inspector RCE
- CVE-2025-6514: mcp-remote Command Injection
- CVE-2025-68143/68144/68145: Anthropic Git MCP
- CVE-2025-66416: DNS Rebinding
- CVE-2025-6515: Session Hijacking
- Tool Poisoning, Confused Deputy, Rug Pull attacks

ETHICAL USE NOTICE:
This tool is intended for authorized security testing only.
All tests are designed to be safe and non-destructive.
"""

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urljoin

import aiohttp
import websockets

from .utils import calculate_cvss_score, severity_from_cvss
from .cve_detector import CVEDetector
from .attack_patterns import AttackPatternDetector


@dataclass
class Vulnerability:
    """Container for vulnerability findings."""
    id: str
    name: str
    description: str
    severity: str
    cvss_score: float
    category: str
    affected_component: str
    proof_of_concept: Dict[str, Any]
    remediation: str
    references: List[str] = field(default_factory=list)
    verified: bool = False
    cve_id: Optional[str] = None
    
    def __post_init__(self):
        if not self.id:
            self.id = f"MCP-VULN-{uuid.uuid4().hex[:8].upper()}"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "category": self.category,
            "affected_component": self.affected_component,
            "proof_of_concept": self.proof_of_concept,
            "remediation": self.remediation,
            "references": self.references,
            "verified": self.verified,
            "cve_id": self.cve_id
        }


class ActiveScanner:
    """Performs active security scanning on MCP servers."""
    
    # Test payloads for various vulnerability classes
    SSRF_TEST_URLS = [
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://localhost:22/",  # SSH port
        "http://127.0.0.1:80/",  # Local HTTP
        "file:///etc/passwd",  # File protocol
    ]
    
    PATH_TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd",
        "....//....//etc/passwd",
        "%2e%2e%2fetc%2fpasswd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    ]
    
    COMMAND_INJECTION_PAYLOADS = [
        ";echo 'MCP_TEST'",
        "| echo 'MCP_TEST'",
        "`echo MCP_TEST`",
        "$(echo MCP_TEST)",
        "& whoami",
        "&& id",
    ]
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger, args: Any):
        self.config = config
        self.logger = logger
        self.args = args
        self.timeout = config.get("scan", {}).get("timeout", 30)
        self.delay = config.get("scan", {}).get("delay_between_requests", 0)
        self.risk_level = args.risk
        self.intensity = args.level
        self.vulnerabilities: List[Vulnerability] = []
        
        # Initialize specialized detectors
        self.cve_detector = CVEDetector(config, logger, args)
        self.attack_detector = AttackPatternDetector(config, logger)
    
    async def scan(self, target_info: Any, fingerprint: Any) -> List[Vulnerability]:
        """
        Run all active security scans.
        
        Args:
            target_info: Validated target information
            fingerprint: Fingerprint results
        
        Returns:
            List of discovered vulnerabilities
        """
        self.logger.info("Starting active scanning phase...")
        
        # Run CVE detection
        cve_findings = await self.cve_detector.detect_all(target_info, fingerprint)
        for cve in cve_findings:
            vuln = Vulnerability(
                id=f"MCP-CVE-{cve.cve_id.replace('-', '')}",
                name=cve.name,
                description=cve.description,
                severity=cve.severity,
                cvss_score=cve.cvss_score,
                category="known_cve",
                affected_component=cve.evidence.get("tool_detected", "unknown"),
                proof_of_concept=cve.evidence,
                remediation=cve.remediation,
                references=cve.references,
                verified=cve.verified,
                cve_id=cve.cve_id
            )
            self.vulnerabilities.append(vuln)
        
        # Run attack pattern detection
        attack_findings = self.attack_detector.detect_all(fingerprint)
        for finding in attack_findings:
            vuln = Vulnerability(
                id=f"MCP-ATTACK-{finding.pattern_name.replace(' ', '-').upper()[:20]}",
                name=finding.pattern_name,
                description=finding.description,
                severity=finding.severity,
                cvss_score=finding.cvss_score,
                category=finding.category,
                affected_component=finding.affected_component,
                proof_of_concept=finding.evidence,
                remediation=finding.remediation,
                references=finding.references
            )
            self.vulnerabilities.append(vuln)
        
        # Run scans based on risk level
        if self.risk_level in ["low", "medium", "high"]:
            # Authentication bypass tests
            auth_vulns = await self._test_auth_bypass(target_info, fingerprint)
            self.vulnerabilities.extend(auth_vulns)
            
            if self.delay:
                await asyncio.sleep(self.delay)
            
            # Tool injection tests
            injection_vulns = await self._test_tool_injection(target_info, fingerprint)
            self.vulnerabilities.extend(injection_vulns)
            
            if self.delay:
                await asyncio.sleep(self.delay)
        
        if self.risk_level in ["medium", "high"]:
            # Privilege escalation tests
            priv_vulns = await self._test_privilege_escalation(target_info, fingerprint)
            self.vulnerabilities.extend(priv_vulns)
            
            if self.delay:
                await asyncio.sleep(self.delay)
            
            # Confused deputy tests
            deputy_vulns = await self._test_confused_deputy(target_info, fingerprint)
            self.vulnerabilities.extend(deputy_vulns)
            
            if self.delay:
                await asyncio.sleep(self.delay)
            
            # SSRF tests
            ssrf_vulns = await self._test_ssrf(target_info, fingerprint)
            self.vulnerabilities.extend(ssrf_vulns)
            
            if self.delay:
                await asyncio.sleep(self.delay)
        
        if self.risk_level == "high":
            # Data exfiltration path tests
            exfil_vulns = await self._test_data_exfil_paths(target_info, fingerprint)
            self.vulnerabilities.extend(exfil_vulns)
            
            if self.delay:
                await asyncio.sleep(self.delay)
            
            # Input validation tests
            validation_vulns = await self._test_input_validation(target_info, fingerprint)
            self.vulnerabilities.extend(validation_vulns)
            
            if self.delay:
                await asyncio.sleep(self.delay)
            
            # Path traversal tests
            path_vulns = await self._test_path_traversal(target_info, fingerprint)
            self.vulnerabilities.extend(path_vulns)
        
        self.logger.info(f"Active scanning complete. Found {len(self.vulnerabilities)} vulnerabilities.")
        return self.vulnerabilities
    
    async def _test_auth_bypass(self, target_info: Any, fingerprint: Any) -> List[Vulnerability]:
        """Test for authentication bypass vulnerabilities."""
        vulnerabilities = []
        
        if not fingerprint.auth_required:
            self.logger.info("Authentication not required - checking for missing auth")
            
            # Check if sensitive operations are accessible
            if fingerprint.tools:
                sensitive_tools = self._identify_sensitive_tools(fingerprint.tools)
                if sensitive_tools:
                    vuln = Vulnerability(
                        id="MCP-AUTH-001",
                        name="Missing Authentication on Sensitive Operations",
                        description="The MCP server allows access to sensitive tools without authentication. "
                                   f"Found {len(sensitive_tools)} sensitive tools accessible without credentials.",
                        severity="high",
                        cvss_score=7.5,
                        category="authentication",
                        affected_component="access_control",
                        proof_of_concept={
                            "sensitive_tools": [t.get("name") for t in sensitive_tools[:5]],
                            "test_method": "Unauthenticated tool enumeration"
                        },
                        remediation="Implement authentication for all MCP endpoints. "
                                   "Use OAuth 2.0 or API keys with proper scope validation.",
                        references=[
                            "https://modelcontextprotocol.io/specification/security",
                            "https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/"
                        ],
                        verified=True
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_tool_injection(self, target_info: Any, fingerprint: Any) -> List[Vulnerability]:
        """Test for tool-level injection vulnerabilities."""
        vulnerabilities = []
        
        # Check for tools that accept and execute code
        code_tools = self._find_code_execution_tools(fingerprint.tools)
        
        for tool in code_tools:
            vuln = Vulnerability(
                id="MCP-INJ-001",
                name=f"Potential Code Injection in Tool '{tool.get('name')}'",
                description=f"Tool '{tool.get('name')}' appears to accept and execute code. "
                           "This could lead to remote code execution if input is not properly sanitized. "
                           "Similar to CVE-2025-6514 and CVE-2025-53967.",
                severity="critical",
                cvss_score=9.8,
                category="injection",
                affected_component=f"tool:{tool.get('name')}",
                proof_of_concept={
                    "tool_name": tool.get("name"),
                    "tool_description": tool.get("description"),
                    "input_schema": tool.get("inputSchema"),
                    "test_payload": "__import__('os').system('id')  # Safe test - not executed",
                    "related_cves": ["CVE-2025-6514", "CVE-2025-53967"]
                },
                remediation="Implement strict input validation. Use sandboxed execution environments. "
                           "Consider using allowlists for permitted operations. Never use shell interpolation.",
                references=[
                    "https://owasp.org/www-community/attacks/Code_Injection",
                    "https://nvd.nist.gov/vuln/detail/CVE-2025-6514",
                    "https://nvd.nist.gov/vuln/detail/CVE-2025-53967"
                ],
                verified=False
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_privilege_escalation(self, target_info: Any, fingerprint: Any) -> List[Vulnerability]:
        """Test for privilege escalation vulnerabilities."""
        vulnerabilities = []
        
        # Check for admin/debug tools accessible to regular users
        admin_tools = self._find_admin_tools(fingerprint.tools)
        
        if admin_tools and not fingerprint.auth_required:
            vuln = Vulnerability(
                id="MCP-PRIV-001",
                name="Administrative Tools Accessible Without Privileges",
                description=f"Found {len(admin_tools)} administrative tools accessible without proper authorization. "
                           "This could allow privilege escalation similar to CVE-2025-68145.",
                severity="high",
                cvss_score=8.0,
                category="privilege_escalation",
                affected_component="access_control",
                proof_of_concept={
                    "admin_tools": [t.get("name") for t in admin_tools],
                    "auth_required": fingerprint.auth_required,
                    "related_cve": "CVE-2025-68145"
                },
                remediation="Implement role-based access control (RBAC). "
                           "Require authentication and authorization for administrative functions.",
                references=[
                    "https://owasp.org/www-community/vulnerabilities/Missing_function_level_access_control",
                    "https://nvd.nist.gov/vuln/detail/CVE-2025-68145"
                ],
                verified=True
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_confused_deputy(self, target_info: Any, fingerprint: Any) -> List[Vulnerability]:
        """Test for confused deputy vulnerabilities."""
        vulnerabilities = []
        
        # Look for tools that access resources on behalf of users
        deputy_tools = self._find_deputy_tools(fingerprint.tools)
        
        for tool in deputy_tools:
            vuln = Vulnerability(
                id="MCP-DEPUTY-001",
                name=f"Potential Confused Deputy in Tool '{tool.get('name')}'",
                description=f"Tool '{tool.get('name')}' acts on behalf of users but may not properly "
                           "validate the user's authority to access requested resources. "
                           "Similar to OAuth Proxy confused deputy attacks.",
                severity="medium",
                cvss_score=6.5,
                category="confused_deputy",
                affected_component=f"tool:{tool.get('name')}",
                proof_of_concept={
                    "tool_name": tool.get("name"),
                    "description": tool.get("description"),
                    "risk": "Tool may access resources without verifying user permissions"
                },
                remediation="Implement proper authorization checks. Validate user permissions "
                           "before accessing resources on their behalf. Use per-client OAuth registrations.",
                references=[
                    "https://cwe.mitre.org/data/definitions/441.html",
                    "https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices"
                ],
                verified=False
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_ssrf(self, target_info: Any, fingerprint: Any) -> List[Vulnerability]:
        """Test for SSRF vulnerabilities."""
        vulnerabilities = []
        
        # Find tools that make external network requests
        network_tools = self._find_network_tools(fingerprint.tools)
        
        for tool in network_tools:
            # Check if URL parameter is accepted
            schema = tool.get("inputSchema", {})
            properties = schema.get("properties", {})
            
            for prop_name, prop_spec in properties.items():
                if prop_spec.get("type") == "string":
                    if any(kw in prop_name.lower() for kw in ["url", "uri", "link", "endpoint", "address"]):
                        vuln = Vulnerability(
                            id="MCP-SSRF-001",
                            name=f"Potential SSRF in Tool '{tool.get('name')}'",
                            description=f"Tool '{tool.get('name')}' can make network requests to user-controlled URLs. "
                                       "This could be abused for SSRF attacks similar to CVE-2025-65513 and CVE-2025-5276.",
                            severity="high",
                            cvss_score=8.0,
                            category="ssrf",
                            affected_component=f"tool:{tool.get('name')}",
                            proof_of_concept={
                                "tool_name": tool.get("name"),
                                "url_parameter": prop_name,
                                "test_urls": self.SSRF_TEST_URLS[:2],
                                "related_cves": ["CVE-2025-65513", "CVE-2025-5276"]
                            },
                            remediation="Implement strict URL validation. Block private IP ranges and internal services. "
                                       "Use allowlists for permitted destinations. Implement egress filtering.",
                            references=[
                                "https://owasp.org/www-community/vulnerabilities/Server_Side_Request_Forgery",
                                "https://nvd.nist.gov/vuln/detail/CVE-2025-65513",
                                "https://nvd.nist.gov/vuln/detail/CVE-2025-5276"
                            ],
                            verified=False
                        )
                        vulnerabilities.append(vuln)
                        break  # One SSRF finding per tool is enough
        
        return vulnerabilities
    
    async def _test_data_exfil_paths(self, target_info: Any, fingerprint: Any) -> List[Vulnerability]:
        """Test for potential data exfiltration paths."""
        vulnerabilities = []
        
        # Find tools that make external network requests
        network_tools = self._find_network_tools(fingerprint.tools)
        
        for tool in network_tools:
            vuln = Vulnerability(
                id="MCP-EXFIL-001",
                name=f"Potential Data Exfiltration via Tool '{tool.get('name')}'",
                description=f"Tool '{tool.get('name')}' can make network requests which could be "
                           "abused for data exfiltration or SSRF attacks.",
                severity="medium",
                cvss_score=5.5,
                category="data_exfiltration",
                affected_component=f"tool:{tool.get('name')}",
                proof_of_concept={
                    "tool_name": tool.get("name"),
                    "description": tool.get("description"),
                    "risk": "Tool may be used to send data to external servers"
                },
                remediation="Implement egress filtering. Restrict external network access. "
                           "Log and monitor outbound connections. Implement DLP controls.",
                references=[
                    "https://owasp.org/www-community/vulnerabilities/Server_Side_Request_Forgery",
                    "https://cwe.mitre.org/data/definitions/918.html"
                ],
                verified=False
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_input_validation(self, target_info: Any, fingerprint: Any) -> List[Vulnerability]:
        """Test for input validation weaknesses."""
        vulnerabilities = []
        
        # Check for tools with weak input validation
        weak_validation_tools = []
        
        for tool in fingerprint.tools:
            schema = tool.get("inputSchema", {})
            properties = schema.get("properties", {})
            
            # Check for missing validation
            for prop_name, prop_spec in properties.items():
                # Check for string fields without pattern/maxLength
                if prop_spec.get("type") == "string":
                    if "pattern" not in prop_spec and "maxLength" not in prop_spec:
                        weak_validation_tools.append({
                            "tool": tool.get("name"),
                            "parameter": prop_name
                        })
        
        if weak_validation_tools:
            vuln = Vulnerability(
                id="MCP-INPUT-001",
                name="Weak Input Validation Detected",
                description=f"Found {len(weak_validation_tools)} parameters without proper validation. "
                           "This could lead to injection attacks similar to CVE-2025-68144.",
                severity="medium",
                cvss_score=5.0,
                category="input_validation",
                affected_component="input_validation",
                proof_of_concept={
                    "weak_parameters": weak_validation_tools[:10],
                    "issue": "Missing pattern/maxLength validation",
                    "related_cve": "CVE-2025-68144"
                },
                remediation="Add input validation to all parameters. Use JSON Schema patterns, "
                           "maxLength, and enum constraints where applicable.",
                references=[
                    "https://owasp.org/www-community/vulnerabilities/Improper_Input_Validation",
                    "https://nvd.nist.gov/vuln/detail/CVE-2025-68144"
                ],
                verified=True
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_path_traversal(self, target_info: Any, fingerprint: Any) -> List[Vulnerability]:
        """Test for path traversal vulnerabilities."""
        vulnerabilities = []
        
        # Find tools that accept file paths
        file_tools = []
        for tool in fingerprint.tools:
            tool_name = tool.get("name", "").lower()
            description = tool.get("description", "").lower()
            
            if any(kw in tool_name or kw in description for kw in ["file", "path", "directory", "read", "write"]):
                schema = tool.get("inputSchema", {})
                properties = schema.get("properties", {})
                
                for prop_name, prop_spec in properties.items():
                    if prop_spec.get("type") == "string":
                        if any(kw in prop_name.lower() for kw in ["path", "file", "directory", "location"]):
                            file_tools.append({
                                "tool": tool.get("name"),
                                "parameter": prop_name
                            })
        
        if file_tools:
            vuln = Vulnerability(
                id="MCP-PATH-001",
                name="Potential Path Traversal Vectors",
                description=f"Found {len(file_tools)} file path parameters that may be vulnerable to path traversal. "
                           "Similar to CVE-2025-68143 and CVE-2025-68145.",
                severity="high",
                cvss_score=7.5,
                category="path_traversal",
                affected_component="file_operations",
                proof_of_concept={
                    "file_path_parameters": file_tools[:10],
                    "test_payloads": self.PATH_TRAVERSAL_PAYLOADS[:3],
                    "related_cves": ["CVE-2025-68143", "CVE-2025-68145"]
                },
                remediation="Implement strict path validation. Use chroot jails or sandboxed file access. "
                           "Validate paths against allowed directories. Block path traversal sequences.",
                references=[
                    "https://owasp.org/www-community/attacks/Path_Traversal",
                    "https://nvd.nist.gov/vuln/detail/CVE-2025-68143",
                    "https://nvd.nist.gov/vuln/detail/CVE-2025-68145"
                ],
                verified=False
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _identify_sensitive_tools(self, tools: List[Dict]) -> List[Dict]:
        """Identify tools that perform sensitive operations."""
        sensitive_keywords = [
            "delete", "remove", "drop", "admin", "config",
            "password", "secret", "key", "token", "auth",
            "execute", "exec", "run", "shell", "system"
        ]
        
        sensitive = []
        for tool in tools:
            tool_text = f"{tool.get('name', '')} {tool.get('description', '')}".lower()
            if any(kw in tool_text for kw in sensitive_keywords):
                sensitive.append(tool)
        
        return sensitive
    
    def _find_code_execution_tools(self, tools: List[Dict]) -> List[Dict]:
        """Find tools that may execute code."""
        code_keywords = [
            "execute", "eval", "exec", "run", "code", "script",
            "python", "javascript", "shell", "command", "system",
            "compile", "interpret", "subprocess", "spawn"
        ]
        
        code_tools = []
        for tool in tools:
            tool_text = f"{tool.get('name', '')} {tool.get('description', '')}".lower()
            if any(kw in tool_text for kw in code_keywords):
                code_tools.append(tool)
        
        return code_tools
    
    def _find_admin_tools(self, tools: List[Dict]) -> List[Dict]:
        """Find administrative tools."""
        admin_keywords = [
            "admin", "manage", "configure", "settings", "user",
            "permission", "role", "access", "debug", "logs",
            "system", "restart", "stop", "kill"
        ]
        
        admin_tools = []
        for tool in tools:
            tool_text = f"{tool.get('name', '')} {tool.get('description', '')}".lower()
            if any(kw in tool_text for kw in admin_keywords):
                admin_tools.append(tool)
        
        return admin_tools
    
    def _find_deputy_tools(self, tools: List[Dict]) -> List[Dict]:
        """Find tools that act as confused deputies."""
        deputy_keywords = [
            "access", "read", "write", "fetch", "get", "post",
            "request", "proxy", "forward", "delegate", "impersonate",
            "on behalf", "act as", "delegate"
        ]
        
        deputy_tools = []
        for tool in tools:
            tool_text = f"{tool.get('name', '')} {tool.get('description', '')}".lower()
            if any(kw in tool_text for kw in deputy_keywords):
                deputy_tools.append(tool)
        
        return deputy_tools
    
    def _find_network_tools(self, tools: List[Dict]) -> List[Dict]:
        """Find tools that make network requests."""
        network_keywords = [
            "http", "request", "fetch", "url", "webhook", "callback",
            "download", "upload", "connect", "socket", "api",
            "curl", "wget", "network", "external"
        ]
        
        network_tools = []
        for tool in tools:
            tool_text = f"{tool.get('name', '')} {tool.get('description', '')}".lower()
            if any(kw in tool_text for kw in network_keywords):
                network_tools.append(tool)
        
        return network_tools
