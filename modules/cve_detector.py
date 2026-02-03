"""
MCPReconX - CVE Detector Module
================================
Detects known CVEs and vulnerability patterns in MCP servers.

Based on research from:
- CVE-2025-49596: MCP Inspector RCE
- CVE-2025-6514: mcp-remote OS Command Injection
- CVE-2025-68143/68144/68145: Anthropic Git MCP vulnerabilities
- CVE-2025-66416: DNS Rebinding in MCP Python SDK
- CVE-2025-6515: Session Hijacking in oatpp-mcp
- CVE-2025-65513: SSRF in fetch-mcp

ETHICAL USE NOTICE:
This tool is intended for authorized security testing only.
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

import aiohttp
import websockets

from .utils import calculate_cvss_score, severity_from_cvss


@dataclass
class CVEFinding:
    """Container for CVE detection results."""
    cve_id: str
    name: str
    description: str
    severity: str
    cvss_score: float
    affected_versions: List[str]
    detection_method: str
    evidence: Dict[str, Any]
    remediation: str
    references: List[str]
    verified: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "affected_versions": self.affected_versions,
            "detection_method": self.detection_method,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
            "verified": self.verified
        }


class CVEDetector:
    """Detects known CVEs in MCP implementations."""
    
    # Known CVE database
    CVE_DATABASE = {
        "CVE-2025-49596": {
            "name": "MCP Inspector Unauthenticated RCE",
            "description": "MCP Inspector versions < 0.14.1 allow unauthenticated remote code execution via stdio command injection. The proxy accepts arbitrary commands without authentication.",
            "cvss_v3": 9.8,
            "cvss_v4": 9.4,
            "severity": "critical",
            "affected_versions": ["< 0.14.1"],
            "indicators": {
                "endpoints": ["/sse", "/message"],
                "ports": [6277, 6274],
                "headers": ["mcp-session-id"],
                "response_patterns": ["transportType", "stdio", "command="]
            },
            "test_payload": {
                "transportType": "stdio",
                "command": "echo",
                "args": ["CVE-2025-49596_TEST"]
            },
            "remediation": "Upgrade to MCP Inspector >= 0.14.1. Enable session token authentication and validate Host/Origin headers.",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2025-49596",
                "https://github.com/advisories/GHSA-xrp8-pp5p-9p92"
            ]
        },
        "CVE-2025-6514": {
            "name": "mcp-remote OS Command Injection",
            "description": "mcp-remote 0.0.5-0.1.15 allows OS command injection via crafted authorization_endpoint response URL, enabling RCE when connecting to untrusted MCP servers.",
            "cvss_v3": 9.6,
            "cvss_v4": 9.3,
            "severity": "critical",
            "affected_versions": ["0.0.5 - 0.1.15"],
            "indicators": {
                "package_name": "mcp-remote",
                "npm_package": True,
                "auth_endpoint_vulnerable": True
            },
            "test_payload": None,  # Would require malicious server
            "remediation": "Upgrade to mcp-remote >= 0.1.16. Only connect to trusted MCP servers over HTTPS.",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2025-6514",
                "https://github.com/advisories/GHSA-9f8h-5r6j-7v2x"
            ]
        },
        "CVE-2025-68143": {
            "name": "Anthropic Git MCP Path Traversal - git_init",
            "description": "git_init tool in mcp-server-git accepts arbitrary filesystem paths during repository creation without validation, allowing directory creation anywhere.",
            "cvss_v3": 8.8,
            "cvss_v4": 6.5,
            "severity": "high",
            "affected_versions": ["< 2025.9.25"],
            "indicators": {
                "tools": ["git_init"],
                "server_type": "git",
                "path_validation": False
            },
            "test_payload": {"repo_path": "../../../tmp/test_repo"},
            "remediation": "Upgrade to mcp-server-git >= 2025.9.25. git_init tool was removed.",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2025-68143",
                "https://github.com/modelcontextprotocol/server-git/security/advisories"
            ]
        },
        "CVE-2025-68144": {
            "name": "Anthropic Git MCP Argument Injection",
            "description": "git_diff and git_checkout functions pass user-controlled arguments directly to git CLI commands without sanitization, allowing argument injection.",
            "cvss_v3": 8.1,
            "cvss_v4": 6.4,
            "severity": "high",
            "affected_versions": ["< 2025.12.18"],
            "indicators": {
                "tools": ["git_diff", "git_checkout"],
                "server_type": "git",
                "argument_sanitization": False
            },
            "test_payload": {"file_path": "--output=/etc/passwd"},
            "remediation": "Upgrade to mcp-server-git >= 2025.12.18. Implement proper argument sanitization.",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2025-68144"
            ]
        },
        "CVE-2025-68145": {
            "name": "Anthropic Git MCP Path Validation Bypass",
            "description": "Path validation when using --repository flag to limit operations to a specific repository path can be bypassed, allowing access to arbitrary repositories.",
            "cvss_v3": 7.1,
            "cvss_v4": 6.3,
            "severity": "medium",
            "affected_versions": ["< 2025.12.18"],
            "indicators": {
                "server_type": "git",
                "repository_restriction": True,
                "path_validation_bypass": True
            },
            "test_payload": {"repo_path": "../other_repo"},
            "remediation": "Upgrade to mcp-server-git >= 2025.12.18. Implement strict path validation.",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2025-68145"
            ]
        },
        "CVE-2025-66416": {
            "name": "MCP Python SDK DNS Rebinding",
            "description": "MCP Python SDK < 1.23.0 does not enable DNS rebinding protection by default for HTTP-based servers, allowing attackers to bypass same-origin policy.",
            "cvss_v3": 7.6,
            "cvss_v4": 7.2,
            "severity": "high",
            "affected_versions": ["< 1.23.0"],
            "indicators": {
                "sdk": "python",
                "transport": ["http", "sse"],
                "dns_rebinding_protection": False
            },
            "test_payload": None,  # Requires DNS rebinding setup
            "remediation": "Upgrade to mcp Python SDK >= 1.23.0. Enable TransportSecuritySettings with DNS rebinding protection.",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2025-66416",
                "https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-8xxm-h78q-7pv8"
            ]
        },
        "CVE-2025-6515": {
            "name": "oatpp-mcp Session Hijacking via Predictable Session IDs",
            "description": "oatpp-mcp returns instance pointer as session ID, which is neither unique nor cryptographically secure, allowing session hijacking through ID prediction.",
            "cvss_v3": 8.2,
            "cvss_v4": 7.8,
            "severity": "high",
            "affected_versions": ["affected versions unknown"],
            "indicators": {
                "implementation": "oatpp-mcp",
                "session_id_pattern": "pointer",
                "transport": "sse"
            },
            "test_payload": None,  # Requires session spraying
            "remediation": "Use cryptographically secure random session IDs with at least 128 bits of entropy.",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2025-6515",
                "https://jfrog.com/blog/mcp-prompt-hijacking-vulnerability/"
            ]
        },
        "CVE-2025-65513": {
            "name": "fetch-mcp SSRF Vulnerability",
            "description": "fetch-mcp <= 1.0.2 has Server-Side Request Forgery vulnerability allowing attackers to bypass private IP validation and access internal network resources.",
            "cvss_v3": 8.5,
            "cvss_v4": 8.0,
            "severity": "high",
            "affected_versions": ["<= 1.0.2"],
            "indicators": {
                "package_name": "fetch-mcp",
                "tool_name": "fetch",
                "ssrf_vulnerable": True
            },
            "test_payload": {"url": "http://169.254.169.254/latest/meta-data/"},
            "remediation": "Upgrade to fetch-mcp > 1.0.2. Implement strict URL validation and block private IP ranges.",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2025-65513",
                "https://github.com/advisories/GHSA-8fxj-2g9q-8fjw"
            ]
        },
        "CVE-2025-53967": {
            "name": "Framelink Figma MCP RCE",
            "description": "Framelink Figma MCP Server has command injection in fetch-with-retry.ts fallback curl execution, allowing RCE via malicious URLs.",
            "cvss_v3": 9.1,
            "cvss_v4": 8.8,
            "severity": "critical",
            "affected_versions": ["affected"],
            "indicators": {
                "server_type": "framelink-figma",
                "fetch_fallback": "curl",
                "command_injection": True
            },
            "test_payload": {"url": "https://api.figma.com/v1/images/test?format=png&ids=0:6\"; touch /pwn; #"},
            "remediation": "Update Framelink Figma MCP Server. Use parameterized commands instead of shell interpolation.",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2025-53967",
                "https://www.imperva.com/blog/another-critical-rce-discovered-in-a-popular-mcp-server/"
            ]
        },
        "CVE-2025-5276": {
            "name": "Markdownify MCP SSRF",
            "description": "mcp-markdownify-server has SSRF in Markdownify.get() allowing access to internal resources via unvalidated URLs.",
            "cvss_v3": 7.5,
            "cvss_v4": 7.0,
            "severity": "high",
            "affected_versions": ["affected"],
            "indicators": {
                "server_type": "markdownify",
                "tool_name": "WebpageToMarkdownTool",
                "ssrf_vulnerable": True
            },
            "test_payload": {"url": "http://localhost:22/"},
            "remediation": "Update mcp-markdownify-server. Implement URL validation and block private IP ranges.",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2025-5276"
            ]
        }
    }
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger, args: Any):
        self.config = config
        self.logger = logger
        self.args = args
        self.timeout = config.get("scan", {}).get("timeout", 30)
        self.findings: List[CVEFinding] = []
    
    async def detect_all(self, target_info: Any, fingerprint: Any) -> List[CVEFinding]:
        """
        Run all CVE detection checks.
        
        Args:
            target_info: Validated target information
            fingerprint: Fingerprint results
        
        Returns:
            List of CVE findings
        """
        self.logger.info("Starting CVE detection phase...")
        
        # Check for MCP Inspector vulnerability
        await self._check_cve_2025_49596(target_info, fingerprint)
        
        # Check for Git MCP vulnerabilities
        await self._check_git_mcp_vulns(target_info, fingerprint)
        
        # Check for DNS rebinding vulnerability
        await self._check_dns_rebinding(target_info, fingerprint)
        
        # Check for SSRF vulnerabilities
        await self._check_ssrf_vulns(target_info, fingerprint)
        
        # Check for command injection patterns
        await self._check_command_injection(target_info, fingerprint)
        
        # Check for session management issues
        await self._check_session_issues(target_info, fingerprint)
        
        # Check for network binding issues (0.0.0.0)
        await self._check_network_binding(target_info, fingerprint)
        
        self.logger.info(f"CVE detection complete. Found {len(self.findings)} CVE matches.")
        return self.findings
    
    async def _check_cve_2025_49596(self, target_info: Any, fingerprint: Any):
        """Check for MCP Inspector unauthenticated RCE (CVE-2025-49596)."""
        cve_id = "CVE-2025-49596"
        cve_info = self.CVE_DATABASE[cve_id]
        
        # Check if target might be MCP Inspector
        indicators = cve_info["indicators"]
        
        # Check port
        parsed = urlparse(target_info.url)
        port = parsed.port or (6277 if "6277" in target_info.url else None)
        
        if port in indicators["ports"] or any(p in target_info.url for p in ["/sse", "/message"]):
            self.logger.warning(f"Potential MCP Inspector instance detected - checking for {cve_id}")
            
            # Try to detect version or unauthenticated access
            is_vulnerable = await self._test_inspector_vulnerability(target_info)
            
            if is_vulnerable:
                finding = CVEFinding(
                    cve_id=cve_id,
                    name=cve_info["name"],
                    description=cve_info["description"],
                    severity=cve_info["severity"],
                    cvss_score=cve_info["cvss_v4"],
                    affected_versions=cve_info["affected_versions"],
                    detection_method="Port/endpoint matching + unauthenticated access test",
                    evidence={
                        "target_url": target_info.url,
                        "indicators_found": ["port_match", "endpoint_match"],
                        "unauthenticated_access": True
                    },
                    remediation=cve_info["remediation"],
                    references=cve_info["references"],
                    verified=is_vulnerable
                )
                self.findings.append(finding)
                self.logger.critical(f"[!] {cve_id} detected: {cve_info['name']}")
    
    async def _test_inspector_vulnerability(self, target_info: Any) -> bool:
        """Test if MCP Inspector allows unauthenticated access."""
        try:
            async with aiohttp.ClientSession() as session:
                # Try to access SSE endpoint without auth
                test_url = urljoin(target_info.url, "/sse")
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=5),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        body = await response.text()
                        # Check for MCP Inspector indicators
                        if "transportType" in body or "mcp-session-id" in str(response.headers):
                            return True
        except Exception:
            pass
        return False
    
    async def _check_git_mcp_vulns(self, target_info: Any, fingerprint: Any):
        """Check for Anthropic Git MCP vulnerabilities."""
        # Check if this is a Git MCP server
        server_info = fingerprint.server_info if hasattr(fingerprint, 'server_info') else {}
        implementation = fingerprint.implementation if hasattr(fingerprint, 'implementation') else None
        
        tools = fingerprint.tools if hasattr(fingerprint, 'tools') else []
        tool_names = [t.get("name", "").lower() for t in tools]
        
        is_git_server = (
            implementation in ["mcp-server-git", "git"]
            or any("git" in name for name in tool_names)
            or any(t in tool_names for t in ["git_init", "git_diff", "git_checkout"])
        )
        
        if is_git_server:
            self.logger.info("Git MCP server detected - checking for Git MCP CVEs")
            
            # Check for CVE-2025-68143 (git_init)
            if "git_init" in tool_names:
                self._add_cve_finding("CVE-2025-68143", {
                    "tool_detected": "git_init",
                    "server_type": "git"
                })
            
            # Check for CVE-2025-68144 (git_diff, git_checkout)
            if any(t in tool_names for t in ["git_diff", "git_checkout"]):
                self._add_cve_finding("CVE-2025-68144", {
                    "tools_detected": [t for t in ["git_diff", "git_checkout"] if t in tool_names],
                    "server_type": "git"
                })
            
            # Check for CVE-2025-68145 (path validation)
            if any("repository" in str(t.get("inputSchema", {})) for t in tools):
                self._add_cve_finding("CVE-2025-68145", {
                    "repository_restriction_detected": True,
                    "server_type": "git"
                })
    
    async def _check_dns_rebinding(self, target_info: Any, fingerprint: Any):
        """Check for DNS rebinding vulnerability (CVE-2025-66416)."""
        # Check if using HTTP-based transport on localhost without auth
        parsed = urlparse(target_info.url)
        
        is_localhost = parsed.hostname in ["localhost", "127.0.0.1", "::1"]
        is_http = parsed.scheme in ["http", "https"]
        auth_required = fingerprint.auth_required if hasattr(fingerprint, 'auth_required') else False
        
        if is_localhost and is_http and not auth_required:
            # Check SDK version if available
            server_info = fingerprint.server_info if hasattr(fingerprint, 'server_info') else {}
            
            # Check for Python SDK
            implementation = fingerprint.implementation if hasattr(fingerprint, 'implementation') else None
            
            if implementation in ["fastmcp", "mcp-python", "python-mcp"]:
                self._add_cve_finding("CVE-2025-66416", {
                    "localhost_http": True,
                    "no_auth": True,
                    "sdk": "python"
                })
    
    async def _check_ssrf_vulns(self, target_info: Any, fingerprint: Any):
        """Check for SSRF vulnerabilities (CVE-2025-65513, CVE-2025-5276)."""
        tools = fingerprint.tools if hasattr(fingerprint, 'tools') else []
        
        for tool in tools:
            tool_name = tool.get("name", "").lower()
            description = tool.get("description", "").lower()
            
            # Check for fetch-related tools
            if any(kw in tool_name for kw in ["fetch", "download", "get", "request"]):
                # Check if URL parameter is accepted
                schema = tool.get("inputSchema", {})
                properties = schema.get("properties", {})
                
                for prop_name, prop_spec in properties.items():
                    if prop_spec.get("type") == "string":
                        if any(kw in prop_name.lower() for kw in ["url", "uri", "link", "endpoint"]):
                            # Potential SSRF vector
                            self._add_cve_finding("CVE-2025-65513", {
                                "tool_name": tool.get("name"),
                                "url_parameter": prop_name,
                                "ssrf_vector": True
                            })
    
    async def _check_command_injection(self, target_info: Any, fingerprint: Any):
        """Check for command injection vulnerabilities."""
        tools = fingerprint.tools if hasattr(fingerprint, 'tools') else []
        
        for tool in tools:
            tool_name = tool.get("name", "").lower()
            description = tool.get("description", "").lower()
            
            # Check for command execution indicators
            command_keywords = ["execute", "exec", "run", "shell", "command", "system", "eval"]
            
            if any(kw in tool_name for kw in command_keywords):
                schema = tool.get("inputSchema", {})
                properties = schema.get("properties", {})
                
                # Check for string parameters that might be command arguments
                for prop_name, prop_spec in properties.items():
                    if prop_spec.get("type") == "string":
                        if any(kw in prop_name.lower() for kw in ["command", "cmd", "args", "argument", "input"]):
                            self.logger.warning(f"Potential command injection vector in tool '{tool_name}'")
                            # Add as a finding but not a specific CVE
    
    async def _check_session_issues(self, target_info: Any, fingerprint: Any):
        """Check for session management issues (CVE-2025-6515)."""
        headers = target_info.headers if hasattr(target_info, 'headers') else {}
        
        # Check for session ID patterns
        session_header = headers.get("mcp-session-id", "")
        
        if session_header:
            # Check if session ID looks predictable (numeric, short, etc.)
            if session_header.isdigit() or len(session_header) < 32:
                self._add_cve_finding("CVE-2025-6515", {
                    "session_id": session_header[:10] + "...",
                    "predictable": True,
                    "pattern": "numeric" if session_header.isdigit() else "short"
                })
    
    async def _check_network_binding(self, target_info: Any, fingerprint: Any):
        """Check for 0.0.0.0 network binding (NeighborJack)."""
        # This requires network-level detection
        # Check if server responds on 0.0.0.0 or binds to all interfaces
        
        parsed = urlparse(target_info.url)
        
        # If the server is accessible via non-localhost IP, it might bind to 0.0.0.0
        if parsed.hostname not in ["localhost", "127.0.0.1", "::1"]:
            self.logger.info("Server accessible via non-localhost address - may bind to 0.0.0.0")
            # This is informational, not necessarily a vulnerability by itself
    
    def _add_cve_finding(self, cve_id: str, evidence: Dict[str, Any]):
        """Add a CVE finding to the results."""
        if cve_id not in self.CVE_DATABASE:
            return
        
        cve_info = self.CVE_DATABASE[cve_id]
        
        # Check if we already found this CVE
        if any(f.cve_id == cve_id for f in self.findings):
            return
        
        finding = CVEFinding(
            cve_id=cve_id,
            name=cve_info["name"],
            description=cve_info["description"],
            severity=cve_info["severity"],
            cvss_score=cve_info.get("cvss_v4", cve_info.get("cvss_v3", 7.0)),
            affected_versions=cve_info["affected_versions"],
            detection_method="Pattern matching and behavior analysis",
            evidence=evidence,
            remediation=cve_info["remediation"],
            references=cve_info["references"],
            verified=False  # Detection is pattern-based, not exploitation
        )
        
        self.findings.append(finding)
        self.logger.critical(f"[!] {cve_id} potentially detected: {cve_info['name']}")
