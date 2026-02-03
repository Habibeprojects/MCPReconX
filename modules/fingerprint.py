"""
MCPReconX - Fingerprinting Module
==================================
Identifies MCP server implementation, version, and capabilities.

ETHICAL USE NOTICE:
This tool is intended for authorized security testing only.
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urljoin

import aiohttp
import websockets


@dataclass
class FingerprintResult:
    """Container for fingerprinting results."""
    implementation: Optional[str] = None
    version: Optional[str] = None
    mcp_version: Optional[str] = None
    auth_method: Optional[str] = None
    auth_required: bool = False
    tools: List[Dict[str, Any]] = field(default_factory=list)
    resources: List[Dict[str, Any]] = field(default_factory=list)
    prompts: List[Dict[str, Any]] = field(default_factory=list)
    capabilities: Dict[str, Any] = field(default_factory=dict)
    server_info: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    behavior_signatures: List[str] = field(default_factory=list)
    security_features: Dict[str, bool] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "implementation": self.implementation,
            "version": self.version,
            "mcp_version": self.mcp_version,
            "auth_method": self.auth_method,
            "auth_required": self.auth_required,
            "tools_count": len(self.tools),
            "tools": self.tools[:10],  # Limit for report
            "resources_count": len(self.resources),
            "prompts_count": len(self.prompts),
            "capabilities": self.capabilities,
            "server_info": self.server_info,
            "headers": dict(self.headers),
            "behavior_signatures": self.behavior_signatures,
            "security_features": self.security_features
        }


class FingerprintEngine:
    """Fingerprints MCP server implementations."""
    
    # Known implementation signatures
    IMPLEMENTATION_SIGNATURES = {
        "langchain-mcp": {
            "headers": ["langchain", "mcp-adapter"],
            "body_patterns": [r"langchain", r"mcp[_-]?adapter"],
            "server_info_fields": ["langchain"]
        },
        "fastmcp": {
            "headers": ["fastmcp"],
            "body_patterns": [r"fastmcp", r"python-mcp"],
            "server_info_fields": ["fastmcp"]
        },
        "mcp-typescript": {
            "headers": ["@modelcontextprotocol"],
            "body_patterns": [r"@modelcontextprotocol/sdk", r"typescript-mcp"],
            "server_info_fields": ["@modelcontextprotocol"]
        },
        "custom-python": {
            "body_patterns": [r"mcp\.server", r"Server\\(.*capabilities"],
            "server_info_fields": []
        },
        "custom-node": {
            "body_patterns": [r"@modelcontextprotocol", r"Server\\s*\\{"],
            "server_info_fields": []
        }
    }
    
    # Authentication indicators
    AUTH_INDICATORS = {
        "bearer": ["authorization", "bearer", "token"],
        "api_key": ["x-api-key", "api-key", "apikey"],
        "oauth": ["oauth", "access_token", "refresh_token"],
        "basic": ["basic auth", "www-authenticate"],
        "custom": ["x-auth", "x-mcp-auth"]
    }
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger, args: Any):
        self.config = config
        self.logger = logger
        self.args = args
        self.timeout = config.get("scan", {}).get("timeout", 30)
        self.delay = config.get("scan", {}).get("delay_between_requests", 0)
    
    async def scan(self, target_info: Any) -> FingerprintResult:
        """
        Perform comprehensive fingerprinting.
        
        Args:
            target_info: Validated TargetInfo object
        
        Returns:
            FingerprintResult with all fingerprinting data
        """
        self.logger.info("Starting fingerprinting phase...")
        
        result = FingerprintResult()
        result.mcp_version = target_info.mcp_version
        result.headers = target_info.headers
        
        # Detect implementation
        result.implementation = await self._detect_implementation(target_info)
        
        # Detect authentication
        result.auth_method, result.auth_required = await self._detect_auth(target_info)
        
        # Enumerate capabilities
        capabilities = await self._enumerate_capabilities(target_info)
        result.tools = capabilities.get("tools", [])
        result.resources = capabilities.get("resources", [])
        result.prompts = capabilities.get("prompts", [])
        result.capabilities = capabilities.get("server_capabilities", {})
        result.server_info = capabilities.get("server_info", {})
        
        # Extract version from server info
        if result.server_info:
            result.version = result.server_info.get("version")
        
        # Analyze security features
        result.security_features = self._analyze_security_features(result, target_info)
        
        # Collect behavior signatures
        result.behavior_signatures = await self._collect_signatures(target_info)
        
        self.logger.info(f"Fingerprinting complete. Detected: {result.implementation or 'Unknown'}")
        
        return result
    
    async def _detect_implementation(self, target_info: Any) -> Optional[str]:
        """Detect server implementation type."""
        self.logger.debug("Detecting implementation...")
        
        headers_str = str(target_info.headers).lower()
        
        # Check headers
        for impl, signatures in self.IMPLEMENTATION_SIGNATURES.items():
            for header_sig in signatures.get("headers", []):
                if header_sig.lower() in headers_str:
                    self.logger.info(f"Implementation detected via headers: {impl}")
                    return impl
        
        # Need to probe for body patterns
        response_body = await self._fetch_server_info(target_info)
        
        if response_body:
            body_str = json.dumps(response_body).lower()
            
            for impl, signatures in self.IMPLEMENTATION_SIGNATURES.items():
                for pattern in signatures.get("body_patterns", []):
                    if re.search(pattern, body_str, re.IGNORECASE):
                        self.logger.info(f"Implementation detected via body: {impl}")
                        return impl
        
        return None
    
    async def _detect_auth(self, target_info: Any) -> tuple:
        """Detect authentication method and requirements."""
        self.logger.debug("Detecting authentication...")
        
        headers = target_info.headers
        auth_method = None
        auth_required = False
        
        # Check for auth headers
        header_str = str(headers).lower()
        
        for auth_type, indicators in self.AUTH_INDICATORS.items():
            for indicator in indicators:
                if indicator in header_str:
                    auth_method = auth_type
                    break
        
        # Test if auth is required by making unauthenticated request
        if target_info.protocol == "http":
            auth_required = await self._test_auth_required_http(target_info)
        
        return auth_method, auth_required
    
    async def _test_auth_required_http(self, target_info: Any) -> bool:
        """Test if authentication is required."""
        try:
            async with aiohttp.ClientSession() as session:
                # Try to list tools without auth
                request = {
                    "jsonrpc": "2.0",
                    "id": 99,
                    "method": "tools/list"
                }
                
                endpoint = target_info.endpoints.get("jsonrpc", target_info.url)
                
                async with session.post(
                    endpoint,
                    json=request,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    if response.status == 401 or response.status == 403:
                        return True
                    
                    # Check for auth error in response
                    try:
                        data = await response.json()
                        if "error" in data:
                            error_str = str(data["error"]).lower()
                            if any(x in error_str for x in ["auth", "unauthorized", "forbidden", "token"]):
                                return True
                    except:
                        pass
        
        except Exception as e:
            self.logger.debug(f"Auth test error: {e}")
        
        return False
    
    async def _enumerate_capabilities(self, target_info: Any) -> Dict[str, Any]:
        """Enumerate server capabilities."""
        self.logger.info("Enumerating capabilities...")
        
        if target_info.protocol == "http":
            return await self._enumerate_http(target_info)
        elif target_info.protocol == "websocket":
            return await self._enumerate_ws(target_info)
        
        return {}
    
    async def _enumerate_http(self, target_info: Any) -> Dict[str, Any]:
        """Enumerate via HTTP transport."""
        result = {
            "tools": [],
            "resources": [],
            "prompts": [],
            "server_capabilities": {},
            "server_info": {}
        }
        
        headers = {
            "User-Agent": self.config.get("scan", {}).get("user_agent", "MCPReconX/1.0"),
            "Content-Type": "application/json"
        }
        
        # Add auth if provided
        if self.args.auth_token:
            headers["Authorization"] = f"Bearer {self.args.auth_token}"
        elif self.args.api_key:
            headers["X-API-Key"] = self.args.api_key
        
        endpoint = target_info.endpoints.get("jsonrpc", target_info.url)
        
        async with aiohttp.ClientSession() as session:
            # Get tools list
            tools = await self._fetch_tools_list(session, endpoint, headers)
            result["tools"] = tools
            
            if self.delay:
                await asyncio.sleep(self.delay)
            
            # Get resources list
            resources = await self._fetch_resources_list(session, endpoint, headers)
            result["resources"] = resources
            
            if self.delay:
                await asyncio.sleep(self.delay)
            
            # Get prompts list
            prompts = await self._fetch_prompts_list(session, endpoint, headers)
            result["prompts"] = prompts
            
            # Get server info from initialize if available
            server_info = await self._fetch_server_info(target_info)
            if server_info:
                if "result" in server_info:
                    result["server_info"] = server_info["result"].get("serverInfo", {})
                    result["server_capabilities"] = server_info["result"].get("capabilities", {})
        
        return result
    
    async def _enumerate_ws(self, target_info: Any) -> Dict[str, Any]:
        """Enumerate via WebSocket transport."""
        result = {
            "tools": [],
            "resources": [],
            "prompts": [],
            "server_capabilities": {},
            "server_info": {}
        }
        
        try:
            async with websockets.connect(target_info.url, ssl=False) as ws:
                # Send initialize
                init_request = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {
                            "name": "mcpreconx",
                            "version": "1.0.0"
                        }
                    }
                }
                
                await ws.send(json.dumps(init_request))
                init_response = await asyncio.wait_for(ws.recv(), timeout=self.timeout)
                init_data = json.loads(init_response)
                
                if "result" in init_data:
                    result["server_info"] = init_data["result"].get("serverInfo", {})
                    result["server_capabilities"] = init_data["result"].get("capabilities", {})
                
                # Get tools
                tools_request = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
                await ws.send(json.dumps(tools_request))
                tools_response = await asyncio.wait_for(ws.recv(), timeout=self.timeout)
                tools_data = json.loads(tools_response)
                
                if "result" in tools_data and "tools" in tools_data["result"]:
                    result["tools"] = tools_data["result"]["tools"]
                
                # Get resources
                resources_request = {"jsonrpc": "2.0", "id": 3, "method": "resources/list"}
                await ws.send(json.dumps(resources_request))
                resources_response = await asyncio.wait_for(ws.recv(), timeout=self.timeout)
                resources_data = json.loads(resources_response)
                
                if "result" in resources_data and "resources" in resources_data["result"]:
                    result["resources"] = resources_data["result"]["resources"]
                
                # Get prompts
                prompts_request = {"jsonrpc": "2.0", "id": 4, "method": "prompts/list"}
                await ws.send(json.dumps(prompts_request))
                prompts_response = await asyncio.wait_for(ws.recv(), timeout=self.timeout)
                prompts_data = json.loads(prompts_response)
                
                if "result" in prompts_data and "prompts" in prompts_data["result"]:
                    result["prompts"] = prompts_data["result"]["prompts"]
        
        except Exception as e:
            self.logger.debug(f"WS enumeration error: {e}")
        
        return result
    
    async def _fetch_tools_list(self, session: aiohttp.ClientSession, endpoint: str, headers: Dict[str, str]) -> List[Dict]:
        """Fetch tools list from server."""
        request = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        
        try:
            async with session.post(
                endpoint,
                headers=headers,
                json=request,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                ssl=False
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    if "result" in data and "tools" in data["result"]:
                        return data["result"]["tools"]
        except Exception as e:
            self.logger.debug(f"Tools fetch error: {e}")
        
        return []
    
    async def _fetch_resources_list(self, session: aiohttp.ClientSession, endpoint: str, headers: Dict[str, str]) -> List[Dict]:
        """Fetch resources list from server."""
        request = {"jsonrpc": "2.0", "id": 3, "method": "resources/list"}
        
        try:
            async with session.post(
                endpoint,
                headers=headers,
                json=request,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                ssl=False
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    if "result" in data and "resources" in data["result"]:
                        return data["result"]["resources"]
        except Exception as e:
            self.logger.debug(f"Resources fetch error: {e}")
        
        return []
    
    async def _fetch_prompts_list(self, session: aiohttp.ClientSession, endpoint: str, headers: Dict[str, str]) -> List[Dict]:
        """Fetch prompts list from server."""
        request = {"jsonrpc": "2.0", "id": 4, "method": "prompts/list"}
        
        try:
            async with session.post(
                endpoint,
                headers=headers,
                json=request,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                ssl=False
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    if "result" in data and "prompts" in data["result"]:
                        return data["result"]["prompts"]
        except Exception as e:
            self.logger.debug(f"Prompts fetch error: {e}")
        
        return []
    
    async def _fetch_server_info(self, target_info: Any) -> Optional[Dict]:
        """Fetch server info via initialize."""
        if target_info.protocol == "http":
            return await self._fetch_server_info_http(target_info)
        return None
    
    async def _fetch_server_info_http(self, target_info: Any) -> Optional[Dict]:
        """Fetch server info via HTTP."""
        headers = {
            "User-Agent": self.config.get("scan", {}).get("user_agent", "MCPReconX/1.0"),
            "Content-Type": "application/json"
        }
        
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "mcpreconx",
                    "version": "1.0.0"
                }
            }
        }
        
        endpoint = target_info.endpoints.get("jsonrpc", target_info.url)
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    endpoint,
                    headers=headers,
                    json=request,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        return await response.json()
        except Exception as e:
            self.logger.debug(f"Server info fetch error: {e}")
        
        return None
    
    def _analyze_security_features(self, result: FingerprintResult, target_info: Any) -> Dict[str, bool]:
        """Analyze security features present."""
        features = {
            "authentication": result.auth_required or result.auth_method is not None,
            "rate_limiting": "rate-limit" in str(target_info.headers).lower() or "x-ratelimit" in str(target_info.headers).lower(),
            "input_validation": False,  # Will be determined during scanning
            "output_encoding": False,   # Will be determined during scanning
            "logging": False,           # Cannot detect externally
            "sandboxing": False         # Cannot detect externally
        }
        
        return features
    
    async def _collect_signatures(self, target_info: Any) -> List[str]:
        """Collect behavior signatures for identification."""
        signatures = []
        
        # Response time signature
        if target_info.response_time_ms < 50:
            signatures.append("fast_response")
        elif target_info.response_time_ms > 500:
            signatures.append("slow_response")
        
        # Header signatures
        headers = target_info.headers
        if "server" in headers:
            signatures.append(f"server_header:{headers['server']}")
        if "x-powered-by" in headers:
            signatures.append(f"powered_by:{headers['x-powered-by']}")
        
        # CORS headers
        if "access-control-allow-origin" in headers:
            signatures.append("cors_enabled")
        
        return signatures
