"""
MCPReconX - Target Validation Module
=====================================
Validates MCP targets and detects transport protocols.

ETHICAL USE NOTICE:
This tool is intended for authorized security testing only.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, urljoin

import aiohttp
import websockets


@dataclass
class TargetInfo:
    """Container for validated target information."""
    url: str
    valid: bool = False
    protocol: str = "unknown"  # http, websocket
    mcp_version: Optional[str] = None
    transport_type: Optional[str] = None  # sse, streamable-http, websocket
    endpoints: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    response_time_ms: float = 0.0
    supports_jsonrpc: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "url": self.url,
            "valid": self.valid,
            "protocol": self.protocol,
            "mcp_version": self.mcp_version,
            "transport_type": self.transport_type,
            "endpoints": self.endpoints,
            "headers": dict(self.headers),
            "error": self.error,
            "response_time_ms": self.response_time_ms,
            "supports_jsonrpc": self.supports_jsonrpc
        }


class TargetValidator:
    """Validates MCP targets and detects protocols."""
    
    MCP_PROBE_MESSAGE = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "mcpreconx-probe",
                "version": "1.0.0"
            }
        }
    }
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.timeout = config.get("scan", {}).get("timeout", 30)
        self.probe_endpoints = config.get("fingerprint", {}).get("probe_endpoints", [])
    
    async def validate(self, target_url: str) -> TargetInfo:
        """
        Validate target and detect MCP protocol.
        
        Args:
            target_url: Target URL to validate
        
        Returns:
            TargetInfo with validation results
        """
        self.logger.info(f"Validating target: {target_url}")
        
        info = TargetInfo(url=target_url)
        
        # Parse URL
        parsed = urlparse(target_url)
        
        if parsed.scheme in ('ws', 'wss'):
            info.protocol = "websocket"
            await self._validate_websocket(info)
        elif parsed.scheme in ('http', 'https'):
            info.protocol = "http"
            await self._validate_http(info)
        else:
            info.error = f"Unsupported protocol: {parsed.scheme}"
            self.logger.error(info.error)
        
        return info
    
    async def _validate_http(self, info: TargetInfo):
        """Validate HTTP-based MCP endpoint."""
        import time
        
        headers = {
            "User-Agent": self.config.get("scan", {}).get("user_agent", "MCPReconX/1.0"),
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json"
        }
        
        # Try main endpoint first
        try:
            start_time = time.time()
            
            async with aiohttp.ClientSession() as session:
                # Try GET for SSE detection
                async with session.get(
                    info.url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False  # Allow self-signed certs for testing
                ) as response:
                    info.response_time_ms = (time.time() - start_time) * 1000
                    info.headers = dict(response.headers)
                    
                    content_type = response.headers.get('Content-Type', '')
                    
                    if 'text/event-stream' in content_type:
                        info.transport_type = "sse"
                        info.valid = True
                        self.logger.info("SSE transport detected")
                        return
                    
                    # Try POST with JSON-RPC probe
                    async with session.post(
                        info.url,
                        headers=headers,
                        json=self.MCP_PROBE_MESSAGE,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False
                    ) as post_response:
                        if post_response.status == 200:
                            try:
                                data = await post_response.json()
                                if self._is_mcp_response(data):
                                    info.valid = True
                                    info.supports_jsonrpc = True
                                    info.transport_type = "streamable-http"
                                    info.mcp_version = self._extract_mcp_version(data)
                                    self.logger.info("Streamable HTTP transport detected")
                                    return
                            except:
                                pass
        
        except asyncio.TimeoutError:
            self.logger.warning("HTTP validation timeout")
        except Exception as e:
            self.logger.debug(f"HTTP validation error: {e}")
        
        # Try alternative endpoints
        await self._probe_alternative_endpoints(info, headers)
    
    async def _probe_alternative_endpoints(self, info: TargetInfo, headers: Dict[str, str]):
        """Probe alternative MCP endpoints."""
        base_url = info.url.rstrip('/')
        
        for endpoint in self.probe_endpoints:
            test_url = urljoin(base_url + '/', endpoint.lstrip('/'))
            
            try:
                async with aiohttp.ClientSession() as session:
                    # Try GET
                    async with session.get(
                        test_url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=5),
                        ssl=False
                    ) as response:
                        if response.status == 200:
                            content_type = response.headers.get('Content-Type', '')
                            
                            if 'text/event-stream' in content_type:
                                info.endpoints["sse"] = test_url
                                info.valid = True
                                info.transport_type = "sse"
                                self.logger.info(f"Found SSE endpoint: {test_url}")
                                return
                            
                            try:
                                data = await response.json()
                                if self._is_mcp_response(data) or 'tools' in data or 'capabilities' in data:
                                    info.endpoints["discovery"] = test_url
                                    info.valid = True
                                    self.logger.info(f"Found MCP discovery endpoint: {test_url}")
                                    return
                            except:
                                pass
                    
                    # Try POST with probe
                    async with session.post(
                        test_url,
                        headers=headers,
                        json=self.MCP_PROBE_MESSAGE,
                        timeout=aiohttp.ClientTimeout(total=5),
                        ssl=False
                    ) as post_response:
                        if post_response.status == 200:
                            try:
                                data = await post_response.json()
                                if self._is_mcp_response(data):
                                    info.endpoints["jsonrpc"] = test_url
                                    info.valid = True
                                    info.supports_jsonrpc = True
                                    info.transport_type = "streamable-http"
                                    self.logger.info(f"Found JSON-RPC endpoint: {test_url}")
                                    return
                            except:
                                pass
            
            except Exception:
                continue
        
        if not info.valid:
            info.error = "No valid MCP endpoint detected"
    
    async def _validate_websocket(self, info: TargetInfo):
        """Validate WebSocket MCP endpoint."""
        import time
        
        try:
            start_time = time.time()
            
            async with websockets.connect(
                info.url,
                ping_interval=None,
                ssl=False  # Allow self-signed certs
            ) as ws:
                info.response_time_ms = (time.time() - start_time) * 1000
                
                # Send initialize probe
                await ws.send(json.dumps(self.MCP_PROBE_MESSAGE))
                
                # Wait for response
                response = await asyncio.wait_for(
                    ws.recv(),
                    timeout=self.timeout
                )
                
                try:
                    data = json.loads(response)
                    if self._is_mcp_response(data):
                        info.valid = True
                        info.transport_type = "websocket"
                        info.supports_jsonrpc = True
                        info.mcp_version = self._extract_mcp_version(data)
                        self.logger.info("WebSocket MCP endpoint validated")
                        return
                except json.JSONDecodeError:
                    pass
                
                info.error = "WebSocket connected but no MCP response"
        
        except asyncio.TimeoutError:
            info.error = "WebSocket validation timeout"
        except websockets.exceptions.InvalidStatusCode as e:
            info.error = f"WebSocket rejected with status: {e.status_code}"
        except Exception as e:
            info.error = f"WebSocket error: {str(e)}"
    
    def _is_mcp_response(self, data: Dict[str, Any]) -> bool:
        """Check if response is valid MCP/JSON-RPC."""
        if not isinstance(data, dict):
            return False
        
        # Check for JSON-RPC format
        if data.get("jsonrpc") == "2.0":
            return True
        
        # Check for MCP-specific fields
        mcp_fields = ["protocolVersion", "serverInfo", "capabilities", "tools", "resources"]
        if any(field in data for field in mcp_fields):
            return True
        
        # Check result for MCP fields
        if "result" in data and isinstance(data["result"], dict):
            if any(field in data["result"] for field in mcp_fields):
                return True
        
        return False
    
    def _extract_mcp_version(self, data: Dict[str, Any]) -> Optional[str]:
        """Extract MCP version from response."""
        if not isinstance(data, dict):
            return None
        
        # Check root level
        if "protocolVersion" in data:
            return data["protocolVersion"]
        
        # Check result
        if "result" in data and isinstance(data["result"], dict):
            return data["result"].get("protocolVersion")
        
        return None
    
    async def discover_capabilities(self, info: TargetInfo) -> Dict[str, Any]:
        """
        Discover MCP server capabilities.
        
        Args:
            info: Validated target info
        
        Returns:
            Capabilities dictionary
        """
        capabilities = {
            "tools": [],
            "resources": [],
            "prompts": [],
            "resource_templates": []
        }
        
        if info.protocol == "http":
            capabilities = await self._discover_http_capabilities(info)
        elif info.protocol == "websocket":
            capabilities = await self._discover_ws_capabilities(info)
        
        return capabilities
    
    async def _discover_http_capabilities(self, info: TargetInfo) -> Dict[str, Any]:
        """Discover capabilities via HTTP."""
        headers = {
            "User-Agent": self.config.get("scan", {}).get("user_agent", "MCPReconX/1.0"),
            "Content-Type": "application/json"
        }
        
        # Add auth if configured
        # TODO: Add auth header support
        
        endpoint = info.endpoints.get("jsonrpc", info.url)
        
        async with aiohttp.ClientSession() as session:
            # Query tools
            tools_request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list"
            }
            
            try:
                async with session.post(
                    endpoint,
                    headers=headers,
                    json=tools_request,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if "result" in data and "tools" in data["result"]:
                            return {"tools": data["result"]["tools"]}
            except Exception as e:
                self.logger.debug(f"Tools discovery failed: {e}")
        
        return {"tools": []}
    
    async def _discover_ws_capabilities(self, info: TargetInfo) -> Dict[str, Any]:
        """Discover capabilities via WebSocket."""
        try:
            async with websockets.connect(info.url, ssl=False) as ws:
                # Query tools
                tools_request = {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list"
                }
                
                await ws.send(json.dumps(tools_request))
                
                response = await asyncio.wait_for(ws.recv(), timeout=self.timeout)
                data = json.loads(response)
                
                if "result" in data and "tools" in data["result"]:
                    return {"tools": data["result"]["tools"]}
        
        except Exception as e:
            self.logger.debug(f"WS capabilities discovery failed: {e}")
        
        return {"tools": []}
