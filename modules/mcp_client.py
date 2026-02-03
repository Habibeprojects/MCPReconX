"""
MCPReconX - MCP Protocol Client
================================
Working MCP client for HTTP/SSE and WebSocket transports.
Implements the Model Context Protocol specification for testing.

ETHICAL USE NOTICE:
This tool is intended for authorized security testing only.
"""

import asyncio
import json
import logging
import uuid
from typing import Dict, Any, List, Optional, Callable, AsyncGenerator
from urllib.parse import urljoin, urlparse

import aiohttp
import websockets
from websockets.exceptions import ConnectionClosed, InvalidStatusCode


class MCPClient:
    """MCP Protocol client for HTTP/SSE and WebSocket transports."""
    
    MCP_VERSION = "2024-11-05"
    
    def __init__(self, base_url: str, logger: logging.Logger = None, timeout: int = 30):
        self.base_url = base_url
        self.logger = logger or logging.getLogger(__name__)
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None
        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        self.transport_type: Optional[str] = None  # 'http', 'sse', 'websocket'
        self.session_id: Optional[str] = None
        self.server_capabilities: Dict[str, Any] = {}
        self.server_info: Dict[str, Any] = {}
        self.message_counter = 0
        self._initialized = False
        
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={
                "User-Agent": "MCPReconX/2.0 (Security Scanner)",
                "Accept": "application/json, text/event-stream",
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
    
    async def close(self):
        """Close all connections."""
        if self.ws:
            try:
                await self.ws.close()
            except Exception:
                pass
            self.ws = None
        
        if self.session:
            try:
                await self.session.close()
            except Exception:
                pass
            self.session = None
        
        self._initialized = False
    
    def _get_next_id(self) -> int:
        """Get next message ID."""
        self.message_counter += 1
        return self.message_counter
    
    def _create_request(self, method: str, params: Dict = None) -> Dict:
        """Create a JSON-RPC request."""
        request = {
            "jsonrpc": "2.0",
            "id": self._get_next_id(),
            "method": method
        }
        if params:
            request["params"] = params
        return request
    
    async def detect_transport(self) -> Optional[str]:
        """Detect the transport type supported by the server."""
        parsed = urlparse(self.base_url)
        
        # Check if WebSocket
        if parsed.scheme in ('ws', 'wss'):
            try:
                await self._connect_websocket()
                self.transport_type = 'websocket'
                return 'websocket'
            except Exception as e:
                self.logger.debug(f"WebSocket connection failed: {e}")
        
        # Check for SSE
        try:
            sse_url = urljoin(self.base_url, '/sse')
            async with self.session.get(sse_url, ssl=False) as response:
                content_type = response.headers.get('Content-Type', '')
                if 'text/event-stream' in content_type:
                    self.transport_type = 'sse'
                    self.session_id = response.headers.get('mcp-session-id')
                    return 'sse'
        except Exception as e:
            self.logger.debug(f"SSE detection failed: {e}")
        
        # Check for HTTP streamable
        try:
            init_response = await self._http_initialize()
            if init_response:
                self.transport_type = 'http'
                return 'http'
        except Exception as e:
            self.logger.debug(f"HTTP detection failed: {e}")
        
        return None
    
    async def _connect_websocket(self):
        """Connect via WebSocket."""
        self.ws = await websockets.connect(
            self.base_url,
            ping_interval=None,
            ssl=False
        )
    
    async def _http_initialize(self) -> Optional[Dict]:
        """Initialize HTTP connection."""
        request = self._create_request("initialize", {
            "protocolVersion": self.MCP_VERSION,
            "capabilities": {
                "roots": {"listChanged": True},
                "sampling": {}
            },
            "clientInfo": {
                "name": "mcpreconx",
                "version": "2.0.0"
            }
        })
        
        async with self.session.post(
            self.base_url,
            json=request,
            ssl=False
        ) as response:
            if response.status == 200:
                return await response.json()
        return None
    
    async def initialize(self) -> bool:
        """Initialize the MCP connection."""
        if self._initialized:
            return True
        
        if not self.transport_type:
            transport = await self.detect_transport()
            if not transport:
                self.logger.error("Could not detect MCP transport")
                return False
        
        try:
            if self.transport_type == 'websocket':
                return await self._initialize_websocket()
            else:
                return await self._initialize_http()
        except Exception as e:
            self.logger.error(f"Initialization failed: {e}")
            return False
    
    async def _initialize_websocket(self) -> bool:
        """Initialize WebSocket connection."""
        request = self._create_request("initialize", {
            "protocolVersion": self.MCP_VERSION,
            "capabilities": {},
            "clientInfo": {
                "name": "mcpreconx",
                "version": "2.0.0"
            }
        })
        
        await self.ws.send(json.dumps(request))
        response = await asyncio.wait_for(self.ws.recv(), timeout=self.timeout)
        data = json.loads(response)
        
        if "result" in data:
            self.server_capabilities = data["result"].get("capabilities", {})
            self.server_info = data["result"].get("serverInfo", {})
            
            # Send initialized notification
            await self.ws.send(json.dumps({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }))
            
            self._initialized = True
            return True
        
        return False
    
    async def _initialize_http(self) -> bool:
        """Initialize HTTP connection."""
        response = await self._http_initialize()
        
        if response and "result" in response:
            self.server_capabilities = response["result"].get("capabilities", {})
            self.server_info = response["result"].get("serverInfo", {})
            
            # Send initialized notification
            await self.session.post(
                self.base_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized"
                },
                ssl=False
            )
            
            self._initialized = True
            return True
        
        return False
    
    async def call_tool(self, name: str, arguments: Dict = None) -> Optional[Dict]:
        """Call an MCP tool."""
        if not self._initialized:
            if not await self.initialize():
                return None
        
        request = self._create_request("tools/call", {
            "name": name,
            "arguments": arguments or {}
        })
        
        try:
            if self.transport_type == 'websocket':
                await self.ws.send(json.dumps(request))
                response = await asyncio.wait_for(self.ws.recv(), timeout=self.timeout)
                return json.loads(response)
            else:
                async with self.session.post(
                    self.base_url,
                    json=request,
                    ssl=False
                ) as response:
                    if response.status == 200:
                        return await response.json()
        except Exception as e:
            self.logger.debug(f"Tool call failed: {e}")
        
        return None
    
    async def list_tools(self) -> List[Dict]:
        """List available tools."""
        if not self._initialized:
            if not await self.initialize():
                return []
        
        request = self._create_request("tools/list")
        
        try:
            if self.transport_type == 'websocket':
                await self.ws.send(json.dumps(request))
                response = await asyncio.wait_for(self.ws.recv(), timeout=self.timeout)
                data = json.loads(response)
            else:
                async with self.session.post(
                    self.base_url,
                    json=request,
                    ssl=False
                ) as response:
                    data = await response.json()
            
            if "result" in data and "tools" in data["result"]:
                return data["result"]["tools"]
        except Exception as e:
            self.logger.debug(f"List tools failed: {e}")
        
        return []
    
    async def list_resources(self) -> List[Dict]:
        """List available resources."""
        if not self._initialized:
            if not await self.initialize():
                return []
        
        request = self._create_request("resources/list")
        
        try:
            if self.transport_type == 'websocket':
                await self.ws.send(json.dumps(request))
                response = await asyncio.wait_for(self.ws.recv(), timeout=self.timeout)
                data = json.loads(response)
            else:
                async with self.session.post(
                    self.base_url,
                    json=request,
                    ssl=False
                ) as response:
                    data = await response.json()
            
            if "result" in data and "resources" in data["result"]:
                return data["result"]["resources"]
        except Exception as e:
            self.logger.debug(f"List resources failed: {e}")
        
        return []
    
    async def list_prompts(self) -> List[Dict]:
        """List available prompts."""
        if not self._initialized:
            if not await self.initialize():
                return []
        
        request = self._create_request("prompts/list")
        
        try:
            if self.transport_type == 'websocket':
                await self.ws.send(json.dumps(request))
                response = await asyncio.wait_for(self.ws.recv(), timeout=self.timeout)
                data = json.loads(response)
            else:
                async with self.session.post(
                    self.base_url,
                    json=request,
                    ssl=False
                ) as response:
                    data = await response.json()
            
            if "result" in data and "prompts" in data["result"]:
                return data["result"]["prompts"]
        except Exception as e:
            self.logger.debug(f"List prompts failed: {e}")
        
        return []
    
    async def read_resource(self, uri: str) -> Optional[Dict]:
        """Read a resource by URI."""
        if not self._initialized:
            if not await self.initialize():
                return None
        
        request = self._create_request("resources/read", {"uri": uri})
        
        try:
            if self.transport_type == 'websocket':
                await self.ws.send(json.dumps(request))
                response = await asyncio.wait_for(self.ws.recv(), timeout=self.timeout)
                return json.loads(response)
            else:
                async with self.session.post(
                    self.base_url,
                    json=request,
                    ssl=False
                ) as response:
                    if response.status == 200:
                        return await response.json()
        except Exception as e:
            self.logger.debug(f"Read resource failed: {e}")
        
        return None
    
    async def get_prompt(self, name: str, arguments: Dict = None) -> Optional[Dict]:
        """Get a prompt by name."""
        if not self._initialized:
            if not await self.initialize():
                return None
        
        params = {"name": name}
        if arguments:
            params["arguments"] = arguments
        
        request = self._create_request("prompts/get", params)
        
        try:
            if self.transport_type == 'websocket':
                await self.ws.send(json.dumps(request))
                response = await asyncio.wait_for(self.ws.recv(), timeout=self.timeout)
                return json.loads(response)
            else:
                async with self.session.post(
                    self.base_url,
                    json=request,
                    ssl=False
                ) as response:
                    if response.status == 200:
                        return await response.json()
        except Exception as e:
            self.logger.debug(f"Get prompt failed: {e}")
        
        return None
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get server information."""
        return {
            "transport_type": self.transport_type,
            "session_id": self.session_id,
            "server_info": self.server_info,
            "capabilities": self.server_capabilities,
            "initialized": self._initialized
        }
