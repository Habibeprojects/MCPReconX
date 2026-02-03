"""
MCPReconX - Internet MCP Server Discovery
==========================================
Discovers publicly exposed MCP servers on the internet.

WARNING: Only scan hosts you have permission to test!

ETHICAL USE NOTICE:
This tool is intended for authorized security testing only.
"""

import asyncio
import ipaddress
import logging
import random
from typing import Dict, Any, List, Optional, Set, AsyncGenerator
from urllib.parse import urljoin

import aiohttp


class InternetDiscovery:
    """Discover publicly exposed MCP servers on the internet."""
    
    # Common MCP ports to check
    MCP_PORTS = [
        3000,  # Common development port
        3001,  # Common alternate port
        8080,  # Common HTTP port
        8081,  # Common alternate port
        5000,  # Flask/Python common
        5001,  # Flask/Python alternate
        8000,  # Common HTTP port
        8001,  # Common alternate
        9000,  # Common port
        6277,  # MCP Inspector default
        6274,  # MCP Inspector alternate
        8765,  # Common custom port
        8766,  # Common custom port
    ]
    
    # Common MCP endpoints to check
    MCP_ENDPOINTS = [
        "/sse",
        "/mcp",
        "/mcp/v1",
        "/.well-known/mcp",
        "/capabilities",
        "/mcp/sse",
        "/stream",
        "/message",
        "/jsonrpc",
        "/mcp/stream",
    ]
    
    # MCP response indicators
    MCP_INDICATORS = [
        b'"jsonrpc":',
        b'"jsonrpc" :',
        b'"tools"',
        b'"capabilities"',
        b'"protocolVersion"',
        b'"serverInfo"',
        b'"mcp"',
        b'text/event-stream',
    ]
    
    def __init__(self, logger: logging.Logger = None, timeout: int = 10):
        self.logger = logger or logging.getLogger(__name__)
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore: Optional[asyncio.Semaphore] = None
        
    async def __aenter__(self):
        """Async context manager entry."""
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=10,
            enable_cleanup_closed=True,
            force_close=True,
        )
        
        timeout = aiohttp.ClientTimeout(total=self.timeout, connect=5)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                "User-Agent": "MCPReconX/2.0 (Security Research)",
                "Accept": "application/json, text/event-stream, */*",
            }
        )
        
        self.semaphore = asyncio.Semaphore(50)  # Limit concurrent connections
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def scan_host(
        self,
        host: str,
        ports: List[int] = None,
        endpoints: List[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Scan a single host for MCP servers.
        
        Args:
            host: Hostname or IP address
            ports: List of ports to check (default: common MCP ports)
            endpoints: List of endpoints to check (default: common endpoints)
        
        Returns:
            List of discovered MCP endpoints
        """
        ports = ports or self.MCP_PORTS
        endpoints = endpoints or self.MCP_ENDPOINTS
        
        discovered = []
        tasks = []
        
        for port in ports:
            for endpoint in endpoints:
                tasks.append(self._check_endpoint(host, port, endpoint))
        
        # Also check WebSocket
        for port in ports:
            tasks.append(self._check_websocket(host, port))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, dict) and result.get("is_mcp"):
                discovered.append(result)
        
        return discovered
    
    async def _check_endpoint(
        self,
        host: str,
        port: int,
        endpoint: str
    ) -> Dict[str, Any]:
        """Check if an endpoint is an MCP server."""
        async with self.semaphore:
            # Try HTTPS first
            urls_to_try = [
                f"https://{host}:{port}{endpoint}",
                f"http://{host}:{port}{endpoint}"
            ]
            
            for url in urls_to_try:
                try:
                    result = await self._probe_http_endpoint(url)
                    if result.get("is_mcp"):
                        return result
                except Exception:
                    continue
            
            return {"is_mcp": False}
    
    async def _probe_http_endpoint(self, url: str) -> Dict[str, Any]:
        """Probe an HTTP endpoint for MCP indicators."""
        result = {
            "url": url,
            "is_mcp": False,
            "transport": None,
            "indicators": []
        }
        
        try:
            async with self.session.get(url, ssl=False, allow_redirects=False) as response:
                content_type = response.headers.get('Content-Type', '')
                
                # Check for SSE
                if 'text/event-stream' in content_type:
                    result["transport"] = "sse"
                    result["indicators"].append("sse_content_type")
                    result["is_mcp"] = True
                    result["status"] = response.status
                    result["headers"] = dict(response.headers)
                    return result
                
                # Check for JSON response
                if 'application/json' in content_type:
                    try:
                        body = await response.read()
                        if any(indicator in body for indicator in self.MCP_INDICATORS):
                            result["transport"] = "http"
                            result["indicators"].append("mcp_json_response")
                            result["is_mcp"] = True
                            result["status"] = response.status
                            result["sample"] = body[:500].decode('utf-8', errors='ignore')
                            return result
                    except Exception:
                        pass
                
                # Check body for MCP indicators
                if response.status == 200:
                    try:
                        body = await response.read()
                        if any(indicator in body for indicator in self.MCP_INDICATORS):
                            result["transport"] = "http"
                            result["indicators"].append("mcp_body_indicator")
                            result["is_mcp"] = True
                            result["status"] = response.status
                            return result
                    except Exception:
                        pass
                        
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            self.logger.debug(f"Probe failed for {url}: {e}")
        
        return result
    
    async def _check_websocket(self, host: str, port: int) -> Dict[str, Any]:
        """Check if a WebSocket endpoint is an MCP server."""
        async with self.semaphore:
            result = {
                "url": f"ws://{host}:{port}",
                "is_mcp": False,
                "transport": None
            }
            
            try:
                import websockets
                
                ws_url = f"ws://{host}:{port}"
                
                try:
                    async with websockets.connect(ws_url, ping_interval=None, close_timeout=5) as ws:
                        # Send initialize message
                        init_msg = {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "initialize",
                            "params": {
                                "protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {"name": "mcpreconx", "version": "2.0.0"}
                            }
                        }
                        
                        await ws.send(json.dumps(init_msg))
                        
                        try:
                            response = await asyncio.wait_for(ws.recv(), timeout=5)
                            response_data = json.loads(response)
                            
                            if "result" in response_data or "jsonrpc" in response_data:
                                result["is_mcp"] = True
                                result["transport"] = "websocket"
                                result["response"] = response_data
                                
                        except asyncio.TimeoutError:
                            pass
                            
                except Exception as e:
                    self.logger.debug(f"WebSocket check failed for {ws_url}: {e}")
                    
            except ImportError:
                self.logger.debug("websockets library not available")
            
            return result
    
    async def scan_network_range(
        self,
        network: str,
        ports: List[int] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Scan a network range for MCP servers.
        
        WARNING: Only scan networks you own or have permission to test!
        
        Args:
            network: CIDR notation (e.g., "192.168.1.0/24")
            ports: List of ports to check
        
        Yields:
            Discovered MCP endpoints
        """
        try:
            net = ipaddress.ip_network(network, strict=False)
            hosts = list(net.hosts())
            
            self.logger.info(f"Scanning {len(hosts)} hosts in {network}")
            
            # Limit to reasonable number
            if len(hosts) > 256:
                self.logger.warning(f"Network too large, sampling 256 hosts")
                hosts = random.sample(hosts, 256)
            
            for ip in hosts:
                host = str(ip)
                discovered = await self.scan_host(host, ports)
                
                for endpoint in discovered:
                    yield endpoint
                
                await asyncio.sleep(0.1)  # Rate limiting
                
        except ValueError as e:
            self.logger.error(f"Invalid network range: {e}")
    
    async def scan_from_list(
        self,
        hosts: List[str],
        ports: List[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Scan a list of hosts for MCP servers.
        
        Args:
            hosts: List of hostnames or IPs
            ports: List of ports to check
        
        Returns:
            List of discovered MCP endpoints
        """
        all_discovered = []
        
        for host in hosts:
            self.logger.info(f"Scanning host: {host}")
            discovered = await self.scan_host(host, ports)
            all_discovered.extend(discovered)
        
        return all_discovered
    
    async def check_common_cloud_endpoints(self) -> List[Dict[str, Any]]:
        """Check common cloud service endpoints for MCP exposure."""
        # This is a placeholder for cloud-specific checks
        # In practice, you'd need credentials and specific APIs
        return []
    
    def generate_report(self, discovered: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a discovery report."""
        by_transport = {}
        by_indicator = {}
        
        for endpoint in discovered:
            transport = endpoint.get("transport", "unknown")
            by_transport[transport] = by_transport.get(transport, 0) + 1
            
            for indicator in endpoint.get("indicators", []):
                by_indicator[indicator] = by_indicator.get(indicator, 0) + 1
        
        return {
            "total_discovered": len(discovered),
            "by_transport": by_transport,
            "by_indicator": by_indicator,
            "endpoints": discovered
        }
