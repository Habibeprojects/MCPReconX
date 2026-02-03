"""
MCPReconX - GitHub MCP Server Discovery
========================================
Discovers MCP servers on GitHub by searching repositories.

ETHICAL USE NOTICE:
This tool is intended for authorized security testing only.
Only scan repositories you own or have permission to test.
"""

import asyncio
import base64
import json
import logging
import re
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urlparse

import aiohttp


class GitHubDiscovery:
    """Discover MCP servers on GitHub."""
    
    GITHUB_API_BASE = "https://api.github.com"
    
    # Search queries for finding MCP servers
    SEARCH_QUERIES = [
        "mcp server language:Python",
        "mcp server language:TypeScript",
        "mcp-server language:Python",
        "mcp-server language:TypeScript",
        "modelcontextprotocol language:Python",
        "modelcontextprotocol language:TypeScript",
        "fastmcp language:Python",
        "@modelcontextprotocol/sdk",
    ]
    
    # MCP-related file patterns
    MCP_FILE_PATTERNS = [
        r"mcp.*server",
        r"server.*mcp",
        r"fastmcp",
        r"modelcontextprotocol",
        r"mcp.*\.json",
    ]
    
    # Known MCP server repositories (popular ones)
    KNOWN_MCP_SERVERS = [
        "modelcontextprotocol/server-git",
        "modelcontextprotocol/server-filesystem",
        "modelcontextprotocol/server-postgres",
        "modelcontextprotocol/server-sqlite",
        "modelcontextprotocol/server-github",
        "modelcontextprotocol/server-slack",
        "modelcontextprotocol/server-brave-search",
        "modelcontextprotocol/server-fetch",
        "modelcontextprotocol/server-puppeteer",
        "modelcontextprotocol/server-everything",
    ]
    
    def __init__(self, github_token: Optional[str] = None, logger: logging.Logger = None):
        self.github_token = github_token
        self.logger = logger or logging.getLogger(__name__)
        self.session: Optional[aiohttp.ClientSession] = None
        self.discovered_servers: List[Dict[str, Any]] = []
        
    async def __aenter__(self):
        """Async context manager entry."""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "MCPReconX/2.0"
        }
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        
        self.session = aiohttp.ClientSession(headers=headers)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def search_mcp_servers(self, max_results: int = 100) -> List[Dict[str, Any]]:
        """
        Search for MCP server repositories on GitHub.
        
        Args:
            max_results: Maximum number of repositories to return
        
        Returns:
            List of repository information dictionaries
        """
        self.logger.info("Searching GitHub for MCP servers...")
        
        all_repos = []
        seen_repos: Set[str] = set()
        
        for query in self.SEARCH_QUERIES:
            if len(all_repos) >= max_results:
                break
            
            try:
                repos = await self._search_repositories(query, per_page=min(30, max_results - len(all_repos)))
                
                for repo in repos:
                    repo_id = f"{repo['owner']['login']}/{repo['name']}"
                    if repo_id not in seen_repos:
                        seen_repos.add(repo_id)
                        
                        # Analyze repository for MCP indicators
                        mcp_info = await self._analyze_repository(repo)
                        if mcp_info:
                            all_repos.append(mcp_info)
                        
                        if len(all_repos) >= max_results:
                            break
                
                # Rate limit protection
                await asyncio.sleep(0.5)
                
            except Exception as e:
                self.logger.debug(f"Search query failed: {query} - {e}")
        
        self.logger.info(f"Discovered {len(all_repos)} potential MCP servers")
        return all_repos
    
    async def _search_repositories(self, query: str, per_page: int = 30) -> List[Dict]:
        """Search GitHub repositories."""
        url = f"{self.GITHUB_API_BASE}/search/repositories"
        params = {
            "q": query,
            "sort": "updated",
            "order": "desc",
            "per_page": per_page
        }
        
        async with self.session.get(url, params=params) as response:
            if response.status == 200:
                data = await response.json()
                return data.get("items", [])
            elif response.status == 403:
                self.logger.warning("GitHub API rate limit exceeded")
                return []
            else:
                self.logger.debug(f"GitHub API error: {response.status}")
                return []
    
    async def _analyze_repository(self, repo: Dict) -> Optional[Dict[str, Any]]:
        """Analyze a repository for MCP server characteristics."""
        owner = repo["owner"]["login"]
        name = repo["name"]
        
        analysis = {
            "repository": f"{owner}/{name}",
            "url": repo["html_url"],
            "description": repo.get("description", ""),
            "stars": repo.get("stargazers_count", 0),
            "language": repo.get("language", "Unknown"),
            "updated_at": repo.get("updated_at", ""),
            "mcp_indicators": [],
            "potential_endpoints": [],
            "has_mcp_config": False,
            "has_mcp_code": False,
            "risk_level": "unknown"
        }
        
        # Check for MCP in description/name
        text_to_check = f"{name} {analysis['description']}".lower()
        if any(kw in text_to_check for kw in ["mcp", "modelcontextprotocol", "model context protocol"]):
            analysis["mcp_indicators"].append("keyword_in_description")
        
        # Check for MCP config files
        config_files = await self._check_mcp_config_files(owner, name)
        if config_files:
            analysis["has_mcp_config"] = True
            analysis["mcp_indicators"].extend(config_files)
        
        # Check for MCP code patterns
        code_indicators = await self._check_mcp_code_patterns(owner, name)
        if code_indicators:
            analysis["has_mcp_code"] = True
            analysis["mcp_indicators"].extend(code_indicators)
        
        # Determine risk level
        if analysis["has_mcp_config"] or analysis["has_mcp_code"]:
            analysis["risk_level"] = self._assess_risk_level(analysis)
        
        return analysis if analysis["mcp_indicators"] else None
    
    async def _check_mcp_config_files(self, owner: str, name: str) -> List[str]:
        """Check for MCP configuration files in repository."""
        indicators = []
        
        config_files = [
            "package.json",
            "pyproject.toml",
            "setup.py",
            "requirements.txt",
            "mcp.json",
            "mcp-config.json",
            "claude_desktop_config.json"
        ]
        
        for filename in config_files:
            try:
                content = await self._get_file_content(owner, name, filename)
                if content:
                    if self._is_mcp_related_content(content):
                        indicators.append(f"mcp_in_{filename}")
            except Exception:
                pass
        
        return indicators
    
    async def _check_mcp_code_patterns(self, owner: str, name: str) -> List[str]:
        """Check for MCP code patterns in repository."""
        indicators = []
        
        # Check README
        try:
            readme = await self._get_file_content(owner, name, "README.md")
            if readme:
                readme_lower = readme.lower()
                if any(kw in readme_lower for kw in ["mcp", "modelcontextprotocol", "model context protocol"]):
                    indicators.append("mcp_in_readme")
                
                # Look for endpoint URLs
                endpoint_patterns = [
                    r"https?://[^\s]+/sse",
                    r"https?://[^\s]+/mcp",
                    r"ws://[^\s]+",
                    r"wss://[^\s]+"
                ]
                for pattern in endpoint_patterns:
                    matches = re.findall(pattern, readme)
                    if matches:
                        indicators.append(f"endpoint_in_readme")
                        break
        except Exception:
            pass
        
        return indicators
    
    async def _get_file_content(self, owner: str, name: str, path: str) -> Optional[str]:
        """Get file content from GitHub."""
        url = f"{self.GITHUB_API_BASE}/repos/{owner}/{name}/contents/{path}"
        
        async with self.session.get(url) as response:
            if response.status == 200:
                data = await response.json()
                if "content" in data:
                    content = base64.b64decode(data["content"]).decode('utf-8', errors='ignore')
                    return content
            return None
    
    def _is_mcp_related_content(self, content: str) -> bool:
        """Check if content is MCP-related."""
        content_lower = content.lower()
        mcp_keywords = [
            "@modelcontextprotocol",
            "modelcontextprotocol",
            "mcp-server",
            "mcp_server",
            "fastmcp",
            "mcp.client",
            "mcp.server"
        ]
        return any(kw in content_lower for kw in mcp_keywords)
    
    def _assess_risk_level(self, analysis: Dict) -> str:
        """Assess risk level based on repository characteristics."""
        indicators = analysis.get("mcp_indicators", [])
        
        # High risk: Popular repositories with MCP code
        if analysis.get("stars", 0) > 100 and analysis.get("has_mcp_code"):
            return "high"
        
        # Medium risk: Has MCP config or code
        if analysis.get("has_mcp_config") or analysis.get("has_mcp_code"):
            return "medium"
        
        # Low risk: Only keyword matches
        return "low"
    
    async def get_known_mcp_servers(self) -> List[Dict[str, Any]]:
        """Get information about known MCP servers."""
        servers = []
        
        for repo_full_name in self.KNOWN_MCP_SERVERS:
            try:
                owner, name = repo_full_name.split('/')
                url = f"{self.GITHUB_API_BASE}/repos/{repo_full_name}"
                
                async with self.session.get(url) as response:
                    if response.status == 200:
                        repo = await response.json()
                        analysis = await self._analyze_repository(repo)
                        if analysis:
                            servers.append(analysis)
                
                await asyncio.sleep(0.3)
                
            except Exception as e:
                self.logger.debug(f"Failed to get {repo_full_name}: {e}")
        
        return servers
    
    async def search_by_topic(self, topic: str = "mcp", max_results: int = 50) -> List[Dict[str, Any]]:
        """Search repositories by topic."""
        self.logger.info(f"Searching GitHub for topic: {topic}")
        
        url = f"{self.GITHUB_API_BASE}/search/repositories"
        params = {
            "q": f"topic:{topic}",
            "sort": "stars",
            "order": "desc",
            "per_page": max_results
        }
        
        async with self.session.get(url, params=params) as response:
            if response.status == 200:
                data = await response.json()
                repos = data.get("items", [])
                
                analyzed = []
                for repo in repos:
                    analysis = await self._analyze_repository(repo)
                    if analysis:
                        analyzed.append(analysis)
                
                return analyzed
            
        return []
    
    def generate_scan_targets(self, repos: List[Dict]) -> List[str]:
        """Generate potential scan targets from discovered repositories."""
        targets = []
        
        for repo in repos:
            # For local testing, suggest localhost ports
            targets.append(f"# {repo['repository']} - {repo['url']}")
            targets.append(f"# Potential local endpoint:")
            targets.append(f"# http://localhost:3000/sse")
            targets.append(f"# ws://localhost:3001")
            targets.append("")
        
        return targets
