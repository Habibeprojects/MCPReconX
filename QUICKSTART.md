# MCPReconX v2.0 - Quick Start Guide

## Installation

```bash
# Clone and setup
git clone https://github.com/security/mcpreconx.git
cd mcpreconx
pip install -r requirements.txt
```

## Basic Usage

### 1. Scan a Local MCP Server

```bash
# Simple scan
python main.py --target http://localhost:3000/sse

# Full assessment with CVE detection
python main.py -t http://localhost:3000/sse --cve-check --detect-patterns
```

### 2. Discover MCP Servers on GitHub

```bash
# Search GitHub for MCP servers
python main.py --discover-github

# With GitHub token (better rate limits)
python main.py --discover-github --github-token YOUR_TOKEN
```

### 3. Scan Internet for Exposed MCP Servers

```bash
# Scan a host
python main.py --discover-internet --target example.com

# Scan network range
python main.py --discover-internet --target 192.168.1.0/24
```

## Common Commands

```bash
# Full security assessment
python main.py -t http://target.com/mcp --cve-check --detect-patterns --risk high --report-all

# Fingerprint only
python main.py -t http://target.com/mcp --fingerprint-only

# With authentication
python main.py -t http://target.com/mcp --auth-token "Bearer TOKEN"

# Verbose output
python main.py -t http://target.com/mcp -vv

# Batch mode (no prompts)
python main.py -t http://target.com/mcp --batch --json
```

## Output

Reports are saved to `reports/` directory:
- `mcpreconx_report_{session_id}.json` - JSON report
- `mcpreconx_report_{session_id}.pdf` - PDF report

Logs are saved to `logs/` directory.

## Testing

```bash
# Run test suite
python test_scanner.py
```

## Safety

- **Safe mode is default** - only detection, no exploitation
- Use `--exploit` flag with `--risk high` for simulation mode
- Always ensure you have permission before scanning

## Support

- Issues: GitHub Issues
- Docs: README.md
- Ethics: DISCLAIMER.md
