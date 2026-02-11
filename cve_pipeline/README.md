# The Hunter's Loop

A professional-grade automated security scanning pipeline with intelligent routing, AI-powered triage, and robust safety controls.

## Features

- **Intelligent Routing**: Automatically classifies URLs and routes them to appropriate scanners
- **Parameter Deduplication**: Avoids redundant scans on similar endpoints
- **Scope Enforcement**: Strict domain validation prevents out-of-scope attacks
- **Rate Limiting**: Global rate limiting to prevent WAF bans and DoS
- **AI Triage**: Uses Gemini to validate findings and reduce false positives
- **Crash Recovery**: Resumes from last checkpoint after interruptions
- **Graceful Shutdown**: Properly saves state on SIGINT/SIGTERM

## Quick Start

### Using Docker (Recommended)

```bash
# 1. Configure your scope and API keys
cp .env.example .env
# Edit .env with your API keys

# Edit config/scope_rules.json with your target scope

# 2. Build and run
docker-compose up --build
```

### Local Development

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Ensure external tools are installed and in PATH:
#    - subfinder, httpx, nuclei, katana, gau (Go)
#    - rustscan (Rust)
#    - sqlmap, hydra (System)

# 3. Configure
cp .env.example .env
# Edit .env and config/scope_rules.json

# 4. Run
python main.py example.com --dry-run  # Test mode
python main.py example.com            # Full scan
```

## Configuration

### Environment Variables (`.env`)

| Variable | Description | Required |
|----------|-------------|----------|
| `GEMINI_API_KEY` | Google Gemini API key for AI triage | Optional |
| `DISCORD_WEBHOOK_URL` | Discord webhook for alerts | Optional |
| `GLOBAL_RATE_LIMIT` | Requests per second limit | Default: 150 |
| `ENABLE_BRUTEFORCE` | Enable Hydra brute-force | Default: False |

### Scope Rules (`config/scope_rules.json`)

```json
{
  "allowed_domains": [
    ".example.com",
    "api.example.com"
  ],
  "excluded_domains": [
    "out-of-scope.example.com"
  ]
}
```

## Pipeline Stages

```
┌─────────────────────────────────────────────────────────────┐
│                      Stage 1: RECON                        │
│   subfinder → httpx → katana + gau → Scope Filter          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Stage 2: ROUTING                        │
│   URL Analysis → Parameter Deduplication → Classification  │
│   (Dynamic, Login, API, CMS, JS, Static)                   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Stage 3: SCANNING                        │
│   Dynamic → Dalfox + SQLMap                                │
│   Login   → Hydra (if enabled)                             │
│   CMS     → Nuclei (CMS templates)                         │
│   API     → Nuclei (API templates)                         │
│   JS      → Nuclei (Secret templates)                      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Stage 4: AI TRIAGE                       │
│   Filter MEDIUM+ → Gemini Analysis → Discord Alert         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Stage 5: REPORT                          │
│   Markdown Report → data/<target>/report.md                │
└─────────────────────────────────────────────────────────────┘
```

## Safety Features

1. **Scope Guard**: All URLs validated before scanning
2. **Timeouts**: 5-minute timeout on all subprocess calls
3. **Rate Limiting**: Configurable global rate limit
4. **Brute-Force Gate**: Hydra disabled by default
5. **SQLMap Optimization**: Uses `--technique=BEU` (no slow Time-based)
6. **WAL Mode**: SQLite with WAL for crash-resistant state

## Project Structure

```
cve_pipeline/
├── config/
│   ├── settings.py          # Configuration management
│   └── scope_rules.json     # Allowed/excluded domains
├── core/
│   ├── logger.py            # Rich logging
│   ├── state_manager.py     # SQLite WAL state persistence
│   └── orchestrator.py      # Main pipeline logic
├── modules/
│   ├── recon.py             # Subdomain + URL enumeration
│   ├── router.py            # Intelligent URL routing
│   ├── scanner.py           # Tool wrappers
│   └── ai_triage.py         # Gemini-powered validation
├── utils/
│   ├── scope_guard.py       # Domain validation
│   ├── notifier.py          # Discord/Slack alerts
│   └── proxy_manager.py     # Proxy rotation (stub)
├── data/                    # Scan outputs
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── main.py                  # Entry point
```

## Legal Disclaimer

**This tool is for authorized security testing only.**

Only use this tool on systems you have explicit permission to test. Unauthorized access to computer systems is illegal. The authors are not responsible for any misuse of this software.

## License

MIT
