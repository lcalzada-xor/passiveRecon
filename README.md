# passiveRecon

Passive web reconnaissance and enumeration toolkit.

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [External Tools](#external-tools)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Basic Commands](#basic-commands)
  - [Active Mode](#active-mode)
  - [Proxy Configuration](#proxy-configuration)
  - [HTML Reports](#html-reports)
- [Configuration](#configuration)
  - [Configuration File](#configuration-file)
  - [Environment Variables](#environment-variables)
  - [Available Options](#available-options)
- [Output Format](#output-format)
  - [Artifact Manifest](#artifact-manifest)
  - [Field Reference](#field-reference)
  - [Output Directory Structure](#output-directory-structure)
- [Integrations](#integrations)
  - [Censys](#censys)
  - [RDAP](#rdap)
  - [DNS Resolution (dnsx)](#dns-resolution-dnsx)
  - [Link Discovery (GoLinkfinderEVO)](#link-discovery-golinkfinderevo)
- [Development](#development)
- [License](#license)

---

## Overview

passiveRecon is a comprehensive passive reconnaissance framework designed to enumerate web assets and discover attack surface through multiple data sources. It aggregates findings from various OSINT tools and APIs, normalizes the output, and produces structured artifacts for further analysis.

**Key Features:**
- **Passive & Active Modes**: Run passive enumeration or enable active verification
- **Multi-source Aggregation**: Integrates with popular OSINT tools (subfinder, amass, etc.)
- **Structured Output**: Consolidated JSONL manifest with temporal tracking
- **Proxy Support**: Full HTTP/HTTPS proxy support with custom CA certificates
- **HTML Reporting**: Generate visual summaries with statistics and charts
- **Configurable**: YAML/JSON configuration files and CLI flags

---

## Project Structure

The repository follows a clean architecture pattern with clear separation of concerns:

```
.
├── cmd/                    # CLI applications
│   ├── passive-rec/       # Main reconnaissance binary
│   └── install-deps/      # Dependency installer utility
├── internal/
│   ├── core/              # Core business logic
│   │   ├── app/          # Application orchestration
│   │   ├── pipeline/     # Data processing pipeline
│   │   └── runner/       # Tool execution
│   ├── adapters/          # External integrations
│   │   ├── artifacts/    # Artifact management
│   │   ├── report/       # Report generation
│   │   ├── routes/       # Route categorization
│   │   └── sources/      # Data source adapters
│   └── platform/          # Shared utilities
│       ├── config/       # Configuration handling
│       ├── netutil/      # Network utilities
│       └── certs/        # Certificate handling
└── requirements.txt       # External tool dependencies
```

This organization keeps dependencies flowing from the core outward to adapters, making it easy to locate components by their responsibility.

---

## Installation

### Prerequisites

- **Go 1.21+**: Required to build and run the tool
- **Git**: For cloning the repository
- **Network Access**: To download external tools and query APIs

### External Tools

This project relies on third-party reconnaissance utilities. Install them automatically:

```bash
go run ./cmd/install-deps
```

This command:
1. Reads `requirements.txt`
2. Checks if each tool is available on your `PATH`
3. Uses `go install` to fetch missing tools
4. Installs to `$GOBIN` or `$GOPATH/bin`

**Ensure your Go bin directory is in your PATH:**
```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

---

## Quick Start

Run a basic passive scan:

```bash
go run ./cmd/passive-rec -target example.com -outdir ./output
```

Run with active verification and HTML report:

```bash
go run ./cmd/passive-rec -target example.com -outdir ./output --active -report
```

Use a configuration file:

```bash
go run ./cmd/passive-rec --config config.yaml
```

---

## Usage

### Basic Commands

**Passive reconnaissance:**
```bash
go run ./cmd/passive-rec -target example.com -outdir out
```

**Specify which tools to run:**
```bash
go run ./cmd/passive-rec -target example.com -outdir out -tools subfinder,amass
```

**Adjust timeout and verbosity:**
```bash
go run ./cmd/passive-rec -target example.com -timeout 300 -verbosity 2
```

### Active Mode

Enable active verification with `--active` to:
- Resolve discovered domains with **dnsx**
- Extract links from HTML/JS with **GoLinkfinderEVO**
- Verify HTTP status codes with **httpx**

```bash
go run ./cmd/passive-rec -target example.com -outdir out --active
```

**Active mode outputs:**
- DNS resolutions: `dns/dns.active`
- Link findings: `routes/linkFindings/findings.{json,html,raw}`
- HTTP verification: Enriched artifacts with status codes

### Proxy Configuration

Route all HTTP/HTTPS traffic through a proxy:

```bash
go run ./cmd/passive-rec \
  -target example.com \
  -proxy http://127.0.0.1:8080
```

**With TLS interception (Burp/ZAP):**
```bash
go run ./cmd/passive-rec \
  -target example.com \
  -proxy http://127.0.0.1:8080 \
  -proxy-ca ~/.config/burp/ca-cert.pem
```

The proxy settings apply to both the main tool and all external tools (subfinder, httpx, etc.).

### HTML Reports

Generate an HTML summary with statistics, top domains, and histograms:

```bash
go run ./cmd/passive-rec -target example.com -outdir out -report
```

The report is saved as `report.html` in the output directory and reads directly from `artifacts.jsonl`.

---

## Configuration

### Configuration File

Pre-populate CLI flags using YAML or JSON:

```bash
go run ./cmd/passive-rec --config config.yaml
```

**Precedence:** CLI flags override configuration file values.

#### YAML Example

```yaml
target: example.com
outdir: ./output
workers: 10
active: true
tools:
  - subfinder
  - amass
  - censys
timeout: 180
verbosity: 1
report: true
proxy: http://127.0.0.1:8080
proxy_ca: ~/.config/burp/ca-cert.pem
censys_api_id: "${CENSYS_API_ID}"
censys_api_secret: "${CENSYS_API_SECRET}"
```

#### JSON Example

```json
{
  "target": "example.com",
  "outdir": "./output",
  "workers": 10,
  "active": true,
  "tools": ["subfinder", "amass", "censys"],
  "timeout": 180,
  "verbosity": 1,
  "report": true,
  "proxy": "http://127.0.0.1:8080",
  "proxy_ca": "~/.config/burp/ca-cert.pem",
  "censys_api_id": "${CENSYS_API_ID}",
  "censys_api_secret": "${CENSYS_API_SECRET}"
}
```

### Environment Variables

Sensitive values can be set via environment variables:

```bash
export CENSYS_API_ID="your-api-id"
export CENSYS_API_SECRET="your-api-secret"
export HTTP_PROXY="http://127.0.0.1:8080"
export HTTPS_PROXY="http://127.0.0.1:8080"
```

### Available Options

| Field | Type | Description |
|-------|------|-------------|
| `target` | string | Target domain to enumerate |
| `outdir` | string | Output directory path |
| `workers` | int | Number of concurrent workers |
| `active` | bool | Enable active verification |
| `tools` | list/CSV | Tools to execute (e.g., `subfinder,amass`) |
| `timeout` | int | Timeout per tool in seconds |
| `verbosity` | int | Log level (0=errors, 1=info, 2=debug, 3=trace) |
| `report` | bool | Generate HTML report |
| `proxy` | string | HTTP/HTTPS proxy URL |
| `proxy_ca` | string | Path to custom CA certificate (PEM format) |
| `censys_api_id` | string | Censys API ID |
| `censys_api_secret` | string | Censys API Secret |

---

## Output Format

### Artifact Manifest

Each execution emits a consolidated manifest: **`artifacts.jsonl`**

Every line is a JSON object representing a discovered artifact:

```json
{
  "type": "domain",
  "value": "api.example.com",
  "active": true,
  "up": true,
  "tool": "subfinder",
  "tools": ["subfinder", "amass"],
  "occurrences": 2,
  "first_seen": "2025-10-11T14:30:00Z",
  "last_seen": "2025-10-11T14:35:00Z",
  "version": "1.0",
  "metadata": {
    "raw": "api.example.com [200 OK]",
    "status": 200
  }
}
```

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Artifact category (see types below) |
| `value` | string | Normalized artifact value |
| `active` | boolean | Whether discovered via active scan |
| `up` | boolean | Whether artifact is responsive (active mode only) |
| `tool` | string | Primary discovery tool |
| `tools` | []string | All tools that discovered this artifact |
| `occurrences` | int | Number of times artifact was seen |
| `first_seen` | string | ISO 8601 timestamp of first discovery |
| `last_seen` | string | ISO 8601 timestamp of last update |
| `version` | string | Schema version (current: `1.0`) |
| `metadata` | object | Additional context (see below) |

#### Artifact Types

- `domain` - Domain names
- `route` - URL paths and endpoints
- `js` - JavaScript files
- `html` - HTML pages
- `image` - Image resources
- `maps` - Map/location resources
- `json` - JSON endpoints
- `api` - API endpoints
- `wasm` - WebAssembly modules
- `svg` - SVG files
- `crawl` - Crawlable endpoints
- `meta-route` - Meta/redirect routes
- `meta` - Metadata entries
- `rdap` - RDAP records
- `certificate` - TLS certificates

#### Metadata Fields

| Field | Type | Description |
|-------|------|-------------|
| `raw` | string/[]string | Original unprocessed value(s) |
| `status` | int | HTTP status code (active routes) |
| `names` | []string | SAN entries (certificates) |
| `key` | string | Deduplication key |

**Benefits:**
- **Temporal Analysis**: Track when artifacts appear/disappear across runs
- **Multi-source Correlation**: See which tools found each artifact
- **Programmatic Consumption**: Parse JSONL instead of multiple text files
- **Forward Compatible**: Schema versioning for future migrations

### Output Directory Structure

```
output/
├── artifacts.jsonl          # Consolidated manifest
├── report.html              # HTML summary (if -report enabled)
├── domains/
│   ├── domains.passive      # Passive domain discoveries
│   └── domains.active       # Active domain discoveries
├── routes/
│   ├── routes.passive
│   ├── routes.active
│   ├── js.passive
│   ├── js.active
│   └── linkFindings/        # GoLinkfinderEVO outputs
│       ├── findings.json
│       ├── findings.html
│       └── findings.raw
├── dns/
│   └── dns.active           # dnsx resolution output
├── rdap/
│   └── rdap.passive         # RDAP metadata
└── meta/
    ├── meta.passive
    └── meta.active
```

---

## Integrations

### Censys

Query the [Censys Search API](https://search.censys.io/api) for certificate enumeration.

**Setup:**
```bash
export CENSYS_API_ID="your-id"
export CENSYS_API_SECRET="your-secret"
go run ./cmd/passive-rec -target example.com -tools censys
```

Or via flags:
```bash
go run ./cmd/passive-rec \
  -target example.com \
  -tools censys \
  -censys-api-id "$CENSYS_API_ID" \
  -censys-api-secret "$CENSYS_API_SECRET"
```

**Rate Limits:**
- Free accounts: 250 search credits/month
- Review [official limits](https://support.censys.io/hc/en-us/articles/360059995051-Rate-Limits-and-Quotas)
- Adjust `-timeout` to avoid quota exhaustion

Certificate common names and SANs are extracted and added to domain artifacts.

### RDAP

Passive stage automatically queries public RDAP directories for:
- Registrar information
- Domain status
- Nameserver details

**Output:**
- Summary: Appended to `meta.passive`
- Raw data: `rdap/rdap.passive`

### DNS Resolution (dnsx)

When `--active` is enabled, discovered domains are resolved using [dnsx](https://github.com/projectdiscovery/dnsx).

**Features:**
- Bulk DNS resolution
- A/AAAA record extraction
- CNAME following

**Output:**
- Raw JSONL: `dns/dns.active`
- Enriched artifacts with discovered IPs

### Link Discovery (GoLinkfinderEVO)

Active mode runs [GoLinkfinderEVO](https://github.com/lcalzada-xor/GoLinkfinderEVO) on HTML/JS/crawl artifacts.

**Process:**
1. Collects active HTML, JavaScript, and crawl artifacts
2. Extracts endpoints and URLs
3. Categorizes findings (API, JSON, WASM, etc.)
4. Feeds back into artifact pipeline

**Output:**
- Consolidated: `routes/linkFindings/findings.{json,html,raw}`
- Per-type: `findings.html.*`, `findings.js.*`, `findings.crawl.*`

---

## Development

**Run tests:**
```bash
go test ./...
```

**Build binary:**
```bash
go build -o passive-rec ./cmd/passive-rec
```

**Run with race detector:**
```bash
go run -race ./cmd/passive-rec -target example.com
```

**Lint:**
```bash
golangci-lint run
```

---

## License

[Add your license here]
