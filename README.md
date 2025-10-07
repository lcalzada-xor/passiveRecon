# passiveRecon

Passive web enumeration.

## External tools

This project relies on several third-party reconnaissance utilities. You can ensure they are installed by running:

```
go run ./cmd/install-deps
```

The command reads `requirements.txt`, checks if each binary is already available on your `PATH`, and uses `go install` to fetch any missing tools. The installation succeeds only if you have Go installed locally and network access to download the modules. Tools are installed into your `GOBIN` directory (or `$GOPATH/bin` if `GOBIN` is not set), so make sure that directory is exported in your `PATH`.


## Usage

Generate the passive reconnaissance dataset with:

```
go run ./cmd/passive-rec -target example.com -outdir out
```

To render an HTML summary with totals, top domains and histograms alongside the `.passive` files, add the `-report` flag:

```
go run ./cmd/passive-rec -target example.com -outdir out -report
```

The report is saved as `report.html` inside the selected output directory.

If you need to route all outbound HTTP/S requests (including third-party tools) through a proxy, provide its URL via `-proxy`:

```
go run ./cmd/passive-rec -target example.com -proxy http://127.0.0.1:8080
```

The value is used to populate the standard `HTTP(S)_PROXY` environment variables before invoking the pipeline. When your proxy
performs TLS interception with its own certificate authority (for example Burp Suite or OWASP ZAP), point `-proxy-ca` to the
PEM file containing that certificate so passive-rec trusts the man-in-the-middle tunnel:

```
go run ./cmd/passive-rec -target example.com -proxy http://127.0.0.1:8080 -proxy-ca ~/.config/burp/ca-cert.pem
```

When the `--active` flag is enabled the pipeline now includes [GoLinkfinderEVO](https://github.com/lcalzada-xor/GoLinkfinderEVO).
The tool inspects the active HTML, JavaScript and crawl lists, stores consolidated reports under `routes/linkFindings/` (`findings.json`, `findings.html` and `findings.raw`) and feeds the discovered endpoints back into the categorised `.active` artifacts.
For reference, the raw GoLinkfinderEVO outputs from each input list are also preserved alongside the consolidated files as `findings.html.*`, `findings.js.*` and `findings.crawl.*`.

The passive stage now queries the public RDAP directory for the target domain. Its summaries are appended to `meta.passive` while a copy of the raw metadata lives under `rdap/rdap.passive`, making it easier to review registrar, status and nameserver details alongside the rest of the reconnaissance output.

### Artifact manifest

Each execution now emits a consolidated manifest as `artifacts.jsonl` at the root of the output directory. Every line is a JSON
object with the following shape:

```json
{
  "type": "domain | route | js | html | image | maps | json | api | wasm | svg | crawl | meta-route | meta | rdap | certificate",
  "value": "canonical artifact value",
  "active": false,
  "tool": "optional source name",
  "metadata": {
    "raw": "original line before normalisation",
    "status": 200,
    "names": ["alt1.example.com"],
    "key": "sha256:..."
  }
}
```

`type` denotes the sink that received the artifact and `value` stores the normalised representation that was written to the
traditional `.passive`/`.active` files. The optional `metadata` object captures additional context such as HTTP status codes for
active routes, the unmodified line seen on the pipeline, deduplication keys and certificate SAN lists. When available the
`tool` attribute indicates the originating tool (for example `rdap`, `httpx` or `censys`). Consumers can iterate over the JSONL
stream instead of reopening and parsing multiple `.passive` files when producing reports or dashboards.

### Configuration file

You can pre-populate the CLI flags with a YAML or JSON configuration file by passing its path through `--config`:

```
go run ./cmd/passive-rec --config config.yaml
```

If a value is present both in the config file and as a CLI flag, the CLI flag wins. Supported keys are:

| Campo              | Tipo                | Descripción                                      |
|--------------------|---------------------|--------------------------------------------------|
| `target`           | string              | Dominio objetivo                                 |
| `outdir`           | string              | Directorio de salida                             |
| `workers`          | int                 | Número de workers concurrentes                   |
| `active`           | bool                | Ejecuta comprobaciones activas                   |
| `tools`            | lista o CSV         | Herramientas a ejecutar                          |
| `timeout`          | int                 | Timeout por herramienta en segundos              |
| `verbosity`        | int                 | Nivel de verbosidad (0-3)                        |
| `report`           | bool                | Genera informe HTML                              |
| `proxy`            | string              | URL del proxy HTTP/HTTPS                         |
| `proxy_ca`         | string              | Ruta a un certificado CA adicional para el proxy |
| `censys_api_id`    | string              | Credencial Censys API ID                         |
| `censys_api_secret`| string              | Credencial Censys API Secret                     |

A YAML example:

```yaml
target: example.com
outdir: out
workers: 10
active: true
tools:
  - subfinder
  - amass
timeout: 180
verbosity: 1
report: true
proxy: http://127.0.0.1:8080
proxy_ca: ~/.config/burp/ca-cert.pem
censys_api_id: "${CENSYS_API_ID}"
censys_api_secret: "${CENSYS_API_SECRET}"
```

The same configuration in JSON:

```json
{
  "target": "example.com",
  "outdir": "out",
  "workers": 10,
  "active": true,
  "tools": ["subfinder", "amass"],
  "timeout": 180,
  "verbosity": 1,
  "report": true,
  "proxy": "http://127.0.0.1:8080",
  "proxy_ca": "~/.config/burp/ca-cert.pem",
  "censys_api_id": "${CENSYS_API_ID}",
  "censys_api_secret": "${CENSYS_API_SECRET}"
}
```

## Censys certificates integration

The `censys` source consumes the [Censys Search API](https://search.censys.io/api) to enumerate hosts from the certificate corpus. When certificate records are ingested their common name and SAN entries are now added to the domain artifacts, feeding both the passive list (and the active list when running in active mode). You must supply your account credentials through the new flags or environment variables:

```bash
passive-rec --tools censys --censys-api-id "$CENSYS_API_ID" --censys-api-secret "$CENSYS_API_SECRET"
# or export them before running
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
passive-rec --tools censys
```

Censys enforces per-account rate limits (for example, free accounts currently offer 250 Search credits per month and strict request throttling). Review the [official limits](https://support.censys.io/hc/en-us/articles/360059995051-Rate-Limits-and-Quotas) that apply to your plan and adjust your `--timeout` or tool selection accordingly to avoid hitting those quotas.
