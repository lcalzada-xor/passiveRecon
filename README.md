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
  "censys_api_id": "${CENSYS_API_ID}",
  "censys_api_secret": "${CENSYS_API_SECRET}"
}
```

## Censys certificates integration

The `censys` source consumes the [Censys Search API](https://search.censys.io/api) to enumerate hosts from the certificate corpus. You must supply your account credentials through the new flags or environment variables:

```bash
passive-rec --tools censys --censys-api-id "$CENSYS_API_ID" --censys-api-secret "$CENSYS_API_SECRET"
# or export them before running
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
passive-rec --tools censys
```

Censys enforces per-account rate limits (for example, free accounts currently offer 250 Search credits per month and strict request throttling). Review the [official limits](https://support.censys.io/hc/en-us/articles/360059995051-Rate-Limits-and-Quotas) that apply to your plan and adjust your `--timeout` or tool selection accordingly to avoid hitting those quotas.
