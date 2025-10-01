# passiveRecon

Passive web enumeration.

## External tools

This project relies on several third-party reconnaissance utilities. You can ensure they are installed by running:

```
go run ./cmd/install-deps
```

The command reads `requirements.txt`, checks if each binary is already available on your `PATH`, and uses `go install` to fetch any missing tools. The installation succeeds only if you have Go installed locally and network access to download the modules. Tools are installed into your `GOBIN` directory (or `$GOPATH/bin` if `GOBIN` is not set), so make sure that directory is exported in your `PATH`.

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
