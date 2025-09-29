# passiveRecon

Passive web enumeration.

## External tools

This project relies on several third-party reconnaissance utilities. You can ensure they are installed by running:

```
go run ./cmd/install-deps
```

The command reads `requirements.txt`, checks if each binary is already available on your `PATH`, and uses `go install` to fetch any missing tools. The installation succeeds only if you have Go installed locally and network access to download the modules. Tools are installed into your `GOBIN` directory (or `$GOPATH/bin` if `GOBIN` is not set), so make sure that directory is exported in your `PATH`.
