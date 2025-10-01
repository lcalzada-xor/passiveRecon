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
