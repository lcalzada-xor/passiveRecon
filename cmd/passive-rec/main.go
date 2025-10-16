package main

import (
	"flag"
	"fmt"
	"os"

	"passive-rec/internal/core/app"
	"passive-rec/internal/platform/config"
	"passive-rec/internal/platform/logx"
)

func main() {
	cfg := config.ParseFlags()

	// Aplicar configuración de logging
	logx.SetVerbosity(cfg.Verbosity)
	logx.ApplyCliFlags(logx.CliFlags{
		NoColor:   cfg.NoColor,
		Compact:   cfg.Compact,
		Verbosity: getVerbosityString(cfg.Verbosity),
		Width:     cfg.LogWidth,
	})

	if err := config.ApplyProxy(cfg.Proxy); err != nil {
		logx.Error("Error configurando proxy", logx.Fields{"error": err.Error()})
		os.Exit(1)
	}
	if cfg.Proxy != "" {
		logx.Info("Proxy configurado", logx.Fields{"proxy": cfg.Proxy})
	}
	if err := config.ConfigureRootCAs(cfg.ProxyCACert); err != nil {
		logx.Error("Error configurando certificado CA", logx.Fields{"error": err.Error()})
		os.Exit(1)
	}
	if cfg.ProxyCACert != "" {
		logx.Info("Certificado CA cargado", logx.Fields{"path": cfg.ProxyCACert})
	}
	logx.Info("Iniciando passive-rec", logx.Fields{
		"target":  cfg.Target,
		"outdir":  cfg.OutDir,
		"tools":   cfg.Tools,
		"workers": cfg.Workers,
		"active":  cfg.Active,
		"report":  cfg.Report,
	})

	if cfg.Target == "" {
		fmt.Fprintln(os.Stderr, "uso: -target example.com")
		flag.PrintDefaults()
		os.Exit(1)
	}
	if err := app.Run(cfg); err != nil {
		logx.Error("Error ejecutando aplicación", logx.Fields{"error": err.Error()})
		os.Exit(1)
	}
	logx.Info("Ejecución completada", logx.Fields{"outdir": cfg.OutDir})
}

func getVerbosityString(level int) string {
	switch level {
	case 0:
		return "info"
	case 1:
		return "info"
	case 2:
		return "debug"
	case 3:
		return "trace"
	default:
		return "info"
	}
}
