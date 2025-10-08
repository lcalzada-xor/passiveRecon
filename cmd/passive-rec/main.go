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

	logx.SetVerbosity(cfg.Verbosity)
	if err := config.ApplyProxy(cfg.Proxy); err != nil {
		logx.Errorf("%v", err)
		os.Exit(1)
	}
	if cfg.Proxy != "" {
		logx.Infof("Usando proxy %s", cfg.Proxy)
	}
	if err := config.ConfigureRootCAs(cfg.ProxyCACert); err != nil {
		logx.Errorf("%v", err)
		os.Exit(1)
	}
	if cfg.ProxyCACert != "" {
		logx.Infof("Certificado CA adicional cargado desde %s", cfg.ProxyCACert)
	}
	logx.Infof("Iniciando passive-rec target=%s outdir=%s tools=%v workers=%d active=%v report=%v",
		cfg.Target, cfg.OutDir, cfg.Tools, cfg.Workers, cfg.Active, cfg.Report)

	if cfg.Target == "" {
		fmt.Fprintln(os.Stderr, "uso: -target example.com")
		flag.PrintDefaults()
		os.Exit(1)
	}
	if err := app.Run(cfg); err != nil {
		logx.Errorf("%v", err)
		os.Exit(1)
	}
	logx.Infof("Listo. Archivos .passive creados en: %s", cfg.OutDir)
}
