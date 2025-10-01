package main

import (
	"flag"
	"fmt"
	"os"

	"passive-rec/internal/app"
	"passive-rec/internal/config"
	"passive-rec/internal/logx"
)

func main() {
	cfg := config.ParseFlags()

	logx.SetVerbosity(cfg.Verbosity)
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
