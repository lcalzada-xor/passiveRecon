package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"passive-rec/internal/config"
	"passive-rec/internal/logx"
	"passive-rec/internal/report"
	"passive-rec/internal/runner"
)

type stepFunc func(context.Context, *pipelineState, orchestratorOptions) error

type preconditionFunc func(*pipelineState, orchestratorOptions) (bool, string)

type toolStep struct {
	Name                string
	Group               string
	RequiresActive      bool
	SkipInactiveMessage string
	Run                 stepFunc
	Precondition        preconditionFunc
}

type orchestratorOptions struct {
	cfg       *config.Config
	sink      sink
	requested map[string]bool
	bar       *progressBar
}

type pipelineState struct {
	DomainListFile string
	DedupedDomains []string
}

func runPipeline(ctx context.Context, steps []toolStep, opts orchestratorOptions) *pipelineState {
	state := &pipelineState{DomainListFile: filepath.Join("domains", "domains.passive")}

	for i := 0; i < len(steps); {
		step := steps[i]
		if step.Group == "" {
			runSingleStep(ctx, step, state, opts)
			i++
			continue
		}

		group := step.Group
		var grouped []toolStep
		for i < len(steps) && steps[i].Group == group {
			grouped = append(grouped, steps[i])
			i++
		}
		runConcurrentSteps(ctx, grouped, state, opts)
	}

	return state
}

func runSingleStep(ctx context.Context, step toolStep, state *pipelineState, opts orchestratorOptions) {
	if !opts.requested[step.Name] {
		return
	}
	if !shouldRunStep(step, state, opts) {
		return
	}

	task := runWithTimeout(ctx, opts.cfg.TimeoutS, func(c context.Context) error {
		return step.Run(c, state, opts)
	})
	if opts.bar != nil {
		task = opts.bar.Wrap(step.Name, task)
	}
	if err := task(); err != nil {
		if errors.Is(err, runner.ErrMissingBinary) {
			return
		}
		logx.Warnf("source error: %v", err)
	}
}

func runConcurrentSteps(ctx context.Context, steps []toolStep, state *pipelineState, opts orchestratorOptions) {
	var wg runnerWaitGroup
	for _, step := range steps {
		if !opts.requested[step.Name] {
			continue
		}
		if !shouldRunStep(step, state, opts) {
			continue
		}
		current := step
		task := runWithTimeout(ctx, opts.cfg.TimeoutS, func(c context.Context) error {
			return current.Run(c, state, opts)
		})
		if opts.bar != nil {
			task = opts.bar.Wrap(current.Name, task)
		}
		wg.Go(task)
	}
	wg.Wait()
}

func shouldRunStep(step toolStep, state *pipelineState, opts orchestratorOptions) bool {
	if step.RequiresActive && !opts.cfg.Active {
		skipStep(step, opts, step.SkipInactiveMessage)
		return false
	}
	if step.Precondition != nil {
		ok, message := step.Precondition(state, opts)
		if !ok {
			skipStep(step, opts, message)
			return false
		}
	}
	return true
}

func skipStep(step toolStep, opts orchestratorOptions, message string) {
	if message != "" {
		opts.sink.In() <- message
	}
	if opts.bar != nil {
		opts.bar.StepDone(step.Name, "omitido")
	}
}

var defaultSteps = map[string]toolStep{
	"amass":       {Name: "amass", Run: stepAmass},
	"subfinder":   {Name: "subfinder", Group: "subdomain-sources", Run: stepSubfinder},
	"assetfinder": {Name: "assetfinder", Group: "subdomain-sources", Run: stepAssetfinder},
	"crtsh":       {Name: "crtsh", Group: "cert-sources", Run: stepCRTSh},
	"censys":      {Name: "censys", Group: "cert-sources", Run: stepCensys},
	"dedupe":      {Name: "dedupe", Run: stepDedupe},
	"waybackurls": {
		Name:         "waybackurls",
		Group:        "archive-sources",
		Run:          stepWayback,
		Precondition: requireDedupedDomains("meta: waybackurls skipped (no domains after dedupe)")},
	"gau": {
		Name:         "gau",
		Group:        "archive-sources",
		Run:          stepGAU,
		Precondition: requireDedupedDomains("meta: gau skipped (no domains after dedupe)")},
	"httpx": {
		Name:                "httpx",
		Run:                 stepHTTPX,
		RequiresActive:      true,
		SkipInactiveMessage: "meta: httpx skipped (requires --active)",
	},
	"subjs": {
		Name:                "subjs",
		Run:                 stepSubJS,
		RequiresActive:      true,
		SkipInactiveMessage: "meta: subjs skipped (requires --active)",
	},
}

func requireDedupedDomains(message string) preconditionFunc {
	return func(state *pipelineState, opts orchestratorOptions) (bool, string) {
		if len(state.DedupedDomains) == 0 {
			return false, message
		}
		return true, ""
	}
}

func stepAmass(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	return sourceAmass(ctx, opts.cfg.Target, opts.sink.In(), opts.cfg.Active)
}

func stepSubfinder(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	return sourceSubfinder(ctx, opts.cfg.Target, opts.sink.In())
}

func stepAssetfinder(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	return sourceAssetfinder(ctx, opts.cfg.Target, opts.sink.In())
}

func stepCRTSh(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	return sourceCRTSh(ctx, opts.cfg.Target, opts.sink.In())
}

func stepCensys(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	return sourceCensys(ctx, opts.cfg.Target, opts.cfg.CensysAPIID, opts.cfg.CensysAPISecret, opts.sink.In())
}

func stepDedupe(ctx context.Context, state *pipelineState, opts orchestratorOptions) error {
	opts.sink.Flush()
	domains, err := dedupeDomainList(opts.cfg.OutDir)
	if err != nil {
		return err
	}
	state.DedupedDomains = domains
	state.DomainListFile = filepath.Join("domains", "domains.dedupe")
	opts.sink.In() <- fmt.Sprintf("meta: dedupe retained %d domains", len(domains))
	if len(domains) == 0 {
		opts.sink.In() <- "meta: dedupe produced no domains"
	}
	return nil
}

func stepWayback(ctx context.Context, state *pipelineState, opts orchestratorOptions) error {
	return sourceWayback(ctx, state.DedupedDomains, opts.sink.In())
}

func stepGAU(ctx context.Context, state *pipelineState, opts orchestratorOptions) error {
	return sourceGAU(ctx, state.DedupedDomains, opts.sink.In())
}

func stepHTTPX(ctx context.Context, state *pipelineState, opts orchestratorOptions) error {
	opts.sink.Flush()
	inputs := []string{state.DomainListFile, filepath.Join("routes", "routes.passive")}
	err := sourceHTTPX(ctx, inputs, opts.cfg.OutDir, opts.sink.In())
	opts.sink.Flush()
	return err
}

func stepSubJS(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	return sourceSubJS(ctx, filepath.Join("routes", "routes.active"), opts.cfg.OutDir, opts.sink.In())
}

func executePostProcessing(ctx context.Context, cfg *config.Config, sink sink, bar *progressBar, unknown []string) {
	notifyUnknownTools(sink, bar, unknown)

	if cfg.Report {
		sinkFiles := report.DefaultSinkFiles(cfg.OutDir)
		if err := report.Generate(ctx, cfg, sinkFiles); err != nil {
			logx.Warnf("no se pudo generar report.html: %v", err)
		} else {
			logx.Infof("Informe HTML generado en %s", filepath.Join(cfg.OutDir, "report.html"))
		}
	}

	if bar != nil {
		if missing := bar.MissingTools(); len(missing) > 0 {
			logx.Infof("Herramientas faltantes en el sistema: %s", strings.Join(missing, ", "))
		}
	}
}

func notifyUnknownTools(sink sink, bar *progressBar, unknown []string) {
	for _, tool := range unknown {
		sink.In() <- fmt.Sprintf("meta: unknown tool: %s", tool)
		if bar != nil {
			bar.StepDone(tool, "desconocido")
		}
	}
}
