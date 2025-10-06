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
	Timeout             func(*pipelineState, orchestratorOptions) int
}

const (
	defaultToolTimeoutSeconds = 120
	minToolTimeoutSeconds     = 30
	maxToolTimeoutSeconds     = 1200
)

type orchestratorOptions struct {
	cfg       *config.Config
	sink      sink
	requested map[string]bool
	bar       *progressBar
	metrics   *pipelineMetrics
}

type pipelineState struct {
	DomainListFile string
	DedupedDomains []string
}

var defaultPipeline = []toolStep{
	{Name: "amass", Group: "subdomain-sources", Run: stepAmass},
	{Name: "subfinder", Group: "subdomain-sources", Run: stepSubfinder},
	{Name: "assetfinder", Group: "subdomain-sources", Run: stepAssetfinder},
	{Name: "rdap", Group: "subdomain-sources", Run: stepRDAP},
	{Name: "crtsh", Group: "cert-sources", Run: stepCRTSh},
	{Name: "censys", Group: "cert-sources", Run: stepCensys},
	{Name: "dedupe", Run: stepDedupe},
	{
		Name:         "waybackurls",
		Group:        "archive-sources",
		Run:          stepWayback,
		Precondition: requireDedupedDomains("meta: waybackurls skipped (no domains after dedupe)"),
		Timeout:      timeoutWaybackurls,
	},
	{
		Name:         "gau",
		Group:        "archive-sources",
		Run:          stepGAU,
		Precondition: requireDedupedDomains("meta: gau skipped (no domains after dedupe)"),
		Timeout:      timeoutGAU,
	},
	{
		Name:                "httpx",
		Run:                 stepHTTPX,
		RequiresActive:      true,
		SkipInactiveMessage: "meta: httpx skipped (requires --active)",
		Timeout:             timeoutHTTPX,
	},
	{
		Name:                "subjs",
		Run:                 stepSubJS,
		RequiresActive:      true,
		SkipInactiveMessage: "meta: subjs skipped (requires --active)",
	},
	{
		Name:                "linkfinderevo",
		Run:                 stepLinkFinderEVO,
		RequiresActive:      true,
		SkipInactiveMessage: "meta: linkfinderevo skipped (requires --active)",
	},
}

var (
	defaultToolOrder = buildToolOrder(defaultPipeline)
	defaultSteps     = buildStepMap(defaultPipeline)
)

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

func executeStep(ctx context.Context, step toolStep, state *pipelineState, opts orchestratorOptions) (func() error, bool) {
	if !opts.requested[step.Name] {
		if opts.metrics != nil {
			opts.metrics.RecordSkip(step.Name, "no solicitado")
		}
		return nil, false
	}
	if !shouldRunStep(step, state, opts) {
		return nil, false
	}

	timeout := computeStepTimeout(step, state, opts)
	task := runWithTimeout(ctx, timeout, func(c context.Context) error {
		return step.Run(c, state, opts)
	})
	if opts.bar != nil {
		task = opts.bar.Wrap(step.Name, task)
	}
	if opts.metrics != nil {
		task = opts.metrics.Wrap(step.Name, timeout, task)
	}

	wrapped := func() error {
		if err := task(); err != nil {
			if errors.Is(err, runner.ErrMissingBinary) {
				return runner.ErrMissingBinary
			}
			logx.Warnf("source error: %v", err)
		}
		return nil
	}

	return wrapped, true
}

func runSingleStep(ctx context.Context, step toolStep, state *pipelineState, opts orchestratorOptions) {
	task, ok := executeStep(ctx, step, state, opts)
	if !ok {
		return
	}
	task()
}

func runConcurrentSteps(ctx context.Context, steps []toolStep, state *pipelineState, opts orchestratorOptions) {
	var wg runnerWaitGroup
	for _, step := range steps {
		task, ok := executeStep(ctx, step, state, opts)
		if !ok {
			continue
		}
		wg.Go(task)
	}
	wg.Wait()
}

func computeStepTimeout(step toolStep, state *pipelineState, opts orchestratorOptions) int {
	timeout := baseTimeoutSeconds(opts.cfg.TimeoutS)
	if step.Timeout != nil {
		if custom := step.Timeout(state, opts); custom > 0 {
			timeout = custom
		}
	}
	if timeout < minToolTimeoutSeconds {
		timeout = minToolTimeoutSeconds
	}
	if timeout > maxToolTimeoutSeconds {
		timeout = maxToolTimeoutSeconds
	}
	return timeout
}

func baseTimeoutSeconds(configured int) int {
	if configured <= 0 {
		return defaultToolTimeoutSeconds
	}
	return configured
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
	if opts.metrics != nil {
		opts.metrics.RecordSkip(step.Name, message)
	}
}

func buildToolOrder(steps []toolStep) []string {
	order := make([]string, 0, len(steps))
	for _, step := range steps {
		order = append(order, step.Name)
	}
	return order
}

func buildStepMap(steps []toolStep) map[string]toolStep {
	m := make(map[string]toolStep, len(steps))
	for _, step := range steps {
		m[step.Name] = step
	}
	return m
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

func stepRDAP(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	return sourceRDAP(ctx, opts.cfg.Target, opts.sink.In())
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
	if opts.cfg.Active {
		if err := sourceDNSX(ctx, domains, opts.cfg.OutDir, opts.sink.In()); err != nil {
			return err
		}
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

func timeoutWaybackurls(state *pipelineState, opts orchestratorOptions) int {
	base := baseTimeoutSeconds(opts.cfg.TimeoutS)
	domains := len(state.DedupedDomains)
	if domains == 0 {
		return base
	}
	extra := domains / 20
	if extra > 600 {
		extra = 600
	}
	return base + extra
}

func timeoutGAU(state *pipelineState, opts orchestratorOptions) int {
	base := baseTimeoutSeconds(opts.cfg.TimeoutS)
	domains := len(state.DedupedDomains)
	if domains == 0 {
		return base
	}
	extra := domains / 15
	if extra > 600 {
		extra = 600
	}
	return base + extra
}

func timeoutHTTPX(state *pipelineState, opts orchestratorOptions) int {
	base := baseTimeoutSeconds(opts.cfg.TimeoutS)
	domains := len(state.DedupedDomains)
	if domains == 0 {
		return base
	}
	workers := opts.cfg.Workers
	if workers <= 0 {
		workers = 1
	}
	extra := domains / (workers * 2)
	if extra > 900 {
		extra = 900
	}
	return base + extra
}

func stepSubJS(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	return sourceSubJS(ctx, filepath.Join("routes", "routes.active"), opts.cfg.OutDir, opts.sink.In())
}

func stepLinkFinderEVO(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	return sourceLinkFinderEVO(ctx, opts.cfg.Target, opts.cfg.OutDir, opts.sink.In())
}

func executePostProcessing(ctx context.Context, cfg *config.Config, sink sink, bar *progressBar, unknown []string) {
	notifyUnknownTools(sink, bar, unknown)

	if cfg.Report {
		sinkFiles := report.DefaultSinkFiles(cfg.OutDir)
		if cfg.Active {
			sinkFiles.ActiveDomains = filepath.Join(cfg.OutDir, "domains", "domains.active")
			sinkFiles.ActiveRoutes = filepath.Join(cfg.OutDir, "routes", "routes.active")
			sinkFiles.ActiveCerts = filepath.Join(cfg.OutDir, "certs", "certs.active")
			sinkFiles.ActiveDNS = filepath.Join(cfg.OutDir, "dns", "dns.active")
			sinkFiles.ActiveMeta = filepath.Join(cfg.OutDir, "meta.active")
		}
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
