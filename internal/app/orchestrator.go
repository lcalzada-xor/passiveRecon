package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"passive-rec/internal/config"
	"passive-rec/internal/logx"
	"passive-rec/internal/pipeline"
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
	cache     *executionCache
	runHash   string
}

type pipelineState struct {
	DomainListFile string
	DedupedDomains []string
	DomainsDirty   bool
}

func toolInputChannel(s sink, tool string) (chan<- string, func()) {
	type toolAware interface {
		InWithTool(string) (chan<- string, func())
	}
	if aware, ok := s.(toolAware); ok {
		return aware.InWithTool(tool)
	}

	base := s.In()
	tool = strings.TrimSpace(tool)
	if tool == "" {
		return base, func() {}
	}
	ch := make(chan string)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for line := range ch {
			base <- line
		}
	}()
	cleanup := func() {
		close(ch)
		wg.Wait()
	}
	return ch, cleanup
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

const (
	cacheMaxAge        = 24 * time.Hour
	cacheSkipBaseLabel = "resultado reutilizado desde cache"
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

	if opts.cache != nil && opts.runHash != "" {
		if step.Name == "dedupe" && state.DomainsDirty {
			// Nuevos dominios detectados en esta ejecución: no reutilizamos cache.
		} else if ok, completedAt := opts.cache.ShouldSkip(step.Name, opts.runHash, cacheMaxAge); ok {
			if step.Name == "dedupe" {
				if !loadCachedDedupe(state, opts) {
					logx.Warnf("cache dedupe inválido, se vuelve a ejecutar paso")
					if err := opts.cache.Invalidate(step.Name); err != nil {
						logx.Warnf("no se pudo invalidar cache de %s: %v", step.Name, err)
					}
				} else {
					state.DomainsDirty = false
					announceCacheReuse(step, opts, completedAt)
					return nil, false
				}
			} else {
				announceCacheReuse(step, opts, completedAt)
				return nil, false
			}
		}
	}
	if !shouldRunStep(step, state, opts) {
		return nil, false
	}

	if producesDomainData(step.Name) {
		state.DomainsDirty = true
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
		err := task()
		if err != nil {
			if errors.Is(err, runner.ErrMissingBinary) {
				return runner.ErrMissingBinary
			}
			logx.Warnf("source error: %v", err)
			return nil
		}
		if opts.cache != nil && opts.runHash != "" {
			if markErr := opts.cache.MarkComplete(step.Name, opts.runHash); markErr != nil {
				logx.Warnf("no se pudo actualizar cache para %s: %v", step.Name, markErr)
			}
		}
		if step.Name == "dedupe" {
			state.DomainsDirty = false
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
	input, done := toolInputChannel(opts.sink, "amass")
	defer done()
	return sourceAmass(ctx, opts.cfg.Target, input, opts.cfg.Active)
}

func stepSubfinder(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	input, done := toolInputChannel(opts.sink, "subfinder")
	defer done()
	return sourceSubfinder(ctx, opts.cfg.Target, input)
}

func stepAssetfinder(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	input, done := toolInputChannel(opts.sink, "assetfinder")
	defer done()
	return sourceAssetfinder(ctx, opts.cfg.Target, input)
}

func stepRDAP(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	input, done := toolInputChannel(opts.sink, "rdap")
	defer done()
	return sourceRDAP(ctx, opts.cfg.Target, input)
}

func stepCRTSh(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	input, done := toolInputChannel(opts.sink, "crtsh")
	defer done()
	return sourceCRTSh(ctx, opts.cfg.Target, input)
}

func stepCensys(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	input, done := toolInputChannel(opts.sink, "censys")
	defer done()
	return sourceCensys(ctx, opts.cfg.Target, opts.cfg.CensysAPIID, opts.cfg.CensysAPISecret, input)
}

func stepDedupe(ctx context.Context, state *pipelineState, opts orchestratorOptions) error {
	opts.sink.Flush()
	domains, err := dedupeDomainList(opts.cfg.OutDir)
	if err != nil {
		return err
	}
	state.DedupedDomains = domains
	state.DomainListFile = filepath.Join("domains", "domains.dedupe")
	opts.sink.In() <- pipeline.WrapWithTool("dedupe", fmt.Sprintf("meta: dedupe retained %d domains", len(domains)))
	if len(domains) == 0 {
		opts.sink.In() <- pipeline.WrapWithTool("dedupe", "meta: dedupe produced no domains")
	}
	if opts.cfg.Active {
		input, done := toolInputChannel(opts.sink, "dnsx")
		defer done()
		if err := sourceDNSX(ctx, domains, opts.cfg.OutDir, input); err != nil {
			return err
		}
	}
	return nil
}

func stepWayback(ctx context.Context, state *pipelineState, opts orchestratorOptions) error {
	input, done := toolInputChannel(opts.sink, "waybackurls")
	defer done()
	return sourceWayback(ctx, state.DedupedDomains, input)
}

func stepGAU(ctx context.Context, state *pipelineState, opts orchestratorOptions) error {
	input, done := toolInputChannel(opts.sink, "gau")
	defer done()
	return sourceGAU(ctx, state.DedupedDomains, input)
}

func stepHTTPX(ctx context.Context, state *pipelineState, opts orchestratorOptions) error {
	opts.sink.Flush()
	input, done := toolInputChannel(opts.sink, "httpx")
	defer done()
	err := sourceHTTPX(ctx, opts.cfg.OutDir, input)
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
	input, done := toolInputChannel(opts.sink, "subjs")
	defer done()
	return sourceSubJS(ctx, opts.cfg.OutDir, input)
}

func stepLinkFinderEVO(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	input, done := toolInputChannel(opts.sink, "linkfinderevo")
	defer done()
	return sourceLinkFinderEVO(ctx, opts.cfg.Target, opts.cfg.OutDir, input)
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
		sink.In() <- pipeline.WrapWithTool("unknown", fmt.Sprintf("meta: unknown tool: %s", tool))
		if bar != nil {
			bar.StepDone(tool, "desconocido")
		}
	}
}

func announceCacheReuse(step toolStep, opts orchestratorOptions, completedAt time.Time) {
	if opts.sink != nil {
		opts.sink.In() <- pipeline.WrapWithTool(step.Name, fmt.Sprintf("meta: %s reutilizado desde cache%s", step.Name, cacheAgeSuffix(completedAt)))
	}
	if opts.bar != nil {
		opts.bar.StepDone(step.Name, "cache")
	}
	if opts.metrics != nil {
		opts.metrics.RecordSkip(step.Name, cacheSkipReason(completedAt))
	}
}

func cacheAgeSuffix(completedAt time.Time) string {
	if completedAt.IsZero() {
		return ""
	}
	age := time.Since(completedAt)
	if age < 0 {
		age = 0
	}
	return fmt.Sprintf(" (edad %s)", age.Round(time.Second))
}

func cacheSkipReason(completedAt time.Time) string {
	if completedAt.IsZero() {
		return cacheSkipBaseLabel
	}
	age := time.Since(completedAt)
	if age < 0 {
		age = 0
	}
	return fmt.Sprintf("%s (%s)", cacheSkipBaseLabel, age.Round(time.Second))
}

func producesDomainData(stepName string) bool {
	switch stepName {
	case "amass", "subfinder", "assetfinder", "rdap", "crtsh", "censys":
		return true
	default:
		return false
	}
}

func loadCachedDedupe(state *pipelineState, opts orchestratorOptions) bool {
	if opts.cfg == nil {
		return false
	}
	domains, err := readDedupeFile(opts.cfg.OutDir)
	if err != nil {
		return false
	}
	state.DedupedDomains = domains
	state.DomainListFile = filepath.Join("domains", "domains.dedupe")
	return true
}
