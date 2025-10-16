package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"passive-rec/internal/adapters/report"
	"passive-rec/internal/core/pipeline"
	"passive-rec/internal/core/runner"
	"passive-rec/internal/platform/config"
	"passive-rec/internal/platform/logx"
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

	// Env para ajustar concurrencia por grupo sin cambiar API:
	// ORCHESTRATOR_GROUP_CONCURRENCY="subdomain-sources=3,archive-sources=2"
	envGroupConcurrency = "ORCHESTRATOR_GROUP_CONCURRENCY"
)

// Nombres de herramientas como constantes para evitar typos.
const (
	toolAmass         = "amass"
	toolSubfinder     = "subfinder"
	toolAssetfinder   = "assetfinder"
	toolRDAP          = "rdap"
	toolCRTSh         = "crtsh"
	toolCensys        = "censys"
	toolDedupe        = "dedupe"
	toolWayback       = "waybackurls"
	toolGAU           = "gau"
	toolHTTPX         = "httpx"
	toolSubJS         = "subjs"
	toolLinkFinderEVO = "linkfinderevo"
	toolDNSX          = "dnsx"
	toolUnknown       = "unknown"
)

type orchestratorOptions struct {
	cfg        *config.Config
	sink       sink
	requested  map[string]bool
	bar        *progressBar
	metrics    *pipelineMetrics
	cache      *executionCache
	runHash    string
	checkpoint *CheckpointManager
}

type pipelineState struct {
	DomainListFile string
	DedupedDomains []string
	DomainsDirty   bool
}

// --- Helpers de emisión unificada ------------------------------------------------

func emitWithTool(opts orchestratorOptions, tool, msg string) {
	if msg == "" || opts.sink == nil {
		return
	}
	opts.sink.In() <- pipeline.WrapWithTool(tool, msg)
}

func emitMeta(opts orchestratorOptions, tool, msg string) {
	if msg == "" {
		return
	}
	emitWithTool(opts, tool, "meta: "+msg)
}

// --- Sink-aware input channel con backpressure y cancelación ---------------------

// toolInputChannel crea un proxy con buffer y cancelación para enviar al sink.
// Mantiene la API pública (función no exportada) pero añade robustez interna.
func toolInputChannel(ctx context.Context, s sink, tool, _ string, _ *pipelineMetrics) (chan<- string, func()) {
	type toolAware interface {
		InWithTool(string) (chan<- string, func())
	}
	if aware, ok := s.(toolAware); ok {
		return aware.InWithTool(tool)
	}

	base := s.In()
	tool = strings.TrimSpace(tool)
	if tool == "" {
		// Sin etiquetar – útil para casos internos
		return base, func() {}
	}

	// Canal intermedio buffered para amortiguar ráfagas.
	ch := make(chan string, 512)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for line := range ch {
			// Reenvío con cancelación: evita deadlocks si el sink se satura.
			select {
			case base <- line:
			case <-ctx.Done():
				return
			}
		}
	}()

	cleanup := func() {
		close(ch)
		wg.Wait()
	}
	return ch, cleanup
}

// --- Definición del pipeline -----------------------------------------------------

var defaultPipeline = []toolStep{
	{Name: toolAmass, Group: "subdomain-sources", Run: stepAmass},
	{Name: toolSubfinder, Group: "subdomain-sources", Run: stepSubfinder},
	{Name: toolAssetfinder, Group: "subdomain-sources", Run: stepAssetfinder},
	{Name: toolRDAP, Group: "subdomain-sources", Run: stepRDAP},
	{Name: toolCRTSh, Group: "cert-sources", Run: stepCRTSh},
	{Name: toolCensys, Group: "cert-sources", Run: stepCensys},
	{Name: toolDedupe, Run: stepDedupe},
	{
		Name:                toolDNSX,
		Run:                 stepDNSX,
		RequiresActive:      true,
		SkipInactiveMessage: "meta: dnsx skipped (requires --active)",
		Precondition:        requireDedupedDomains("meta: dnsx skipped (no domains after dedupe)"),
	},
	{
		Name:         toolWayback,
		Group:        "archive-sources",
		Run:          stepWayback,
		Precondition: requireDedupedDomains("meta: waybackurls skipped (no domains after dedupe)"),
		Timeout:      timeoutWaybackurls,
	},
	{
		Name:         toolGAU,
		Group:        "archive-sources",
		Run:          stepGAU,
		Precondition: requireDedupedDomains("meta: gau skipped (no domains after dedupe)"),
		Timeout:      timeoutGAU,
	},
	{
		Name:                toolHTTPX,
		Run:                 stepHTTPX,
		RequiresActive:      true,
		SkipInactiveMessage: "meta: httpx skipped (requires --active)",
		Timeout:             timeoutHTTPX,
	},
	{
		Name:                toolSubJS,
		Run:                 stepSubJS,
		RequiresActive:      true,
		SkipInactiveMessage: "meta: subjs skipped (requires --active)",
	},
	{
		Name:                toolLinkFinderEVO,
		Run:                 stepLinkFinderEVO,
		RequiresActive:      true,
		SkipInactiveMessage: "meta: linkfinderevo skipped (requires --active)",
		Timeout:             timeoutLinkFinderEVO,
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

// --- Orquestación ----------------------------------------------------------------

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
		runConcurrentSteps(ctx, group, grouped, state, opts)
	}

	return state
}

func executeStep(ctx context.Context, step toolStep, state *pipelineState, opts orchestratorOptions) (func() error, bool) {
	if !isStepRequested(step, opts) {
		return nil, false
	}
	if skip := maybeSkipByCache(step, state, opts); skip {
		return nil, false
	}
	if !shouldRunStep(step, state, opts) {
		return nil, false
	}

	if producesDomainData(step.Name) {
		state.DomainsDirty = true
	}

	timeout := computeStepTimeout(step, state, opts)
	task := prepareStepTask(ctx, step, state, opts, timeout)

	return task, true
}

func isStepRequested(step toolStep, opts orchestratorOptions) bool {
	// Verificar si la tool ya fue completada en un checkpoint previo
	if opts.checkpoint != nil && opts.checkpoint.IsToolCompleted(step.Name) {
		if opts.metrics != nil {
			opts.metrics.RecordSkip(step.Name, "completado en ejecución previa (resumiendo)")
		}
		if opts.bar != nil {
			opts.bar.StepDone(step.Name, "resumido")
		}
		emitMeta(opts, step.Name, "resumiendo desde checkpoint (ya completado)")
		return false
	}

	if opts.requested[step.Name] {
		return true
	}
	if opts.metrics != nil {
		opts.metrics.RecordSkip(step.Name, "no solicitado")
	}
	return false
}

func maybeSkipByCache(step toolStep, state *pipelineState, opts orchestratorOptions) bool {
	if opts.cache == nil || opts.runHash == "" {
		return false
	}
	if step.Name == toolDedupe && state.DomainsDirty {
		// Nuevos dominios detectados en esta ejecución: no reutilizamos cache.
		return false
	}

	ok, completedAt := opts.cache.ShouldSkip(step.Name, opts.runHash, cacheMaxAge)
	if !ok {
		return false
	}

	if step.Name != toolDedupe {
		announceCacheReuse(step, opts, completedAt)
		return true
	}

	if loadCachedDedupe(state, opts) {
		state.DomainsDirty = false
		announceCacheReuse(step, opts, completedAt)
		return true
	}

	logx.Warn("Cache de dedupe inválido", logx.Fields{"action": "re-ejecutando paso"})
	if err := opts.cache.Invalidate(step.Name); err != nil {
		logx.Warn("Fallo invalidar cache", logx.Fields{
			"step":  step.Name,
			"error": err.Error(),
		})
	}
	return false
}

func prepareStepTask(ctx context.Context, step toolStep, state *pipelineState, opts orchestratorOptions, timeout int) func() error {
	task := runWithTimeout(ctx, timeout, func(c context.Context) error {
		return step.Run(c, state, opts)
	})

	if opts.bar != nil {
		task = opts.bar.Wrap(step.Name, task)
	}
	if opts.metrics != nil {
		task = opts.metrics.Wrap(step.Name, step.Group, timeout, task)
	}

	return func() error {
		err := task()
		if err != nil {
			// Mantener comportamiento, pero dar diagnósticos mejores
			if errors.Is(err, runner.ErrMissingBinary) {
				emitMeta(opts, step.Name, "missing binary (omitiendo)")
				return runner.ErrMissingBinary
			}
			if errors.Is(err, context.DeadlineExceeded) {
				emitMeta(opts, step.Name, fmt.Sprintf("timeout after %ds", timeout))
				// No propagamos error para no parar el pipeline (comportamiento actual)
				return nil
			}
			logx.Warn("Error en fuente", logx.Fields{
				"step":  step.Name,
				"error": err.Error(),
			})
			return nil
		}

		// Marcar tool como completada en checkpoint
		if opts.checkpoint != nil {
			opts.checkpoint.MarkToolCompleted(step.Name)
		}

		if opts.cache != nil && opts.runHash != "" {
			if markErr := opts.cache.MarkComplete(step.Name, opts.runHash); markErr != nil {
				logx.Warn("Fallo actualizar cache", logx.Fields{
					"step":  step.Name,
					"error": markErr.Error(),
				})
			}
		}
		if step.Name == toolDedupe {
			state.DomainsDirty = false
		}
		return nil
	}
}

func runSingleStep(ctx context.Context, step toolStep, state *pipelineState, opts orchestratorOptions) {
	task, ok := executeStep(ctx, step, state, opts)
	if !ok {
		return
	}
	_ = task()
}

func runConcurrentSteps(ctx context.Context, group string, steps []toolStep, state *pipelineState, opts orchestratorOptions) {
	// Concurrencia por grupo configurable por env.
	maxConc := parseGroupConcurrency(group, len(steps))
	if maxConc <= 0 {
		maxConc = len(steps)
	}
	sem := make(chan struct{}, maxConc)

	start := time.Now()
	if opts.metrics != nil {
		opts.metrics.RecordGroupStart(group, maxConc)
	}

	// Log cabecera de fase con formato visual
	formatter := logx.GetFormatter()
	metadata := map[string]interface{}{
		"concurrency": maxConc,
		"tools":       len(steps),
	}
	phaseHeader := formatter.FormatPhaseHeader(group, metadata, 0)
	logx.Infof("%s", phaseHeader)

	var wg runnerWaitGroup
	for _, st := range steps {
		step := st
		task, ok := executeStep(ctx, step, state, opts)
		if !ok {
			continue
		}
		if opts.metrics != nil {
			opts.metrics.RecordEnqueue(step.Name, group)
		}
		wg.Go(func() error {
			// Control de concurrencia
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return ctx.Err()
			}
			defer func() { <-sem }()
			return task()
		})
	}
	wg.Wait()

	elapsed := time.Since(start)
	if opts.metrics != nil {
		opts.metrics.RecordGroupEnd(group)
	}

	// Calcular artifacts y herramientas ejecutadas
	toolsRun := 0
	for _, st := range steps {
		if opts.requested[st.Name] {
			toolsRun++
		}
	}

	// Log resumen del grupo con formato compacto
	summaryLog := fmt.Sprintf("group=%s tools=%d elapsed=%s",
		group,
		toolsRun,
		logx.FormatDuration(elapsed),
	)
	logx.Infof("%s", summaryLog)
}

func computeStepTimeout(step toolStep, state *pipelineState, opts orchestratorOptions) int {
	// 1. Verificar si hay timeout específico configurado para esta tool
	if opts.cfg != nil && len(opts.cfg.ToolTimeouts) > 0 {
		if customTimeout, ok := opts.cfg.ToolTimeouts[step.Name]; ok && customTimeout > 0 {
			timeout := customTimeout
			if timeout < minToolTimeoutSeconds {
				timeout = minToolTimeoutSeconds
			}
			if timeout > maxToolTimeoutSeconds {
				timeout = maxToolTimeoutSeconds
			}
			return timeout
		}
	}

	// 2. Si la tool tiene función de timeout dinámico, usarla
	timeout := baseTimeoutSeconds(opts.cfg.TimeoutS)
	if step.Timeout != nil {
		if custom := step.Timeout(state, opts); custom > 0 {
			timeout = custom
		}
	}

	// 3. Aplicar límites
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
	// Omitir herramientas de enumeración de subdominios cuando scope=domain
	if opts.cfg != nil && strings.ToLower(strings.TrimSpace(opts.cfg.Scope)) == "domain" {
		if isSubdomainEnumerationTool(step.Name) {
			skipStep(step, opts, fmt.Sprintf("meta: %s skipped (scope=domain, herramienta de enumeración de subdominios)", step.Name))
			return false
		}
	}

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
		// Unificar: siempre vía emitWithTool
		emitWithTool(opts, step.Name, message)
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
	return func(state *pipelineState, _ orchestratorOptions) (bool, string) {
		if len(state.DedupedDomains) == 0 {
			return false, message
		}
		return true, ""
	}
}

// --- Steps ----------------------------------------------------------------------

func stepAmass(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	if opts.metrics != nil {
		opts.metrics.RecordInputs(toolAmass, "subdomain-sources", 1)
	}
	input, done := toolInputChannel(ctx, opts.sink, toolAmass, "subdomain-sources", opts.metrics)
	defer done()
	return sourceAmass(ctx, opts.cfg.Target, input, opts.cfg.Active)
}

func stepSubfinder(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	if opts.metrics != nil {
		opts.metrics.RecordInputs(toolSubfinder, "subdomain-sources", 1)
	}
	input, done := toolInputChannel(ctx, opts.sink, toolSubfinder, "subdomain-sources", opts.metrics)
	defer done()
	return sourceSubfinder(ctx, opts.cfg.Target, input)
}

func stepAssetfinder(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	if opts.metrics != nil {
		opts.metrics.RecordInputs(toolAssetfinder, "subdomain-sources", 1)
	}
	input, done := toolInputChannel(ctx, opts.sink, toolAssetfinder, "subdomain-sources", opts.metrics)
	defer done()
	return sourceAssetfinder(ctx, opts.cfg.Target, input)
}

func stepRDAP(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	if opts.metrics != nil {
		opts.metrics.RecordInputs(toolRDAP, "subdomain-sources", 1)
	}
	input, done := toolInputChannel(ctx, opts.sink, toolRDAP, "subdomain-sources", opts.metrics)
	defer done()
	return sourceRDAP(ctx, opts.cfg.Target, input)
}

func stepCRTSh(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	if opts.metrics != nil {
		opts.metrics.RecordInputs(toolCRTSh, "cert-sources", 1)
	}
	input, done := toolInputChannel(ctx, opts.sink, toolCRTSh, "cert-sources", opts.metrics)
	defer done()
	return sourceCRTSh(ctx, opts.cfg.Target, input)
}

func stepCensys(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	if opts.metrics != nil {
		opts.metrics.RecordInputs(toolCensys, "cert-sources", 1)
	}
	input, done := toolInputChannel(ctx, opts.sink, toolCensys, "cert-sources", opts.metrics)
	defer done()
	return sourceCensys(ctx, opts.cfg.Target, opts.cfg.CensysAPIID, opts.cfg.CensysAPISecret, input)
}

func stepDedupe(ctx context.Context, state *pipelineState, opts orchestratorOptions) error {
	opts.sink.Flush()

	domains, total, err := dedupeDomainList(opts.cfg.OutDir)
	if err != nil {
		return err
	}
	state.DedupedDomains = domains
	state.DomainListFile = filepath.Join("domains", "domains.dedupe")

	if opts.metrics != nil {
		opts.metrics.RecordInputs(toolDedupe, "", int64(total))
		opts.metrics.RecordOutputCount(toolDedupe, "", int64(len(domains)))
	}

	emitMeta(opts, toolDedupe, fmt.Sprintf("dedupe retained %d domains", len(domains)))
	if len(domains) == 0 {
		emitMeta(opts, toolDedupe, "dedupe produced no domains")
	}
	return nil
}

func stepWayback(ctx context.Context, state *pipelineState, opts orchestratorOptions) error {
	if opts.metrics != nil {
		opts.metrics.RecordInputs(toolWayback, "archive-sources", int64(len(state.DedupedDomains)))
	}
	input, done := toolInputChannel(ctx, opts.sink, toolWayback, "archive-sources", opts.metrics)
	defer done()
	return sourceWayback(ctx, state.DedupedDomains, input)
}

func stepGAU(ctx context.Context, state *pipelineState, opts orchestratorOptions) error {
	if opts.metrics != nil {
		opts.metrics.RecordInputs(toolGAU, "archive-sources", int64(len(state.DedupedDomains)))
	}
	input, done := toolInputChannel(ctx, opts.sink, toolGAU, "archive-sources", opts.metrics)
	defer done()
	return sourceGAU(ctx, state.DedupedDomains, input)
}

func stepHTTPX(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	opts.sink.Flush()
	input, done := toolInputChannel(ctx, opts.sink, toolHTTPX, "", opts.metrics)
	defer done()
	return sourceHTTPX(ctx, opts.cfg.OutDir, input)
}

func stepDNSX(ctx context.Context, state *pipelineState, opts orchestratorOptions) error {
	if opts.metrics != nil {
		opts.metrics.RecordInputs(toolDNSX, "", int64(len(state.DedupedDomains)))
	}
	input, done := toolInputChannel(ctx, opts.sink, toolDNSX, "", opts.metrics)
	defer done()
	return sourceDNSX(ctx, state.DedupedDomains, opts.cfg.OutDir, input)
}

func stepSubJS(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	input, done := toolInputChannel(ctx, opts.sink, toolSubJS, "", opts.metrics)
	defer done()
	return sourceSubJS(ctx, opts.cfg.OutDir, input)
}

func stepLinkFinderEVO(ctx context.Context, _ *pipelineState, opts orchestratorOptions) error {
	input, done := toolInputChannel(ctx, opts.sink, toolLinkFinderEVO, "", opts.metrics)
	defer done()
	return sourceLinkFinderEVO(ctx, opts.cfg.Target, opts.cfg.OutDir, input)
}

// --- Timeouts dependientes del input -------------------------------------------

func timeoutWaybackurls(state *pipelineState, opts orchestratorOptions) int {
	base := baseTimeoutSeconds(opts.cfg.TimeoutS)
	domains := len(state.DedupedDomains)
	if domains == 0 {
		return base
	}
	// Tiering suave para evitar picos raros
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

func timeoutLinkFinderEVO(state *pipelineState, opts orchestratorOptions) int {
	base := baseTimeoutSeconds(opts.cfg.TimeoutS)
	// LinkFinderEVO procesa archivos HTML/JS/crawl activos
	// A 15 entradas/segundo y max 200 por tipo, necesita ~40s para procesar 600 entradas
	// Agregamos tiempo generoso para manejar archivos grandes y análisis GF
	extra := 300 // 5 minutos adicionales por defecto
	timeout := base + extra
	if timeout > maxToolTimeoutSeconds {
		timeout = maxToolTimeoutSeconds
	}
	return timeout
}

// --- Unknown tools & cache messaging --------------------------------------------

func executePostProcessing(ctx context.Context, cfg *config.Config, sink sink, bar *progressBar, unknown []string) {
	notifyUnknownTools(sink, bar, unknown)

	if cfg.Report {
		if err := report.GenerateV2(ctx, cfg); err != nil {
			logx.Warn("Fallo generar reportes", logx.Fields{"error": err.Error()})
		} else {
			logx.Info("Reportes generados", logx.Fields{"directory": cfg.OutDir + "/reports/"})
		}
	}

	if bar != nil {
		if missing := bar.MissingTools(); len(missing) > 0 {
			logx.Info("Herramientas faltantes detectadas", logx.Fields{
				"tools": strings.Join(missing, ", "),
				"count": len(missing),
			})
		}
	}
}

func notifyUnknownTools(sink sink, bar *progressBar, unknown []string) {
	for _, tool := range unknown {
		if sink != nil {
			sink.In() <- pipeline.WrapWithTool(toolUnknown, fmt.Sprintf("meta: unknown tool: %s", tool))
		}
		if bar != nil {
			bar.StepDone(tool, "desconocido")
		}
	}
}

func announceCacheReuse(step toolStep, opts orchestratorOptions, completedAt time.Time) {
	emitWithTool(opts, step.Name, fmt.Sprintf("meta: %s reutilizado desde cache%s", step.Name, cacheAgeSuffix(completedAt)))
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
	case toolAmass, toolSubfinder, toolAssetfinder, toolRDAP, toolCRTSh, toolCensys:
		return true
	default:
		return false
	}
}

// isSubdomainEnumerationTool indica si una herramienta está diseñada específicamente
// para enumerar subdominios. Con scope=domain estas herramientas no aportan valor
// ya que sus resultados serán filtrados de todas formas.
//
// Nota: crtsh y censys NO se omiten porque pueden devolver certificados del dominio
// exacto que contienen información valiosa independientemente del scope.
func isSubdomainEnumerationTool(stepName string) bool {
	switch stepName {
	case toolAmass, toolSubfinder, toolAssetfinder, toolRDAP:
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

// --- Concurrencia por grupo (env) -----------------------------------------------

func parseGroupConcurrency(group string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(envGroupConcurrency))
	if raw == "" {
		return fallback
	}
	// formato: "subdomain-sources=3,archive-sources=2"
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])
		if !strings.EqualFold(k, group) {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return fallback
		}
		return n
	}
	return fallback
}
