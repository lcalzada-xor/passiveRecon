package linkfinderevo

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"

	"passive-rec/internal/adapters/artifacts"
	"passive-rec/internal/core/runner"
)

var (
	// Permite inyección en tests.
	findBin = runner.FindBin
	runCmd  = runner.RunCommandWithDir
)

const findingsDirName = "linkFindings"

// Run ejecuta el binario GoLinkfinderEVO sobre HTML/JS/crawl activos,
// agrega resultados, persiste artefactos y emite rutas clasificadas al sink.
func Run(ctx context.Context, target string, outdir string, out chan<- string) error {
	bin, ok := findBin("GoLinkfinderEVO")
	if !ok {
		emit(out, "active: meta: GoLinkfinderEVO not found in PATH")
		return runner.ErrMissingBinary
	}

	findingsDir := filepath.Join(outdir, "routes", findingsDirName)
	if err := os.MkdirAll(findingsDir, defaultDirPerm); err != nil {
		return fmt.Errorf("mkdir findings dir: %w", err)
	}

	selectors := map[string]artifacts.ActiveState{
		"html":  artifacts.UpOnly,
		"js":    artifacts.UpOnly,
		"crawl": artifacts.UpOnly,
	}
	valuesByType, err := artifacts.CollectValuesByType(outdir, selectors)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			emit(out, "active: meta: linkfinderevo skipped (missing artifacts.jsonl)")
			return nil
		}
		return fmt.Errorf("collect artifacts: %w", err)
	}

	inputs := []struct {
		label  string
		values []string
	}{
		{label: "html", values: valuesByType["html"]},
		{label: "js", values: valuesByType["js"]},
		{label: "crawl", values: valuesByType["crawl"]},
	}

	// Reportar estadísticas de input encontrado
	totalInputs := 0
	for _, input := range inputs {
		if len(input.values) > 0 {
			emit(out, fmt.Sprintf("active: meta: linkfinderevo found %d %s entries", len(input.values), input.label))
			totalInputs += len(input.values)
		}
	}
	if totalInputs == 0 {
		emit(out, "active: meta: linkfinderevo skipped (no html/js/crawl artifacts found with up status)")
		return nil
	}

	agg := newAggregate()
	gfAgg := newGFAggregate()
	var firstErr error

	maxEntries := len(inputs) * maxInputEntries
	totalBudget := entryBudget(ctx, maxEntries)

	emit(out, fmt.Sprintf("active: meta: linkfinderevo budget: %d entries (max: %d, inputs: %d)", totalBudget, maxEntries, totalInputs))

	if totalBudget <= 0 {
		deadline, hasDeadline := ctx.Deadline()
		if hasDeadline {
			remaining := time.Until(deadline)
			emit(out, fmt.Sprintf("active: meta: linkfinderevo skipped (insufficient time budget, deadline in %s)", remaining.Round(time.Millisecond)))
		} else {
			emit(out, "active: meta: linkfinderevo skipped (insufficient time budget)")
		}
		return nil
	}

	// Semilla separada por ejecución para muestreos.
	rand.Seed(time.Now().UnixNano())

	for _, input := range inputs {
		// Cancelación temprana por contexto.
		if ctx.Err() != nil {
			recordError(&firstErr, ctx.Err())
			break
		}

		data := encodeEntries(input.values)
		if len(data) == 0 {
			continue
		}

		if totalBudget <= 0 {
			emit(out, fmt.Sprintf("active: meta: linkfinderevo skipped %s (time budget exhausted)", input.label))
			break
		}

		tmpDir, err := os.MkdirTemp("", tmpPrefix)
		if err != nil {
			recordError(&firstErr, fmt.Errorf("mktemp: %w", err))
			break
		}

		limit := maxInputEntries
		if totalBudget < limit {
			limit = totalBudget
		}

		inputPath, err := writeInput(tmpDir, input.label, data)
		if err != nil {
			recordError(&firstErr, fmt.Errorf("write input: %w", err))
			_ = os.RemoveAll(tmpDir)
			continue
		}

		absPath := inputPath

		samplePath, totalEntries, sampledEntries, err := maybeSampleInput(tmpDir, input.label, data, limit)
		if err != nil {
			recordError(&firstErr, fmt.Errorf("sampling: %w", err))
			_ = os.RemoveAll(tmpDir)
			break
		}
		if samplePath != "" {
			absPath = samplePath
			emit(out, fmt.Sprintf("active: meta: linkfinderevo sampling %d of %d entries from %s", sampledEntries, totalEntries, input.label))
		}
		if sampledEntries == 0 {
			emit(out, fmt.Sprintf("active: meta: linkfinderevo skipped %s (no entries within time budget)", input.label))
			_ = os.RemoveAll(tmpDir)
			continue
		}

		totalBudget -= sampledEntries
		if totalBudget < 0 {
			totalBudget = 0
		}

		rawPath := filepath.Join(tmpDir, "findings.raw")
		htmlPath := filepath.Join(tmpDir, "findings.html")
		jsonPath := filepath.Join(tmpDir, "findings.json")

		args := buildArgs(absPath, target, rawPath, htmlPath, jsonPath, input.label)

		// Drenaje de salida CLI para evitar bloqueo.
		intermediate := make(chan string)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range intermediate {
			}
		}()

		runErr := runCmd(ctx, tmpDir, bin, args, intermediate)
		close(intermediate)
		wg.Wait()

		if err := accumulateResults(jsonPath, agg); err != nil {
			recordError(&firstErr, fmt.Errorf("accumulate results: %w", err))
		}
		if err := accumulateGFFindings(filepath.Join(tmpDir, "gf.json"), gfAgg); err != nil {
			recordError(&firstErr, fmt.Errorf("accumulate gf: %w", err))
		}

		// Persistir resultados siempre que existan archivos, incluso si GoLinkfinderEVO falló.
		// Esto evita perder resultados parciales cuando falla en una URL específica.
		shouldPersist := true
		if shouldPersist {
			if err := persistArtifacts(findingsDir, input.label, rawPath, htmlPath, jsonPath); err != nil {
				recordError(&firstErr, fmt.Errorf("persist artifacts: %w", err))
			}
			if err := persistGFArtifacts(findingsDir, input.label, tmpDir); err != nil {
				recordError(&firstErr, fmt.Errorf("persist gf: %w", err))
			}
		}

		if runErr != nil {
			recordError(&firstErr, runErr)
			// No hacer break: continuar procesando otros tipos de input (html, js, crawl)
			// para no perder todos los resultados por un fallo en un tipo específico.
			emit(out, fmt.Sprintf("active: meta: linkfinderevo error on %s (continuing with other inputs): %v", input.label, runErr))
		}

		_ = os.RemoveAll(tmpDir)
		if totalBudget == 0 {
			emit(out, "active: meta: linkfinderevo stopped (time budget consumed)")
			break
		}
	}

	if err := writeOutputs(outdir, agg, gfAgg, out); err != nil {
		recordError(&firstErr, fmt.Errorf("write outputs: %w", err))
	}

	return firstErr
}
