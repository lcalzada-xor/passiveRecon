package app

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"passive-rec/internal/logx"
)

type pipelineMetrics struct {
	mu    sync.Mutex
	steps map[string]*stepMetric
	order []string
}

type stepMetric struct {
	Name       string
	Start      time.Time
	End        time.Time
	Duration   time.Duration
	Status     string
	Skipped    bool
	SkipReason string
	Timeout    time.Duration
}

func newPipelineMetrics() *pipelineMetrics {
	return &pipelineMetrics{
		steps: make(map[string]*stepMetric),
		order: make([]string, 0),
	}
}

func (m *pipelineMetrics) ensure(name string) *stepMetric {
	if m.steps == nil {
		m.steps = make(map[string]*stepMetric)
	}
	metric, ok := m.steps[name]
	if !ok {
		metric = &stepMetric{Name: name}
		m.steps[name] = metric
		m.order = append(m.order, name)
	}
	return metric
}

func (m *pipelineMetrics) Wrap(name string, timeout int, fn func() error) func() error {
	if m == nil {
		return fn
	}
	return func() error {
		start := time.Now()
		m.mu.Lock()
		metric := m.ensure(name)
		metric.Start = start
		metric.Skipped = false
		metric.SkipReason = ""
		if timeout > 0 {
			metric.Timeout = time.Duration(timeout) * time.Second
		}
		m.mu.Unlock()

		err := fn()

		end := time.Now()
		status := classifyStepError(err)

		m.mu.Lock()
		metric.End = end
		metric.Duration = end.Sub(start)
		metric.Status = status
		m.mu.Unlock()

		return err
	}
}

func (m *pipelineMetrics) RecordSkip(name, reason string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	metric := m.ensure(name)
	metric.Skipped = true
	metric.Status = "omitido"
	metric.SkipReason = strings.TrimSpace(reason)
	metric.Start = time.Time{}
	metric.End = time.Time{}
	metric.Duration = 0
}

func (m *pipelineMetrics) Summaries() []stepMetric {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]stepMetric, 0, len(m.order))
	for _, name := range m.order {
		if metric, ok := m.steps[name]; ok {
			copy := *metric
			out = append(out, copy)
		}
	}
	return out
}

func logPipelineMetrics(metrics *pipelineMetrics) {
	if metrics == nil {
		return
	}

	summaries := metrics.Summaries()
	if len(summaries) == 0 {
		return
	}

	durations := make([]time.Duration, 0, len(summaries))
	var maxDuration time.Duration
	for _, metric := range summaries {
		if metric.Skipped {
			reason := metric.SkipReason
			if reason == "" {
				reason = "sin motivo reportado"
			}
			logx.Infof("pipeline: %s omitido (%s)", metric.Name, reason)
			continue
		}

		start := metric.Start.Format(time.RFC3339)
		end := metric.End.Format(time.RFC3339)
		duration := metric.Duration
		durations = append(durations, duration)
		if duration > maxDuration {
			maxDuration = duration
		}
		logx.Infof("pipeline: %s status=%s dur=%s inicio=%s fin=%s", metric.Name, metric.Status, duration.Round(time.Millisecond), start, end)
	}

	if len(durations) == 0 {
		return
	}

	p95Duration := percentileDuration(durations, 95)

	logx.Infof("pipeline: resumen tiempos pasos=%d p95=%s max=%s", len(durations), p95Duration.Round(time.Millisecond), maxDuration.Round(time.Millisecond))
}

func writePipelineMetricsReport(outDir string, metrics *pipelineMetrics, pipelineDuration time.Duration) error {
	if metrics == nil {
		return nil
	}

	summaries := metrics.Summaries()

	type stepEntry struct {
		Name            string  `json:"name"`
		Status          string  `json:"status"`
		DurationSeconds float64 `json:"duration_seconds,omitempty"`
		Start           string  `json:"start,omitempty"`
		End             string  `json:"end,omitempty"`
		Skipped         bool    `json:"skipped"`
		SkipReason      string  `json:"skip_reason,omitempty"`
		TimeoutSeconds  float64 `json:"timeout_seconds,omitempty"`
	}

	type bottleneckEntry struct {
		Name            string  `json:"name"`
		DurationSeconds float64 `json:"duration_seconds"`
	}

	type pipelineEntry struct {
		DurationSeconds     float64 `json:"duration_seconds"`
		StepsTotal          int     `json:"steps_total"`
		StepsCompleted      int     `json:"steps_completed"`
		StepsSuccessful     int     `json:"steps_successful"`
		StepsSkipped        int     `json:"steps_skipped"`
		StepsFailed         int     `json:"steps_failed"`
		StepsTimeout        int     `json:"steps_timeout"`
		StepsMissing        int     `json:"steps_missing"`
		AverageDuration     float64 `json:"average_duration_seconds,omitempty"`
		P95Duration         float64 `json:"p95_duration_seconds,omitempty"`
		MaxDuration         float64 `json:"max_duration_seconds,omitempty"`
		Start               string  `json:"start,omitempty"`
		End                 string  `json:"end,omitempty"`
		LongestStep         string  `json:"longest_step,omitempty"`
		LongestStepDuration float64 `json:"longest_step_duration_seconds,omitempty"`
	}

	type report struct {
		GeneratedAt time.Time         `json:"generated_at"`
		Pipeline    pipelineEntry     `json:"pipeline"`
		Steps       []stepEntry       `json:"steps"`
		Bottlenecks []bottleneckEntry `json:"bottlenecks,omitempty"`
	}

	if len(summaries) == 0 {
		data := report{
			GeneratedAt: time.Now().UTC(),
			Pipeline: pipelineEntry{
				DurationSeconds: secondsWithMillis(pipelineDuration),
			},
			Steps: make([]stepEntry, 0),
		}
		return writeMetricsFile(outDir, data)
	}

	steps := make([]stepEntry, 0, len(summaries))
	durationSamples := make([]time.Duration, 0, len(summaries))
	completed := 0
	successful := 0
	skipped := 0
	failed := 0
	timeouts := 0
	missing := 0
	var totalDuration time.Duration
	var earliestStart time.Time
	var latestEnd time.Time
	var longestName string
	var longestDuration time.Duration
	bottleneckCandidates := make([]bottleneckEntry, 0, len(summaries))

	for _, metric := range summaries {
		entry := stepEntry{
			Name:       metric.Name,
			Status:     metric.Status,
			Skipped:    metric.Skipped,
			SkipReason: metric.SkipReason,
		}
		if !metric.Start.IsZero() {
			entry.Start = metric.Start.Format(time.RFC3339)
			if earliestStart.IsZero() || metric.Start.Before(earliestStart) {
				earliestStart = metric.Start
			}
		}
		if !metric.End.IsZero() {
			entry.End = metric.End.Format(time.RFC3339)
			if latestEnd.IsZero() || metric.End.After(latestEnd) {
				latestEnd = metric.End
			}
		}
		if metric.Timeout > 0 {
			entry.TimeoutSeconds = secondsWithMillis(metric.Timeout)
		}
		if !metric.Skipped {
			completed++
			entry.DurationSeconds = secondsWithMillis(metric.Duration)
			totalDuration += metric.Duration
			switch metric.Status {
			case "ok":
				successful++
			case "timeout":
				timeouts++
				failed++
			case "error":
				failed++
			case "faltante":
				missing++
			}
			if metric.Duration > 0 {
				durationSamples = append(durationSamples, metric.Duration)
				if metric.Duration > longestDuration {
					longestDuration = metric.Duration
					longestName = metric.Name
				}
				bottleneckCandidates = append(bottleneckCandidates, bottleneckEntry{
					Name:            metric.Name,
					DurationSeconds: secondsWithMillis(metric.Duration),
				})
			}
		} else {
			skipped++
		}
		steps = append(steps, entry)
	}

	sort.Slice(bottleneckCandidates, func(i, j int) bool {
		return bottleneckCandidates[i].DurationSeconds > bottleneckCandidates[j].DurationSeconds
	})
	const maxBottlenecks = 5
	if len(bottleneckCandidates) > maxBottlenecks {
		bottleneckCandidates = bottleneckCandidates[:maxBottlenecks]
	}

	avgDuration := 0.0
	if completed > 0 {
		avg := time.Duration(int64(totalDuration) / int64(completed))
		avgDuration = secondsWithMillis(avg)
	}

	p95 := 0.0
	maxDuration := 0.0
	if len(durationSamples) > 0 {
		p95Duration := percentileDuration(durationSamples, 95)
		p95 = secondsWithMillis(p95Duration)
		maxDuration = secondsWithMillis(longestDuration)
	}

	pipelineInfo := pipelineEntry{
		DurationSeconds:     secondsWithMillis(pipelineDuration),
		StepsTotal:          len(summaries),
		StepsCompleted:      completed,
		StepsSuccessful:     successful,
		StepsSkipped:        skipped,
		StepsFailed:         failed,
		StepsTimeout:        timeouts,
		StepsMissing:        missing,
		AverageDuration:     avgDuration,
		P95Duration:         p95,
		MaxDuration:         maxDuration,
		LongestStep:         longestName,
		LongestStepDuration: maxDuration,
	}

	if !earliestStart.IsZero() {
		pipelineInfo.Start = earliestStart.Format(time.RFC3339)
	}
	if !latestEnd.IsZero() {
		pipelineInfo.End = latestEnd.Format(time.RFC3339)
	}

	data := report{
		GeneratedAt: time.Now().UTC(),
		Pipeline:    pipelineInfo,
		Steps:       steps,
	}
	if len(bottleneckCandidates) > 0 {
		data.Bottlenecks = bottleneckCandidates
	}

	return writeMetricsFile(outDir, data)
}

func secondsWithMillis(d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return math.Round(d.Seconds()*1000) / 1000
}

func writeMetricsFile(outDir string, payload any) error {
	metricsPath := filepath.Join(outDir, "metrics")
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := metricsPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, metricsPath)
}

func percentileDuration(durations []time.Duration, percentile int) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	copyDurations := make([]time.Duration, len(durations))
	copy(copyDurations, durations)
	sort.Slice(copyDurations, func(i, j int) bool {
		return copyDurations[i] < copyDurations[j]
	})
	if percentile <= 0 {
		return copyDurations[0]
	}
	if percentile >= 100 {
		return copyDurations[len(copyDurations)-1]
	}
	rank := (percentile*len(copyDurations) + 100 - 1) / 100
	index := rank - 1
	if index < 0 {
		index = 0
	}
	if index >= len(copyDurations) {
		index = len(copyDurations) - 1
	}
	return copyDurations[index]
}
