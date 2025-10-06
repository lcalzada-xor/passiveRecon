package app

import (
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
