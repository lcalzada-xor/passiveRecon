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

	"passive-rec/internal/platform/logx"
)

type pipelineMetrics struct {
	mu     sync.Mutex
	steps  map[string]*stepMetric
	order  []string
	groups map[string]*groupMetric
}

type stepMetric struct {
	Name       string
	Group      string
	Start      time.Time
	End        time.Time
	Duration   time.Duration
	Queue      time.Duration
	Status     string
	Skipped    bool
	SkipReason string
	Timeout    time.Duration
	Inputs     int64
	Outputs    int64
	MetaLines  int64
	Errors     map[string]int64

	queueStart time.Time
}

type groupMetric struct {
	Name        string
	Concurrency int
	Start       time.Time
	End         time.Time
}

func newPipelineMetrics() *pipelineMetrics {
	return &pipelineMetrics{
		steps:  make(map[string]*stepMetric),
		order:  make([]string, 0),
		groups: make(map[string]*groupMetric),
	}
}

func (m *pipelineMetrics) ensure(name, group string) *stepMetric {
	if m.steps == nil {
		m.steps = make(map[string]*stepMetric)
	}
	metric, ok := m.steps[name]
	if !ok {
		metric = &stepMetric{Name: name, Group: group, Errors: make(map[string]int64)}
		m.steps[name] = metric
		m.order = append(m.order, name)
	}
	if metric.Errors == nil {
		metric.Errors = make(map[string]int64)
	}
	if group != "" && metric.Group == "" {
		metric.Group = group
	}
	return metric
}

func (m *pipelineMetrics) Wrap(name, group string, timeout int, fn func() error) func() error {
	if m == nil {
		return fn
	}
	return func() error {
		start := time.Now()
		m.mu.Lock()
		metric := m.ensure(name, group)
		metric.Start = start
		metric.Skipped = false
		metric.SkipReason = ""
		if timeout > 0 {
			metric.Timeout = time.Duration(timeout) * time.Second
		}
		if !metric.queueStart.IsZero() && metric.Queue == 0 {
			if start.After(metric.queueStart) {
				metric.Queue = start.Sub(metric.queueStart)
			}
			metric.queueStart = time.Time{}
		}
		m.mu.Unlock()

		err := fn()

		end := time.Now()
		status := classifyStepError(err)

		m.mu.Lock()
		metric.End = end
		metric.Duration = end.Sub(start)
		metric.Status = status
		if status != "" {
			metric.Errors[status]++
		}
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

	metric := m.ensure(name, "")
	metric.Skipped = true
	metric.Status = "omitido"
	metric.SkipReason = strings.TrimSpace(reason)
	metric.Start = time.Time{}
	metric.End = time.Time{}
	metric.Duration = 0
	metric.Queue = 0
}

func (m *pipelineMetrics) RecordInputs(name, group string, count int64) {
	if m == nil || count < 0 {
		return
	}
	m.mu.Lock()
	metric := m.ensure(name, group)
	metric.Inputs += count
	m.mu.Unlock()
}

func (m *pipelineMetrics) RecordOutput(name, group, line string) {
	if m == nil {
		return
	}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return
	}
	lower := strings.ToLower(trimmed)
	isMeta := strings.HasPrefix(lower, "meta:")

	m.mu.Lock()
	metric := m.ensure(name, group)
	if isMeta {
		metric.MetaLines++
	} else {
		metric.Outputs++
	}
	m.mu.Unlock()
}

func (m *pipelineMetrics) RecordOutputCount(name, group string, count int64) {
	if m == nil || count <= 0 {
		return
	}
	m.mu.Lock()
	metric := m.ensure(name, group)
	metric.Outputs += count
	m.mu.Unlock()
}

func (m *pipelineMetrics) RecordEnqueue(name, group string) {
	if m == nil {
		return
	}
	now := time.Now()
	m.mu.Lock()
	metric := m.ensure(name, group)
	metric.queueStart = now
	m.mu.Unlock()
}

func (m *pipelineMetrics) RecordGroupStart(name string, concurrency int) {
	if m == nil || name == "" {
		return
	}
	now := time.Now()
	m.mu.Lock()
	grp := m.ensureGroup(name)
	if grp.Start.IsZero() {
		grp.Start = now
	}
	grp.Concurrency = concurrency
	m.mu.Unlock()
}

func (m *pipelineMetrics) RecordGroupEnd(name string) {
	if m == nil || name == "" {
		return
	}
	now := time.Now()
	m.mu.Lock()
	grp := m.ensureGroup(name)
	grp.End = now
	m.mu.Unlock()
}

func (m *pipelineMetrics) ensureGroup(name string) *groupMetric {
	if m.groups == nil {
		m.groups = make(map[string]*groupMetric)
	}
	grp, ok := m.groups[name]
	if !ok {
		grp = &groupMetric{Name: name}
		m.groups[name] = grp
	}
	return grp
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
			if copy.Errors != nil {
				copy.Errors = cloneErrorMap(metric.Errors)
			}
			out = append(out, copy)
		}
	}
	return out
}

func (m *pipelineMetrics) Groups() []groupMetric {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.groups) == 0 {
		return nil
	}

	out := make([]groupMetric, 0, len(m.groups))
	for _, grp := range m.groups {
		copy := *grp
		out = append(out, copy)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Start == out[j].Start {
			return out[i].Name < out[j].Name
		}
		return out[i].Start.Before(out[j].Start)
	})
	return out
}

func cloneErrorMap(in map[string]int64) map[string]int64 {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]int64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func logPipelineMetrics(metrics *pipelineMetrics, runHash string, pipelineDuration time.Duration) {
	if metrics == nil {
		return
	}

	summaries := metrics.Summaries()
	if len(summaries) == 0 {
		return
	}

	durations := make([]time.Duration, 0, len(summaries))
	var maxDuration time.Duration
	var totalDuration time.Duration
	var criticalPath time.Duration
	maxConcurrency := 1
	if groups := metrics.Groups(); len(groups) > 0 {
		for _, grp := range groups {
			if grp.Concurrency > maxConcurrency {
				maxConcurrency = grp.Concurrency
			}
		}
	}
	if maxConcurrency <= 0 {
		maxConcurrency = 1
	}
	for _, metric := range summaries {
		if metric.Skipped {
			reason := metric.SkipReason
			if reason == "" {
				reason = "sin motivo reportado"
			}
			logx.Info("pipeline_step_skipped", logx.Fields{
				"step":        metric.Name,
				"tool":        metric.Name,
				"group":       metric.Group,
				"runHash":     runHash,
				"skip_reason": reason,
			})
			continue
		}

		start := metric.Start.Format(time.RFC3339)
		end := metric.End.Format(time.RFC3339)
		duration := metric.Duration
		durations = append(durations, duration)
		totalDuration += duration
		if duration > maxDuration {
			maxDuration = duration
		}
		candidate := metric.Duration + metric.Queue
		if candidate > criticalPath {
			criticalPath = candidate
		}
		fields := logx.Fields{
			"step":        metric.Name,
			"tool":        metric.Name,
			"group":       metric.Group,
			"status":      metric.Status,
			"runHash":     runHash,
			"start":       start,
			"end":         end,
			"duration_ms": duration.Milliseconds(),
			"queue_ms":    metric.Queue.Milliseconds(),
			"inputs":      metric.Inputs,
			"outputs":     metric.Outputs,
			"meta_lines":  metric.MetaLines,
			"timeout_sec": secondsWithMillis(metric.Timeout),
		}
		if metric.Duration > 0 && metric.Outputs > 0 {
			fields["rps"] = round3(float64(metric.Outputs) / metric.Duration.Seconds())
		}
		if len(metric.Errors) > 0 {
			fields["errors"] = metric.Errors
		}
		logx.Info("pipeline_step", fields)
	}

	if len(durations) == 0 {
		return
	}

	p95Duration := percentileDuration(durations, 95)

	summaryFields := logx.Fields{
		"steps":                len(durations),
		"p95_ms":               p95Duration.Milliseconds(),
		"max_ms":               maxDuration.Milliseconds(),
		"sequential_ms":        totalDuration.Milliseconds(),
		"pipeline_duration_ms": pipelineDuration.Milliseconds(),
		"runHash":              runHash,
	}
	if criticalPath > 0 {
		summaryFields["critical_path_ms"] = criticalPath.Milliseconds()
	}
	if pipelineDuration > 0 && totalDuration > 0 {
		speedup := totalDuration.Seconds() / pipelineDuration.Seconds()
		summaryFields["parallel_efficiency"] = round3(speedup / float64(maxConcurrency))
		summaryFields["max_concurrency"] = maxConcurrency
	}
	logx.Info("pipeline_summary", summaryFields)
}

func writePipelineMetricsReport(outDir string, metrics *pipelineMetrics, pipelineDuration time.Duration) error {
	if metrics == nil {
		return nil
	}

	summaries := metrics.Summaries()

	type stepEntry struct {
		Name            string           `json:"name"`
		Group           string           `json:"group,omitempty"`
		Status          string           `json:"status"`
		DurationSeconds float64          `json:"duration_seconds,omitempty"`
		QueueSeconds    float64          `json:"queue_seconds,omitempty"`
		Start           string           `json:"start,omitempty"`
		End             string           `json:"end,omitempty"`
		Inputs          int64            `json:"inputs,omitempty"`
		Outputs         int64            `json:"outputs,omitempty"`
		MetaLines       int64            `json:"meta_lines,omitempty"`
		RPS             float64          `json:"rps,omitempty"`
		Errors          map[string]int64 `json:"errors,omitempty"`
		Skipped         bool             `json:"skipped"`
		SkipReason      string           `json:"skip_reason,omitempty"`
		TimeoutSeconds  float64          `json:"timeout_seconds,omitempty"`
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
		TotalSequential     float64 `json:"total_sequential_seconds,omitempty"`
		CriticalPathSeconds float64 `json:"critical_path_seconds,omitempty"`
		ParallelEfficiency  float64 `json:"parallel_efficiency,omitempty"`
		Start               string  `json:"start,omitempty"`
		End                 string  `json:"end,omitempty"`
		LongestStep         string  `json:"longest_step,omitempty"`
		LongestStepDuration float64 `json:"longest_step_duration_seconds,omitempty"`
	}

	type groupEntry struct {
		Name                string  `json:"name"`
		Concurrency         int     `json:"concurrency"`
		DurationSeconds     float64 `json:"duration_seconds"`
		SequentialSeconds   float64 `json:"sequential_seconds"`
		CriticalPathSeconds float64 `json:"critical_path_seconds"`
		ParallelEfficiency  float64 `json:"parallel_efficiency"`
		Start               string  `json:"start,omitempty"`
		End                 string  `json:"end,omitempty"`
	}

	type report struct {
		GeneratedAt time.Time         `json:"generated_at"`
		Pipeline    pipelineEntry     `json:"pipeline"`
		Steps       []stepEntry       `json:"steps"`
		Groups      []groupEntry      `json:"groups,omitempty"`
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
	var pipelineCritical time.Duration
	bottleneckCandidates := make([]bottleneckEntry, 0, len(summaries))

	groupSnapshots := metrics.Groups()
	groupInfo := make(map[string]groupMetric, len(groupSnapshots))
	for _, grp := range groupSnapshots {
		if grp.Concurrency <= 0 {
			grp.Concurrency = 1
		}
		groupInfo[grp.Name] = grp
	}

	type aggregatedGroup struct {
		name        string
		concurrency int
		sequential  time.Duration
		critical    time.Duration
		start       time.Time
		end         time.Time
	}
	groupsAgg := make(map[string]*aggregatedGroup)
	maxConcurrency := 1

	for _, metric := range summaries {
		entry := stepEntry{
			Name:       metric.Name,
			Group:      metric.Group,
			Status:     metric.Status,
			Skipped:    metric.Skipped,
			SkipReason: metric.SkipReason,
			Inputs:     metric.Inputs,
			Outputs:    metric.Outputs,
			MetaLines:  metric.MetaLines,
			Errors:     metric.Errors,
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
		entry.QueueSeconds = secondsWithMillis(metric.Queue)
		if metric.Duration > 0 {
			entry.DurationSeconds = secondsWithMillis(metric.Duration)
			if metric.Outputs > 0 {
				entry.RPS = round3(float64(metric.Outputs) / metric.Duration.Seconds())
			}
		}

		if !metric.Skipped {
			completed++
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
				stepCritical := metric.Duration + metric.Queue
				if stepCritical > pipelineCritical {
					pipelineCritical = stepCritical
				}
				groupKey := metric.Group
				if groupKey == "" {
					groupKey = metric.Name
				}
				agg := groupsAgg[groupKey]
				if agg == nil {
					agg = &aggregatedGroup{name: groupKey, concurrency: 1}
					if info, ok := groupInfo[metric.Group]; ok {
						if info.Concurrency > 0 {
							agg.concurrency = info.Concurrency
						}
						if !info.Start.IsZero() {
							agg.start = info.Start
						}
						if !info.End.IsZero() {
							agg.end = info.End
						}
					}
					if agg.concurrency > maxConcurrency {
						maxConcurrency = agg.concurrency
					}
					groupsAgg[groupKey] = agg
				}
				queueStart := metric.Start
				if metric.Queue > 0 {
					queueStart = metric.Start.Add(-metric.Queue)
				}
				if !queueStart.IsZero() {
					if agg.start.IsZero() || queueStart.Before(agg.start) {
						agg.start = queueStart
					}
				}
				if !metric.End.IsZero() {
					if agg.end.IsZero() || metric.End.After(agg.end) {
						agg.end = metric.End
					}
				}
				agg.sequential += metric.Duration
				if stepCritical > agg.critical {
					agg.critical = stepCritical
				}
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

	var groupEntries []groupEntry
	if len(groupsAgg) > 0 {
		type sortableGroup struct {
			entry groupEntry
			start time.Time
		}
		sortable := make([]sortableGroup, 0, len(groupsAgg))
		for _, agg := range groupsAgg {
			duration := agg.end.Sub(agg.start)
			if duration < 0 {
				duration = 0
			}
			if duration == 0 {
				duration = agg.sequential
			}
			efficiency := 0.0
			if duration > 0 && agg.concurrency > 0 && agg.sequential > 0 {
				speedup := agg.sequential.Seconds() / duration.Seconds()
				efficiency = speedup / float64(agg.concurrency)
			}
			entry := groupEntry{
				Name:                agg.name,
				Concurrency:         agg.concurrency,
				DurationSeconds:     secondsWithMillis(duration),
				SequentialSeconds:   secondsWithMillis(agg.sequential),
				CriticalPathSeconds: secondsWithMillis(agg.critical),
				ParallelEfficiency:  round3(efficiency),
			}
			if !agg.start.IsZero() {
				entry.Start = agg.start.Format(time.RFC3339)
			}
			if !agg.end.IsZero() {
				entry.End = agg.end.Format(time.RFC3339)
			}
			sortable = append(sortable, sortableGroup{entry: entry, start: agg.start})
		}
		sort.Slice(sortable, func(i, j int) bool {
			si := sortable[i].start
			sj := sortable[j].start
			switch {
			case si.IsZero() && sj.IsZero():
				return sortable[i].entry.Name < sortable[j].entry.Name
			case si.IsZero():
				return false
			case sj.IsZero():
				return true
			case si.Equal(sj):
				return sortable[i].entry.Name < sortable[j].entry.Name
			default:
				return si.Before(sj)
			}
		})
		groupEntries = make([]groupEntry, 0, len(sortable))
		for _, item := range sortable {
			groupEntries = append(groupEntries, item.entry)
		}
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
		TotalSequential:     secondsWithMillis(totalDuration),
		CriticalPathSeconds: secondsWithMillis(pipelineCritical),
		LongestStep:         longestName,
		LongestStepDuration: maxDuration,
	}

	if pipelineDuration > 0 && totalDuration > 0 {
		speedup := totalDuration.Seconds() / pipelineDuration.Seconds()
		if maxConcurrency <= 0 {
			maxConcurrency = 1
		}
		pipelineInfo.ParallelEfficiency = round3(speedup / float64(maxConcurrency))
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
		Groups:      groupEntries,
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

func round3(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return math.Round(v*1000) / 1000
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
