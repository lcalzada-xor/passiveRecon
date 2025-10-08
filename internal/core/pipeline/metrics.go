package pipeline

import (
	"sort"
	"time"
)

type handlerStats struct {
	total time.Duration
	count uint64
}

// HandlerMetric resume el desempeño de un handler del pipeline.
type HandlerMetric struct {
	Name    string
	Count   uint64
	Total   time.Duration
	Average time.Duration
}

type metricHandler struct {
	name    string
	handler Handler
}

func (m *metricHandler) Name() string   { return m.handler.Name() }
func (m *metricHandler) Prefix() string { return m.handler.Prefix() }
func (m *metricHandler) Handle(ctx *Context, line string, isActive bool, tool string) bool {
	if ctx == nil || ctx.S == nil {
		return m.handler.Handle(ctx, line, isActive, tool)
	}
	start := time.Now()
	handled := m.handler.Handle(ctx, line, isActive, tool)
	ctx.S.recordHandlerMetric(m.name, time.Since(start))
	return handled
}

// WithMetrics envuelve un handler y registra métricas de ejecución para el mismo.
func WithMetrics(name string, handler Handler) Handler {
	if handler == nil {
		return nil
	}
	return &metricHandler{name: name, handler: handler}
}

func (s *Sink) recordHandlerMetric(name string, elapsed time.Duration) {
	if s == nil || name == "" {
		return
	}
	s.metricsMu.Lock()
	stat := s.handlerMetrics[name]
	if stat == nil {
		stat = &handlerStats{}
		s.handlerMetrics[name] = stat
	}
	stat.total += elapsed
	stat.count++
	s.metricsMu.Unlock()
}

// HandlerMetrics devuelve una instantánea ordenada de las métricas recolectadas
// para cada handler. El orden es descendente por promedio y estable alfabéticamente
// en caso de empate para facilitar la inspección.
func (s *Sink) HandlerMetrics() []HandlerMetric {
	if s == nil {
		return nil
	}
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	metrics := make([]HandlerMetric, 0, len(s.handlerMetrics))
	for name, stat := range s.handlerMetrics {
		if stat == nil || stat.count == 0 {
			continue
		}
		avg := time.Duration(int64(stat.total) / int64(stat.count))
		metrics = append(metrics, HandlerMetric{
			Name:    name,
			Count:   stat.count,
			Total:   stat.total,
			Average: avg,
		})
	}
	sort.Slice(metrics, func(i, j int) bool {
		if metrics[i].Average == metrics[j].Average {
			return metrics[i].Name < metrics[j].Name
		}
		return metrics[i].Average > metrics[j].Average
	})
	return metrics
}
