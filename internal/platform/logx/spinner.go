package logx

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Spinner struct {
	mu      sync.Mutex
	prefix  string
	active  bool
	manager *spinnerManager
}

type spinnerState struct {
	prefix     string
	frameIndex int
}

type spinnerManager struct {
	mu        sync.Mutex
	renderMu  sync.Mutex
	spinners  map[*Spinner]*spinnerState
	order     []*Spinner
	writer    io.Writer
	isTTY     bool
	refresh   time.Duration
	ticker    *time.Ticker
	lastLines int
}

var globalSpinnerManager = newSpinnerManager()

func newSpinnerManager() *spinnerManager {
	mgr := &spinnerManager{
		spinners: make(map[*Spinner]*spinnerState),
		refresh:  100 * time.Millisecond,
	}
	mgr.SetWriter(getOutputWriter(), getOutputConfig())
	return mgr
}

func NewSpinner(prefix string) *Spinner {
	return &Spinner{
		prefix:  prefix,
		manager: globalSpinnerManager,
	}
}

func (s *Spinner) Start() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.active {
		s.mu.Unlock()
		return
	}
	s.active = true
	prefix := s.prefix
	s.mu.Unlock()

	s.manager.Add(s, prefix)
}

func (s *Spinner) Stop(finalMsg string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return
	}
	s.active = false
	s.mu.Unlock()

	s.manager.Stop(s, finalMsg)
}

func (s *Spinner) StopSuccess(msg string) {
	formatter := GetFormatter()
	status := formatter.colored(colorGreen, "[✔]")
	s.Stop(fmt.Sprintf("%s %s", status, msg))
}

func (s *Spinner) StopError(msg string) {
	formatter := GetFormatter()
	status := formatter.colored(colorRed, "[✗]")
	s.Stop(fmt.Sprintf("%s %s", status, msg))
}

func (s *Spinner) UpdatePrefix(prefix string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.prefix = prefix
	active := s.active
	s.mu.Unlock()

	if active {
		s.manager.Update(s, prefix)
	}
}

func (m *spinnerManager) SetWriter(w io.Writer, cfg OutputConfig) {
	if m == nil {
		return
	}
	if w == nil {
		w = os.Stderr
	}
	m.mu.Lock()
	m.writer = w
	m.isTTY = cfg.IsTTY
	if !m.isTTY {
		m.lastLines = 0
		if m.ticker != nil {
			m.ticker.Stop()
			m.ticker = nil
		}
	}
	m.mu.Unlock()
}

func (m *spinnerManager) Add(s *Spinner, prefix string) {
	if m == nil || s == nil {
		return
	}
	m.mu.Lock()
	if m.spinners == nil {
		m.spinners = make(map[*Spinner]*spinnerState)
	}
	if _, exists := m.spinners[s]; exists {
		m.mu.Unlock()
		return
	}
	m.spinners[s] = &spinnerState{prefix: prefix}
	m.order = append(m.order, s)
	writer := m.writer
	isTTY := m.isTTY
	m.mu.Unlock()

	if writer == nil {
		writer = os.Stderr
	}

	if !isTTY {
		formatter := GetFormatter()
		frame := formatter.colored(colorBlue, SpinnerFrames[0])
		fmt.Fprintf(writer, "%s %s\n", frame, prefix)
		return
	}

	m.render(false)
	m.ensureTicker()
}

func (m *spinnerManager) Stop(s *Spinner, finalMsg string) {
	if m == nil || s == nil {
		return
	}
	writer, isTTY, lines, prevLines, found := m.prepareStopSnapshot(s)
	if writer == nil {
		writer = os.Stderr
	}

	if !isTTY {
		if finalMsg != "" {
			fmt.Fprintf(writer, "%s\n", finalMsg)
		}
		return
	}

	needRender := found && (prevLines > 0 || len(lines) > 0)
	if needRender {
		m.renderMu.Lock()
		m.renderLines(writer, lines, prevLines)
		if finalMsg != "" {
			fmt.Fprintf(writer, "%s\n", finalMsg)
		}
		m.renderMu.Unlock()
		return
	}

	if finalMsg != "" {
		m.renderMu.Lock()
		fmt.Fprintf(writer, "%s\n", finalMsg)
		m.renderMu.Unlock()
	}
}

func (m *spinnerManager) Update(s *Spinner, prefix string) {
	if m == nil || s == nil {
		return
	}
	m.mu.Lock()
	state, ok := m.spinners[s]
	if ok {
		state.prefix = prefix
	}
	isTTY := m.isTTY
	m.mu.Unlock()

	if ok && isTTY {
		m.render(false)
	}
}

func (m *spinnerManager) ensureTicker() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ticker != nil || !m.isTTY || len(m.order) == 0 {
		return
	}
	ticker := time.NewTicker(m.refresh)
	m.ticker = ticker
	go m.loop(ticker)
}

func (m *spinnerManager) loop(t *time.Ticker) {
	for range t.C {
		writer, isTTY, lines, prevLines, hasLines := m.snapshotForRender(true)
		if !isTTY {
			m.stopTicker(t)
			return
		}
		if writer == nil {
			writer = os.Stderr
		}
		if len(lines) == 0 && prevLines == 0 {
			m.stopTicker(t)
			return
		}
		m.renderMu.Lock()
		m.renderLines(writer, lines, prevLines)
		m.renderMu.Unlock()
		if !hasLines {
			m.stopTicker(t)
			return
		}
	}
}

func (m *spinnerManager) stopTicker(t *time.Ticker) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t == nil {
		if m.ticker != nil {
			m.ticker.Stop()
			m.ticker = nil
		}
		return
	}
	if m.ticker == t {
		m.ticker.Stop()
		m.ticker = nil
	}
}

func (m *spinnerManager) render(advance bool) {
	writer, isTTY, lines, prevLines, hasLines := m.snapshotForRender(advance)
	if !isTTY {
		return
	}
	if writer == nil {
		writer = os.Stderr
	}
	if prevLines == 0 && len(lines) == 0 {
		return
	}
	m.renderMu.Lock()
	m.renderLines(writer, lines, prevLines)
	m.renderMu.Unlock()
	if !hasLines {
		m.stopTicker(nil)
	}
}

func (m *spinnerManager) snapshotForRender(advance bool) (io.Writer, bool, []string, int, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	writer := m.writer
	if writer == nil {
		writer = os.Stderr
		m.writer = writer
	}
	isTTY := m.isTTY

	if !isTTY {
		m.lastLines = 0
		return writer, false, nil, 0, false
	}

	formatter := GetFormatter()
	lines := make([]string, 0, len(m.order))
	for _, sp := range m.order {
		st := m.spinners[sp]
		if st == nil {
			continue
		}
		frame := SpinnerFrames[st.frameIndex%len(SpinnerFrames)]
		if advance {
			st.frameIndex = (st.frameIndex + 1) % len(SpinnerFrames)
		}
		colored := formatter.colored(colorBlue, frame)
		lines = append(lines, fmt.Sprintf("%s %s", colored, st.prefix))
	}

	prevLines := m.lastLines
	if len(lines) > 0 {
		m.lastLines = len(lines)
	} else {
		m.lastLines = 0
	}

	return writer, true, lines, prevLines, len(lines) > 0
}

func (m *spinnerManager) prepareStopSnapshot(s *Spinner) (io.Writer, bool, []string, int, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	writer := m.writer
	if writer == nil {
		writer = os.Stderr
		m.writer = writer
	}
	isTTY := m.isTTY

	if m.spinners == nil {
		return writer, isTTY, nil, m.lastLines, false
	}

	if _, ok := m.spinners[s]; !ok {
		return writer, isTTY, nil, m.lastLines, false
	}

	delete(m.spinners, s)
	for i, item := range m.order {
		if item == s {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}

	if len(m.order) == 0 && m.ticker != nil {
		m.ticker.Stop()
		m.ticker = nil
	}

	if !isTTY {
		m.lastLines = 0
		return writer, false, nil, 0, true
	}

	formatter := GetFormatter()
	lines := make([]string, 0, len(m.order))
	for _, sp := range m.order {
		st := m.spinners[sp]
		if st == nil {
			continue
		}
		frame := SpinnerFrames[st.frameIndex%len(SpinnerFrames)]
		colored := formatter.colored(colorBlue, frame)
		lines = append(lines, fmt.Sprintf("%s %s", colored, st.prefix))
	}

	prevLines := m.lastLines
	if len(lines) > 0 {
		m.lastLines = len(lines)
	} else {
		m.lastLines = 0
	}

	return writer, true, lines, prevLines, true
}

func (m *spinnerManager) renderLines(writer io.Writer, lines []string, prevLines int) {
	if writer == nil {
		return
	}
	if prevLines == 0 && len(lines) == 0 {
		return
	}

	buf := &bytes.Buffer{}
	if prevLines > 0 {
		fmt.Fprintf(buf, "\033[%dF", prevLines)
	}

	maxLines := prevLines
	if len(lines) > maxLines {
		maxLines = len(lines)
	}

	for i := 0; i < maxLines; i++ {
		buf.WriteString("\r\033[K")
		if i < len(lines) {
			buf.WriteString(lines[i])
		}
		if i < maxLines-1 {
			buf.WriteByte('\n')
		}
	}

	switch {
	case len(lines) > 0:
		buf.WriteString("\033[E")
	case prevLines > 0:
		fmt.Fprintf(buf, "\033[%dE", prevLines)
	}

	_, _ = writer.Write(buf.Bytes())
}
