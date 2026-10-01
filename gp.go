package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type State string

const (
	StateIdle            State = "IDLE"
	StateConnecting      State = "CONNECTING"
	StateWaitingCallback State = "WAITING_CALLBACK"
	StateSubmitting      State = "SUBMITTING"
	StateConnected       State = "CONNECTED"
	StateFailed          State = "FAILED"
)

const (
	statusTimeout     = 5 * time.Second
	launchURITimeout  = 30 * time.Second
	disconnectTimeout = 15 * time.Second
	stopGrace         = 3 * time.Second
	reachTimeout      = 3 * time.Second
	maxURILen         = 8 * 1024
	logTailLines      = 200
	callbackPrefix    = "globalprotectcallback:"
)

var (
	errBusy     = errors.New("another operation is in progress")
	errBadState = errors.New("operation not allowed in current state")
	errInvalid  = errors.New("invalid request")
)

type Config struct {
	Bin        string
	Portal     string
	Dir        string // ~/.gp-web
	Browser    string
	ReachHosts []string
}

func (c Config) loginURLPath() string   { return filepath.Join(c.Dir, "login-url") }
func (c Config) connectLogPath() string { return filepath.Join(c.Dir, "connect.log") }

type CmdResult struct {
	ExitCode int    `json:"exitCode"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

type Manager struct {
	cfg Config

	// opMu serialises connect, callback and disconnect. status/logs never take it.
	opMu sync.Mutex

	mu          sync.RWMutex
	state       State
	connectCmd  *exec.Cmd
	connectDone chan struct{}
	lastOutput  []string
}

func NewManager(cfg Config) *Manager {
	return &Manager{cfg: cfg, state: StateIdle}
}

func (m *Manager) State() State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *Manager) setState(s State) {
	m.mu.Lock()
	m.state = s
	m.mu.Unlock()
}

func (m *Manager) env() []string {
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "BROWSER=") {
			env = append(env, kv)
		}
	}
	return append(env, "BROWSER="+m.cfg.Browser)
}

// run executes the GlobalProtect CLI with separate args (never through a shell).
// hide, if non-empty, is masked in the output in addition to the regex redaction.
func (m *Manager) run(timeout time.Duration, hide string, args ...string) CmdResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, m.cfg.Bin, args...)
	cmd.Env = m.env()
	cmd.WaitDelay = 2 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			code = -1
			fmt.Fprintf(&stderr, "\n%v", err)
		}
		if ctx.Err() == context.DeadlineExceeded {
			code = -1
			fmt.Fprintf(&stderr, "\ntimeout after %s", timeout)
		}
	}
	clean := func(s string) string {
		if hide != "" {
			s = strings.ReplaceAll(s, hide, "<callback-uri>")
		}
		return redact(strings.TrimSpace(s))
	}
	return CmdResult{ExitCode: code, Stdout: clean(stdout.String()), Stderr: clean(stderr.String())}
}

func (m *Manager) record(desc string, r CmdResult, extra ...string) {
	lines := []string{fmt.Sprintf("[%s] $ globalprotect %s", time.Now().Format(time.TimeOnly), desc)}
	lines = append(lines, extra...)
	lines = append(lines, fmt.Sprintf("exit=%d", r.ExitCode))
	if r.Stdout != "" {
		lines = append(lines, "stdout:", r.Stdout)
	}
	if r.Stderr != "" {
		lines = append(lines, "stderr:", r.Stderr)
	}
	m.mu.Lock()
	m.lastOutput = lines
	m.mu.Unlock()
}

func (m *Manager) connectAlive() bool {
	m.mu.RLock()
	done := m.connectDone
	m.mu.RUnlock()
	if done == nil {
		return false
	}
	select {
	case <-done:
		return false
	default:
		return true
	}
}

// Connect spawns `globalprotect connect` in its own process group.
func (m *Manager) Connect() (State, error) {
	if !m.opMu.TryLock() {
		return m.State(), errBusy
	}
	defer m.opMu.Unlock()

	if st := m.State(); st != StateIdle && st != StateFailed {
		return st, fmt.Errorf("%w: state is %s", errBadState, st)
	}
	// A previous attempt (e.g. mode keep that failed) may have left connect running.
	m.stopConnect(true)

	if err := os.MkdirAll(m.cfg.Dir, 0o700); err != nil {
		return m.State(), err
	}
	if err := os.Remove(m.cfg.loginURLPath()); err != nil && !os.IsNotExist(err) {
		return m.State(), err
	}
	f, err := os.OpenFile(m.cfg.connectLogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return m.State(), err
	}
	fmt.Fprintf(f, "=== %s globalprotect connect --portal %s\n", time.Now().Format(time.DateTime), m.cfg.Portal)
	rw := newRedactWriter(f)

	cmd := exec.Command(m.cfg.Bin, "connect", "--portal", m.cfg.Portal)
	cmd.Env = m.env()
	cmd.Stdout = rw
	cmd.Stderr = rw
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(f, "=== start failed: %v\n", err)
		f.Close()
		m.setState(StateFailed)
		return StateFailed, err
	}

	done := make(chan struct{})
	m.mu.Lock()
	m.connectCmd = cmd
	m.connectDone = done
	m.state = StateConnecting
	m.mu.Unlock()

	go func() {
		err := cmd.Wait()
		rw.Flush()
		desc := "exit 0"
		if err != nil {
			desc = err.Error()
		}
		fmt.Fprintf(f, "=== %s connect (pid %d) exited: %s\n", time.Now().Format(time.DateTime), cmd.Process.Pid, desc)
		f.Close()
		m.mu.Lock()
		// Exited before a login URL was ever captured: nothing left to wait for.
		if m.connectCmd == cmd && m.state == StateConnecting {
			m.state = StateFailed
		}
		m.mu.Unlock()
		close(done)
	}()
	return StateConnecting, nil
}

// stopConnect sends SIGINT to the stored connect process group and waits up to
// stopGrace. With force, it follows up with SIGKILL. Reports whether it exited.
// Only the PID this server spawned is ever signalled.
func (m *Manager) stopConnect(force bool) bool {
	m.mu.RLock()
	cmd, done := m.connectCmd, m.connectDone
	m.mu.RUnlock()
	if cmd == nil {
		return true
	}
	select {
	case <-done:
		return true
	default:
	}
	pgid := cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGINT)
	select {
	case <-done:
		return true
	case <-time.After(stopGrace):
	}
	if !force {
		return false
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	select {
	case <-done:
		return true
	case <-time.After(2 * time.Second):
		return false
	}
}

// LoginURL returns the captured SAML login URL, or "" if not yet available.
func (m *Manager) LoginURL() (State, string) {
	b, err := os.ReadFile(m.cfg.loginURLPath())
	url := ""
	if err == nil {
		url, _, _ = strings.Cut(strings.TrimSpace(string(b)), "\n")
		url = strings.TrimSpace(url)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if url != "" && m.state == StateConnecting {
		m.state = StateWaitingCallback
	}
	return m.state, url
}

func validateCallback(uri, mode string) error {
	switch {
	case len(uri) > maxURILen:
		return fmt.Errorf("%w: uri longer than %d bytes", errInvalid, maxURILen)
	case !strings.HasPrefix(uri, callbackPrefix):
		return fmt.Errorf("%w: uri must start with %s", errInvalid, callbackPrefix)
	case strings.ContainsAny(uri, "\r\n\x00"):
		return fmt.Errorf("%w: uri must not contain newlines", errInvalid)
	case mode != "keep" && mode != "stop-first":
		return fmt.Errorf("%w: mode must be keep or stop-first", errInvalid)
	}
	return nil
}

type CallbackResult struct {
	CmdResult
	State          State `json:"state"`
	ConnectStopped *bool `json:"connectStopped,omitempty"`
}

// Callback hands the pasted callback URI to `globalprotect launch-uri`.
func (m *Manager) Callback(uri, mode string) (CallbackResult, error) {
	if err := validateCallback(uri, mode); err != nil {
		return CallbackResult{State: m.State()}, err
	}
	if !m.opMu.TryLock() {
		return CallbackResult{State: m.State()}, errBusy
	}
	defer m.opMu.Unlock()

	m.setState(StateSubmitting)
	var extra []string
	var stopped *bool
	if mode == "stop-first" {
		ok := m.stopConnect(false)
		stopped = &ok
		extra = append(extra, fmt.Sprintf("mode=stop-first, connect exited before launch-uri: %v", ok))
	} else {
		extra = append(extra, fmt.Sprintf("mode=keep, connect alive: %v", m.connectAlive()))
	}

	res := m.run(launchURITimeout, uri, "launch-uri", uri)
	st := StateFailed
	if res.ExitCode == 0 {
		st = StateConnected
	}
	m.setState(st)
	m.record("launch-uri <callback-uri>", res, extra...)
	return CallbackResult{CmdResult: res, State: st, ConnectStopped: stopped}, nil
}

type ReachResult struct {
	Host  string `json:"host"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type StatusResult struct {
	State        State         `json:"state"`
	GPStatus     string        `json:"gpStatus"`
	Iface        []string      `json:"iface"`
	ConnectAlive bool          `json:"connectAlive"`
	Reach        []ReachResult `json:"reach"`
}

func (m *Manager) Status() StatusResult {
	var wg sync.WaitGroup
	reach := make([]ReachResult, len(m.cfg.ReachHosts))
	for i, h := range m.cfg.ReachHosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reach[i] = ReachResult{Host: h}
			c, err := net.DialTimeout("tcp", h, reachTimeout)
			if err != nil {
				reach[i].Error = err.Error()
				return
			}
			c.Close()
			reach[i].OK = true
		}()
	}

	res := m.run(statusTimeout, "", "show", "--status")
	gp := res.Stdout
	if res.ExitCode != 0 {
		gp = strings.TrimSpace(fmt.Sprintf("exit=%d %s %s", res.ExitCode, res.Stdout, res.Stderr))
	}

	ifaces := []string{}
	if all, err := net.Interfaces(); err == nil {
		for _, ifc := range all {
			if strings.HasPrefix(ifc.Name, "gpd") || strings.HasPrefix(ifc.Name, "tun") {
				name := ifc.Name
				if ifc.Flags&net.FlagUp == 0 {
					name += " (down)"
				}
				ifaces = append(ifaces, name)
			}
		}
	}
	wg.Wait()
	return StatusResult{
		State:        m.State(),
		GPStatus:     gp,
		Iface:        ifaces,
		ConnectAlive: m.connectAlive(),
		Reach:        reach,
	}
}

func (m *Manager) Disconnect() (CmdResult, error) {
	if !m.opMu.TryLock() {
		return CmdResult{}, errBusy
	}
	defer m.opMu.Unlock()

	res := m.run(disconnectTimeout, "", "disconnect")
	stopped := m.stopConnect(true)
	m.setState(StateIdle)
	m.record("disconnect", res, fmt.Sprintf("connect process stopped: %v", stopped))
	return res, nil
}

// Logs returns the tail of connect.log followed by the last command output.
func (m *Manager) Logs() []string {
	lines := []string{}
	if b, err := os.ReadFile(m.cfg.connectLogPath()); err == nil {
		all := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
		if len(all) > logTailLines {
			all = all[len(all)-logTailLines:]
		}
		for _, l := range all {
			lines = append(lines, redact(l))
		}
	}
	m.mu.RLock()
	last := m.lastOutput
	m.mu.RUnlock()
	if len(last) > 0 {
		lines = append(lines, "", "--- last command ---")
		lines = append(lines, last...)
	}
	return lines
}
