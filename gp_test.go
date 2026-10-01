package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	bin, err := filepath.Abs("testdata/fake-globalprotect.sh")
	if err != nil {
		t.Fatal(err)
	}
	capture := filepath.Join(dir, "capture-url.sh")
	script := "#!/bin/sh\nprintf '%s\\n' \"$1\" > '" + filepath.Join(dir, "login-url") + "'\n"
	if err := os.WriteFile(capture, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	m := NewManager(Config{Bin: bin, Portal: "portal.example", Dir: dir, Browser: capture, ReachHosts: nil})
	t.Cleanup(func() { m.stopConnect(true) })
	return m
}

func waitLoginURL(t *testing.T, m *Manager) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, url := m.LoginURL(); url != "" {
			if st != StateWaitingCallback {
				t.Fatalf("state = %s, want WAITING_CALLBACK", st)
			}
			return url
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("login URL not captured")
	return ""
}

func assertNoSecrets(t *testing.T, m *Manager, extra ...string) {
	t.Helper()
	b, _ := os.ReadFile(m.cfg.connectLogPath())
	all := append([]string{string(b), strings.Join(m.Logs(), "\n")}, extra...)
	for _, s := range all {
		for _, secret := range []string{"supersecret", "secretcookie", "tok3n"} {
			if strings.Contains(s, secret) {
				t.Errorf("secret %q leaked in:\n%s", secret, s)
			}
		}
	}
}

func TestValidateCallback(t *testing.T) {
	ok := "globalprotectcallback:abc"
	bad := []struct{ uri, mode string }{
		{"https://x", "keep"},
		{ok + "\nrm -rf", "keep"},
		{ok, "other"},
		{"globalprotectcallback:" + strings.Repeat("a", maxURILen), "keep"},
	}
	for _, c := range bad {
		if err := validateCallback(c.uri, c.mode); !errors.Is(err, errInvalid) {
			t.Errorf("validateCallback(%.30q, %q) = %v, want errInvalid", c.uri, c.mode, err)
		}
	}
	for _, mode := range []string{"keep", "stop-first"} {
		if err := validateCallback(ok, mode); err != nil {
			t.Errorf("valid uri rejected: %v", err)
		}
	}
}

func TestFlowKeep(t *testing.T) {
	m := newTestManager(t)
	if st, err := m.Connect(); err != nil || st != StateConnecting {
		t.Fatalf("Connect = %s, %v", st, err)
	}
	if _, err := m.Connect(); !errors.Is(err, errBadState) {
		t.Fatalf("second Connect err = %v, want errBadState", err)
	}
	if url := waitLoginURL(t, m); !strings.HasPrefix(url, "https://login.example.com/") {
		t.Fatalf("url = %q", url)
	}
	res, err := m.Callback("globalprotectcallback:cas-as=1&token=tok3n", "keep")
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || res.State != StateConnected || res.ConnectStopped != nil {
		t.Fatalf("callback = %+v", res)
	}
	if !strings.Contains(res.Stdout, "<callback-uri>") {
		t.Errorf("stdout should mask uri: %q", res.Stdout)
	}
	if !m.connectAlive() {
		t.Error("keep mode should leave connect running")
	}
	assertNoSecrets(t, m, res.Stdout, res.Stderr)

	if _, err := m.Disconnect(); err != nil {
		t.Fatal(err)
	}
	if m.connectAlive() || m.State() != StateIdle {
		t.Fatalf("after disconnect alive=%v state=%s", m.connectAlive(), m.State())
	}
}

func TestFlowStopFirstAndExpired(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Connect(); err != nil {
		t.Fatal(err)
	}
	waitLoginURL(t, m)
	res, err := m.Callback("globalprotectcallback:expired&token=tok3n", "stop-first")
	if err != nil {
		t.Fatal(err)
	}
	if res.ConnectStopped == nil || !*res.ConnectStopped || m.connectAlive() {
		t.Fatalf("stop-first should stop connect: %+v alive=%v", res, m.connectAlive())
	}
	if res.ExitCode != 1 || res.State != StateFailed {
		t.Fatalf("expired callback = %+v", res)
	}
	if !strings.Contains(res.Stderr, "token=<redacted>") {
		t.Errorf("stderr not redacted: %q", res.Stderr)
	}
	b, _ := os.ReadFile(m.cfg.connectLogPath())
	if !strings.Contains(string(b), "connect interrupted") {
		t.Errorf("connect should have received SIGINT, log:\n%s", b)
	}
	assertNoSecrets(t, m, res.Stdout, res.Stderr)

	// FAILED allows a fresh connect.
	if st, err := m.Connect(); err != nil || st != StateConnecting {
		t.Fatalf("reconnect = %s, %v", st, err)
	}
}

func TestBusy(t *testing.T) {
	m := newTestManager(t)
	m.opMu.Lock()
	defer m.opMu.Unlock()
	if _, err := m.Connect(); !errors.Is(err, errBusy) {
		t.Errorf("Connect err = %v", err)
	}
	if _, err := m.Callback("globalprotectcallback:x", "keep"); !errors.Is(err, errBusy) {
		t.Errorf("Callback err = %v", err)
	}
	if _, err := m.Disconnect(); !errors.Is(err, errBusy) {
		t.Errorf("Disconnect err = %v", err)
	}
	// status and logs must not block on the op mutex.
	done := make(chan struct{})
	go func() { m.Status(); m.Logs(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("status/logs blocked")
	}
}

func TestStatus(t *testing.T) {
	m := newTestManager(t)
	ln := httptest.NewServer(http.NotFoundHandler())
	defer ln.Close()
	m.cfg.ReachHosts = []string{strings.TrimPrefix(ln.URL, "http://"), "127.0.0.1:1"}
	t.Setenv("FAKE_STATUS", "Connected")
	s := m.Status()
	if s.State != StateIdle || !strings.Contains(s.GPStatus, "Connected") || s.ConnectAlive {
		t.Fatalf("status = %+v", s)
	}
	if !s.Reach[0].OK || s.Reach[1].OK {
		t.Fatalf("reach = %+v", s.Reach)
	}
}

func TestHTTPGuardAndValidation(t *testing.T) {
	h := newHandler(newTestManager(t), []byte("<html>"))
	do := func(method, host, ctype, body string) int {
		r := httptest.NewRequest(method, "http://"+host+"/api/callback", strings.NewReader(body))
		if ctype != "" {
			r.Header.Set("Content-Type", ctype)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if c := do("POST", "evil.example:8080", "application/json", `{}`); c != http.StatusForbidden {
		t.Errorf("foreign host: %d", c)
	}
	if c := do("POST", "localhost:8080", "text/plain", `{}`); c != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: %d", c)
	}
	if c := do("POST", "localhost:8080", "application/json", `{"uri":"https://x","mode":"keep"}`); c != http.StatusBadRequest {
		t.Errorf("bad uri: %d", c)
	}
	if c := do("GET", "127.0.0.1:8080", "", ""); c != http.StatusMethodNotAllowed {
		t.Errorf("GET callback: %d", c)
	}
}
