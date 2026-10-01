package main

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write response: %v", err)
	}
}

func writeErr(w http.ResponseWriter, err error, st State) {
	code := http.StatusInternalServerError
	switch {
	case errors.Is(err, errBusy), errors.Is(err, errBadState):
		code = http.StatusConflict
	case errors.Is(err, errInvalid):
		code = http.StatusBadRequest
	}
	writeJSON(w, code, map[string]any{"error": redact(err.Error()), "state": st})
}

func newHandler(m *Manager, index []byte) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(index)
	})

	mux.HandleFunc("POST /api/connect", func(w http.ResponseWriter, r *http.Request) {
		st, err := m.Connect()
		if err != nil {
			writeErr(w, err, st)
			return
		}
		log.Printf("connect started")
		writeJSON(w, http.StatusAccepted, map[string]any{"state": st})
	})

	mux.HandleFunc("GET /api/login-url", func(w http.ResponseWriter, r *http.Request) {
		st, url := m.LoginURL()
		var u any
		if url != "" {
			u = url
		}
		writeJSON(w, http.StatusOK, map[string]any{"state": st, "url": u})
	})

	mux.HandleFunc("POST /api/callback", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			URI  string `json:"uri"`
			Mode string `json:"mode"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 2*maxURILen)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, errInvalid, m.State())
			return
		}
		req.URI = strings.TrimSpace(req.URI)
		res, err := m.Callback(req.URI, req.Mode)
		if err != nil {
			writeErr(w, err, res.State)
			return
		}
		log.Printf("callback mode=%s exit=%d state=%s", req.Mode, res.ExitCode, res.State)
		writeJSON(w, http.StatusOK, res)
	})

	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, m.Status())
	})

	mux.HandleFunc("POST /api/disconnect", func(w http.ResponseWriter, r *http.Request) {
		res, err := m.Disconnect()
		if err != nil {
			writeErr(w, err, m.State())
			return
		}
		log.Printf("disconnect exit=%d", res.ExitCode)
		writeJSON(w, http.StatusOK, res)
	})

	mux.HandleFunc("GET /api/logs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"lines": m.Logs()})
	})

	return guard(mux)
}

// guard rejects requests whose Host is not loopback (DNS rebinding) and POSTs
// without a JSON content type (cross-site form posts cannot set it without CORS).
func guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		next.ServeHTTP(w, r)
	})
}
