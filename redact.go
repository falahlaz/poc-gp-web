package main

import (
	"bytes"
	"io"
	"regexp"
	"sync"
)

var secretRe = regexp.MustCompile(`(token|prelogin-cookie|portal-userauthcookie)=[^&\s'"]+`)

// redact hides token-like query parameters before text is logged or returned.
func redact(s string) string {
	return secretRe.ReplaceAllString(s, "$1=<redacted>")
}

// redactWriter buffers until newline so a secret split across writes is still
// redacted before it reaches the underlying writer.
type redactWriter struct {
	mu  sync.Mutex
	w   io.Writer
	buf []byte
}

func newRedactWriter(w io.Writer) *redactWriter { return &redactWriter{w: w} }

func (r *redactWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	for {
		i := bytes.IndexByte(r.buf, '\n')
		if i < 0 {
			break
		}
		if _, err := io.WriteString(r.w, redact(string(r.buf[:i+1]))); err != nil {
			return len(p), err
		}
		r.buf = r.buf[i+1:]
	}
	return len(p), nil
}

// Flush writes any trailing partial line.
func (r *redactWriter) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) == 0 {
		return nil
	}
	_, err := io.WriteString(r.w, redact(string(r.buf))+"\n")
	r.buf = nil
	return err
}
