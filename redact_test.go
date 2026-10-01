package main

import (
	"bytes"
	"testing"
)

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"globalprotectcallback:x?token=abc123&user=me": "globalprotectcallback:x?token=<redacted>&user=me",
		"prelogin-cookie=zzz portal-userauthcookie=q'": "prelogin-cookie=<redacted> portal-userauthcookie=<redacted>'",
		`"token=a"`:  `"token=<redacted>"`,
		"no secrets": "no secrets",
	}
	for in, want := range cases {
		if got := redact(in); got != want {
			t.Errorf("redact(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactWriterSplitWrites(t *testing.T) {
	var out bytes.Buffer
	w := newRedactWriter(&out)
	w.Write([]byte("a tok"))
	w.Write([]byte("en=sec"))
	w.Write([]byte("ret b\npartial token=x"))
	w.Flush()
	want := "a token=<redacted> b\npartial token=<redacted>\n"
	if out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
}
