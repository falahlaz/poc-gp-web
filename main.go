// Command gp-web is a minimal web UI that drives the GlobalProtect Linux CLI
// through a SAML login whose callback is pasted back manually.
package main

import (
	_ "embed"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

//go:embed web/index.html
var indexHTML []byte

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func loadConfig() Config {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("home dir: %v", err)
	}
	dir := getenv("GP_WEB_DIR", filepath.Join(home, ".gp-web"))
	var hosts []string
	for _, h := range strings.Split(getenv("GP_REACH_HOSTS", ""), ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	portal := getenv("GP_PORTAL", "")
	if portal == "" {
		log.Fatal("GP_PORTAL is required")
	}
	return Config{
		Bin:        getenv("GP_BIN", "/usr/bin/globalprotect"),
		Portal:     portal,
		Dir:        dir,
		Browser:    getenv("BROWSER", filepath.Join(dir, "capture-url.sh")),
		ReachHosts: hosts,
	}
}

func main() {
	// Handling SIGINT (instead of inheriting an ignored disposition, e.g. when
	// started as a background job) makes the spawned connect process start with
	// default SIGINT behaviour, which stop-first mode relies on.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		log.Printf("received %v, exiting", <-sigs)
		os.Exit(0)
	}()

	cfg := loadConfig()
	if os.Geteuid() == 0 {
		log.Printf("WARNING: running as root; GlobalProtect expects the session owner user")
	}
	if os.Getenv("XDG_RUNTIME_DIR") == "" {
		log.Printf("WARNING: XDG_RUNTIME_DIR is not set; the CLI may not reach the per-user agent")
	}
	addr := net.JoinHostPort("127.0.0.1", getenv("GP_PORT", "8080"))
	srv := &http.Server{
		Addr:              addr,
		Handler:           newHandler(NewManager(cfg), indexHTML),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("gp-web listening on http://%s (portal=%s bin=%s dir=%s reach=%v)",
		addr, cfg.Portal, cfg.Bin, cfg.Dir, cfg.ReachHosts)
	log.Fatal(srv.ListenAndServe())
}
