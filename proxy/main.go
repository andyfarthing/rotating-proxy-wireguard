package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	defaultManifestPath  = "/run/wg-proxy/manifest.json"
	defaultProxyPort     = "8080"
	defaultWebUIPort     = "8088"
	defaultLeaseTimeout  = "30"
	defaultDialTimeout   = "30"
	defaultStatsInterval = "5"
)

func main() {
	setupLogging()

	manifestPath  := env("MANIFEST_PATH",    defaultManifestPath)
	proxyPort     := env("PROXY_PORT",        defaultProxyPort)
	webuiPort     := env("WEB_UI_PORT",       defaultWebUIPort)
	leaseTimeout  := mustDuration("LEASE_TIMEOUT",  defaultLeaseTimeout)
	dialTimeout   := mustDuration("DIAL_TIMEOUT",   defaultDialTimeout)
	statsInterval := mustDuration("STATS_INTERVAL", defaultStatsInterval)

	// Read the manifest written by entrypoint.sh
	slog.Info("reading interface manifest", "path", manifestPath)
	ifaces, err := readManifest(manifestPath)
	if err != nil {
		slog.Error("failed to read manifest", "err", err)
		os.Exit(1)
	}
	slog.Info("discovered WireGuard interfaces", "count", len(ifaces))
	for _, iface := range ifaces {
		slog.Info("  interface", "name", iface.Interface, "address", iface.Address)
	}

	pool := NewLeasePool(ifaces, leaseTimeout)
	sc   := NewStatsCollector(statsInterval)

	// --- Proxy server ---
	// The proxyHandler is used directly as the Handler — NOT via http.ServeMux.
	// Go 1.22+ ServeMux rewrites/redirects requests whose URL doesn't look like
	// a normal path, which breaks HTTP CONNECT requests (e.g. CONNECT host:443)
	// by responding with 301 instead of forwarding them to the handler.
	proxySrv := &http.Server{
		Addr:    ":" + proxyPort,
		Handler: &proxyHandler{pool: pool, timeout: dialTimeout},
	}
	go func() {
		slog.Info("proxy listening", "port", proxyPort)
		if err := proxySrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("proxy server error", "err", err)
			os.Exit(1)
		}
	}()

	// --- Web UI server (optional) ---
	var webuiSrv *http.Server
	if webuiPort != "0" {
		uiMux := http.NewServeMux()
		ui := &webUIHandler{pool: pool, stats: sc}
		ui.Register(uiMux)
		webuiSrv = &http.Server{
			Addr:    ":" + webuiPort,
			Handler: uiMux,
		}
		go func() {
			slog.Info("web UI listening", "port", webuiPort)
			if err := webuiSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("web UI server error", "err", err)
			}
		}()
	} else {
		slog.Info("web UI disabled (WEB_UI_PORT=0)")
	}

	// --- Graceful shutdown ---
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop

	slog.Info("shutting down…")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	proxySrv.Shutdown(ctx)
	if webuiSrv != nil {
		webuiSrv.Shutdown(ctx)
	}
	slog.Info("shutdown complete")
}

// setupLogging configures slog based on the LOG_LEVEL environment variable.
func setupLogging() {
	lvl := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})))
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mustDuration(key, fallback string) time.Duration {
	raw := env(key, fallback)
	d, err := time.ParseDuration(raw)
	if err != nil {
		// Allow bare numbers (e.g. "30") to be treated as seconds.
		d, err = time.ParseDuration(raw + "s")
	}
	if err != nil {
		panic(fmt.Sprintf("invalid duration for %s=%q: %v", key, raw, err))
	}
	return d
}


