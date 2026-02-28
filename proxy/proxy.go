//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
)

// proxyHandler implements HTTP and HTTPS (CONNECT) proxying with exclusive
// WireGuard tunnel leasing. Each accepted connection is bound to one
// WireGuard interface for its entire lifetime.
type proxyHandler struct {
	pool    *LeasePool
	timeout time.Duration // per-connection dial timeout
}

func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleCONNECT(w, r)
	} else {
		h.handleHTTP(w, r)
	}
}

// handleCONNECT handles HTTPS tunneling via the HTTP CONNECT method.
// Acquires a tunnel, dials the target, sends 200, then copies bidirectionally.
func (h *proxyHandler) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	slot, err := h.pool.Acquire(r.Context(), r.RemoteAddr)
	if err != nil {
		slog.Warn("tunnel acquire failed", "client", r.RemoteAddr, "err", err)
		http.Error(w, "503 no tunnel available: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer h.pool.Release(slot)

	slog.Info("CONNECT", "client", r.RemoteAddr, "target", r.Host, "iface", slot.Interface)

	dialCtx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	upstream, err := dialViaTunnel(dialCtx, slot.Interface, "tcp", r.Host)
	if err != nil {
		slog.Warn("dial failed", "iface", slot.Interface, "target", r.Host, "err", err)
		http.Error(w, "502 upstream dial failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	// Signal to the client that the tunnel is established.
	w.WriteHeader(http.StatusOK)

	// Hijack the connection for raw bidirectional copy.
	hj, ok := w.(http.Hijacker)
	if !ok {
		slog.Error("responsewriter does not support hijack")
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		slog.Error("hijack failed", "err", err)
		return
	}
	defer clientConn.Close()

	copyBidirectional(clientConn, upstream)
}

// handleHTTP forwards a plain HTTP request. The outbound connection is bound to
// the leased WireGuard interface.
func (h *proxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	slot, err := h.pool.Acquire(r.Context(), r.RemoteAddr)
	if err != nil {
		slog.Warn("tunnel acquire failed", "client", r.RemoteAddr, "err", err)
		http.Error(w, "503 no tunnel available: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer h.pool.Release(slot)

	slog.Info("HTTP", "client", r.RemoteAddr, "target", r.URL.Host, "iface", slot.Interface)

	// Build a fresh request without hop-by-hop headers.
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	removeHopByHopHeaders(outReq.Header)

	dialCtx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	// Apply the dial timeout to the outgoing request context.
	outReq = outReq.WithContext(dialCtx)

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialViaTunnel(ctx, slot.Interface, network, addr)
		},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          1,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		slog.Warn("roundtrip failed", "iface", slot.Interface, "err", err)
		http.Error(w, "502 upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	// Expose which tunnel served this request — used by integration tests and
	// useful for debugging. Does not affect proxy behaviour.
	w.Header().Set("X-Tunnel-Interface", slot.Interface)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// dialViaTunnel creates a TCP connection bound to a specific WireGuard interface
// using SO_BINDTODEVICE so the kernel forces all packets through that interface.
//
// DNS resolution for the hostname is also performed through a dialer bound to
// the same interface to prevent DNS leakage.
func dialViaTunnel(ctx context.Context, iface, network, addr string) (net.Conn, error) {
	// Custom resolver that also binds to the WireGuard interface.
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
			// Dial the system DNS server using a UDP socket bound to the interface.
			d := &net.Dialer{}
			d.Control = bindToDevice(iface)
			return d.DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}

	dialer := &net.Dialer{
		Timeout:  30 * time.Second,
		Resolver: resolver,
		Control:  bindToDevice(iface),
	}
	return dialer.DialContext(ctx, network, addr)
}

// bindToDevice returns a Control function that sets SO_BINDTODEVICE on the socket
// before it is connected. This forces the kernel to route all traffic from the
// socket through the named interface, bypassing the normal routing table.
// Requires CAP_NET_ADMIN (or CAP_NET_RAW).
func bindToDevice(iface string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var innerErr error
		err := c.Control(func(fd uintptr) {
			innerErr = syscall.BindToDevice(int(fd), iface)
		})
		if err != nil {
			return fmt.Errorf("RawConn.Control: %w", err)
		}
		return innerErr
	}
}

// copyBidirectional copies data in both directions between two connections.
//
// When either direction finishes (the client disconnects, the upstream closes,
// or an error occurs), BOTH connections are closed immediately. This unblocks
// the goroutine copying in the other direction, which would otherwise block
// forever waiting for data on a keep-alive connection. Without this, the
// function never returns and the tunnel lease is never released.
func copyBidirectional(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(b, a)
		done <- struct{}{}
	}()
	// Wait for the first direction to finish, then close both connections so
	// the other goroutine unblocks and the second done is received promptly.
	<-done
	a.Close()
	b.Close()
	<-done
}

// hopByHopHeaders lists headers that must not be forwarded by a proxy.
var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Transfer-Encoding",
	"Upgrade", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailers",
}

func removeHopByHopHeaders(h http.Header) {
	for _, hdr := range hopByHopHeaders {
		h.Del(hdr)
	}
}

// readManifest reads the JSON manifest written by entrypoint.sh.
func readManifest(path string) ([]InterfaceInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open manifest %q: %w", path, err)
	}
	defer f.Close()

	var ifaces []InterfaceInfo
	if err := json.NewDecoder(f).Decode(&ifaces); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if len(ifaces) == 0 {
		return nil, fmt.Errorf("manifest contains no interfaces — check that *.conf files exist in the config directory")
	}
	return ifaces, nil
}
