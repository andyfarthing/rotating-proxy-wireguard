package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// InterfaceInfo is returned by discovery at startup.
type InterfaceInfo struct {
	Interface string
	Address   string // as assigned on the host (e.g. "10.0.0.2/32")
}

// PeerStats holds per-peer telemetry scraped from `wg show all dump`.
type PeerStats struct {
	Interface       string
	PeerPublicKey   string
	Endpoint        string
	AllowedIPs      string
	LatestHandshake time.Time
	TxBytes         int64
	RxBytes         int64
}

// InterfaceProcStats holds byte counters from /proc/net/dev.
type InterfaceProcStats struct {
	Interface string
	RxBytes   int64
	TxBytes   int64
}

// WGStats is the full stats snapshot served by the web UI.
type WGStats struct {
	Peers     []PeerStats
	ProcStats map[string]InterfaceProcStats
	CollectedAt time.Time
}

// StatsCollector periodically refreshes WireGuard stats.
type StatsCollector struct {
	mu      sync.RWMutex
	current WGStats
}

// NewStatsCollector starts a background refresh loop.
func NewStatsCollector(interval time.Duration) *StatsCollector {
	sc := &StatsCollector{}
	sc.refresh()
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			sc.refresh()
		}
	}()
	return sc
}

func (sc *StatsCollector) refresh() {
	peers, err := parseWGDump()
	if err != nil {
		slog.Warn("wg stats refresh failed", "err", err)
	}
	proc, err := parseProcNetDev()
	if err != nil {
		slog.Warn("proc/net/dev refresh failed", "err", err)
	}
	sc.mu.Lock()
	sc.current = WGStats{
		Peers:       peers,
		ProcStats:   proc,
		CollectedAt: time.Now(),
	}
	sc.mu.Unlock()
}

// Get returns the latest stats snapshot.
func (sc *StatsCollector) Get() WGStats {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.current
}

// parseWGDump runs `wg show all dump` and parses its output.
// Output format (tab-separated):
//   interface line: <iface> <private-key> <public-key> <listen-port> <fwmark>
//   peer line:      <iface> <peer-pubkey>  <psk>        <endpoint>   <allowed-ips>  <latest-handshake>  <tx-bytes>  <rx-bytes>  <persistent-ka>
func parseWGDump() ([]PeerStats, error) {
	out, err := exec.Command("wg", "show", "all", "dump").Output()
	if err != nil {
		return nil, fmt.Errorf("wg show all dump: %w", err)
	}

	var peers []PeerStats
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		// Interface header line has 5 fields; peer line has 9.
		if len(parts) < 9 {
			continue
		}
		iface := parts[0]
		peerKey := parts[1]
		endpoint := parts[3]
		allowedIPs := parts[4]
		handshakeEpoch, _ := strconv.ParseInt(parts[5], 10, 64)
		txBytes, _ := strconv.ParseInt(parts[6], 10, 64)
		rxBytes, _ := strconv.ParseInt(parts[7], 10, 64)

		var latestHandshake time.Time
		if handshakeEpoch > 0 {
			latestHandshake = time.Unix(handshakeEpoch, 0)
		}
		if endpoint == "(none)" {
			endpoint = ""
		}

		peers = append(peers, PeerStats{
			Interface:       iface,
			PeerPublicKey:   peerKey,
			Endpoint:        endpoint,
			AllowedIPs:      allowedIPs,
			LatestHandshake: latestHandshake,
			TxBytes:         txBytes,
			RxBytes:         rxBytes,
		})
	}
	return peers, scanner.Err()
}

// parseProcNetDev reads /proc/net/dev to get per-interface byte counters.
// Line format (after two header lines):
//   <iface>: <rx_bytes> <rx_pkts> ... <tx_bytes> <tx_pkts> ...
func parseProcNetDev() (map[string]InterfaceProcStats, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := make(map[string]InterfaceProcStats)
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum <= 2 {
			continue // skip header lines
		}
		line := strings.TrimSpace(scanner.Text())
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:colonIdx])
		fields := strings.Fields(line[colonIdx+1:])
		if len(fields) < 9 {
			continue
		}
		rxBytes, _ := strconv.ParseInt(fields[0], 10, 64)
		txBytes, _ := strconv.ParseInt(fields[8], 10, 64)
		result[iface] = InterfaceProcStats{
			Interface: iface,
			RxBytes:   rxBytes,
			TxBytes:   txBytes,
		}
	}
	return result, scanner.Err()
}
