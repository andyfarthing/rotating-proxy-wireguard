package main

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// TunnelStatus represents the current state of a WireGuard tunnel slot.
type TunnelStatus int

const (
	TunnelFree TunnelStatus = iota
	TunnelBusy
)

// TunnelSlot holds runtime state for a single WireGuard interface.
// All mutable fields are protected by LeasePool.mu via the sync.Cond.
type TunnelSlot struct {
	Index     int
	Interface string // e.g. "wg0"
	Address   string // the interface's own IP (e.g. "10.0.0.2/32")

	// Protected by the owning LeasePool's mutex.
	status     TunnelStatus
	clientAddr string
	leaseStart time.Time
}

// LeaseInfo is a safe point-in-time snapshot of a slot (copied under the lock).
type LeaseInfo struct {
	Interface  string
	Address    string
	Status     TunnelStatus
	ClientAddr string
	LeaseStart time.Time
}

// LeasePool manages exclusive assignment of WireGuard tunnels to clients.
//
// Tunnels are assigned in round-robin order. When all tunnels are busy,
// Acquire blocks (up to the configured timeout) until one is released.
// All slot state is protected by a single mutex exposed via a sync.Cond,
// which is the correct pattern for condition-variable waiting in Go.
type LeasePool struct {
	mu      sync.Mutex
	cond    *sync.Cond
	slots   []*TunnelSlot
	next    int           // round-robin cursor (protected by mu)
	timeout time.Duration // maximum wait per Acquire call
}

// NewLeasePool creates a pool from the provided list of interfaces.
func NewLeasePool(ifaces []InterfaceInfo, timeout time.Duration) *LeasePool {
	p := &LeasePool{timeout: timeout}
	p.cond = sync.NewCond(&p.mu)
	for i, iface := range ifaces {
		p.slots = append(p.slots, &TunnelSlot{
			Index:     i,
			Interface: iface.Interface,
			Address:   iface.Address,
		})
	}
	return p
}

// Acquire claims the next free tunnel in round-robin order.
//
// It blocks (under the condition variable) until a tunnel is free, the
// configured timeout elapses, or ctx is cancelled.
// A time.AfterFunc timer sends a Broadcast on timeout so that the Wait
// call is woken up immediately rather than relying on polling.
func (p *LeasePool) Acquire(ctx context.Context, clientAddr string) (*TunnelSlot, error) {
	deadline := time.Now().Add(p.timeout)

	// Send a Broadcast when the deadline is reached so blocked callers wake up.
	timer := time.AfterFunc(p.timeout, func() { p.cond.Broadcast() })
	defer timer.Stop()

	// Also broadcast when the context is cancelled.
	ctxWatchStop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			p.cond.Broadcast()
		case <-ctxWatchStop:
		}
	}()
	defer close(ctxWatchStop)

	p.mu.Lock()
	defer p.mu.Unlock()

	for {
		// Check termination conditions first.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("no tunnel available after %s", p.timeout)
		}

		// Scan from the round-robin cursor once around the pool.
		n := len(p.slots)
		for i := 0; i < n; i++ {
			idx := (p.next + i) % n
			slot := p.slots[idx]
			if slot.status == TunnelFree {
				slot.status = TunnelBusy
				slot.clientAddr = clientAddr
				slot.leaseStart = time.Now()
				p.next = (idx + 1) % n
				return slot, nil
			}
		}

		// No free slot -- Wait atomically releases p.mu and suspends the goroutine
		// until Broadcast/Signal is called (by Release, the timer, or ctx watcher).
		p.cond.Wait()
	}
}

// Release returns a previously acquired slot to the pool and wakes all waiters.
func (p *LeasePool) Release(slot *TunnelSlot) {
	p.mu.Lock()
	slot.status = TunnelFree
	slot.clientAddr = ""
	slot.leaseStart = time.Time{}
	p.mu.Unlock()
	p.cond.Broadcast()
}

// Snapshots returns a point-in-time view of all slots (safe to read without
// holding the lock by copying under it).
func (p *LeasePool) Snapshots() []LeaseInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]LeaseInfo, len(p.slots))
	for i, s := range p.slots {
		out[i] = LeaseInfo{
			Interface:  s.Interface,
			Address:    s.Address,
			Status:     s.status,
			ClientAddr: s.clientAddr,
			LeaseStart: s.leaseStart,
		}
	}
	return out
}
