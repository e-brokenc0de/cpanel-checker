package checker

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"time"

	"cpanel-optimized/parser"
)

// Result represents the outcome of a credential check.
type Result struct {
	Valid    bool
	Protocol string // "cPanel", "WHM", "FTP", "IMAP"
	Error    string // "", "Auth Failed", "IP Blocked", "Host Dead", etc.
}

// Checker defines the interface for protocol-specific credential validators.
// Implementations must be safe for concurrent use.
type Checker interface {
	Name() string
	Port() string
	Check(ctx context.Context, host, username, password string, buf *bytes.Buffer) Result
}

// DeadHostCache tracks hosts that have failed connection attempts.
// Once a host:port is marked dead, all subsequent checks skip the network call.
// Uses sync.Map for write-once-read-many access pattern under high concurrency.
type DeadHostCache struct {
	hosts sync.Map
}

// MarkDead records a host:port as unreachable.
func (d *DeadHostCache) MarkDead(hostPort string) {
	d.hosts.Store(hostPort, struct{}{})
}

// IsDead returns true if the host:port was previously marked unreachable.
func (d *DeadHostCache) IsDead(hostPort string) bool {
	_, ok := d.hosts.Load(hostPort)
	return ok
}

// Chain runs credential checks through an ordered list of protocol checkers.
// It short-circuits on success, definitive auth failure, or IP blocks.
type Chain struct {
	checkers  []Checker
	deadHosts *DeadHostCache
	retries   int
}

// NewChain creates a Chain with the given checkers and retry configuration.
func NewChain(checkers []Checker, retries int) *Chain {
	return &Chain{
		checkers:  checkers,
		deadHosts: &DeadHostCache{},
		retries:   retries,
	}
}

// Run executes the check chain for a single credential.
// buf is a per-worker scratch buffer for building request bodies (avoids allocations).
func (c *Chain) Run(ctx context.Context, cred parser.Credential, buf *bytes.Buffer) Result {
	for _, chk := range c.checkers {
		hostPort := cred.Host + ":" + chk.Port()

		if c.deadHosts.IsDead(hostPort) {
			continue
		}

		result := c.checkWithRetry(ctx, chk, cred, buf, hostPort)

		switch {
		case result.Valid:
			return result
		case result.Error == "IP Blocked":
			// Brute-force protection triggered — stop entirely
			return result
		case result.Error == "Auth Failed":
			// Credentials are definitively wrong — other protocols won't help
			return result
		case isTransient(result.Error):
			// Connection-level failure — mark dead and try next protocol
			c.deadHosts.MarkDead(hostPort)
			continue
		default:
			// Non-transient, non-auth error (e.g., unexpected HTTP status) — try next protocol
			continue
		}
	}

	return Result{Error: "All Checks Failed"}
}

func (c *Chain) checkWithRetry(ctx context.Context, chk Checker, cred parser.Credential, buf *bytes.Buffer, hostPort string) Result {
	var result Result
	for attempt := 0; attempt <= c.retries; attempt++ {
		result = chk.Check(ctx, cred.Host, cred.Username, cred.Password, buf)

		// Don't retry definitive answers
		if result.Valid || result.Error == "Auth Failed" || result.Error == "IP Blocked" {
			return result
		}

		// Only retry transient errors
		if !isTransient(result.Error) {
			return result
		}

		// Mark dead on first transient failure
		if attempt == 0 {
			c.deadHosts.MarkDead(hostPort)
		}

		if attempt < c.retries {
			select {
			case <-time.After(time.Duration(attempt+1) * 500 * time.Millisecond):
			case <-ctx.Done():
				return Result{Error: "Cancelled"}
			}
		}
	}
	return result
}

// isTransient returns true for errors caused by network/infrastructure issues
// (worth retrying) vs definitive application-level failures (not worth retrying).
func isTransient(errMsg string) bool {
	lower := strings.ToLower(errMsg)
	for _, keyword := range transientKeywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}

var transientKeywords = []string{
	"timeout",
	"connection refused",
	"connection reset",
	"no such host",
	"host unreachable",
	"network unreachable",
	"i/o timeout",
	"eof",
	"conn error",
	"tls handshake",
}
