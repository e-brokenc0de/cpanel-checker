package httpclient

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// New creates a shared, performance-tuned http.Client.
//
// Tuning rationale (for fan-out to ~100k unique hosts):
//   - MaxIdleConnsPerHost=2: most hosts receive 1-2 requests; higher wastes memory
//   - DisableCompression: cPanel JSON responses are ~50 bytes; gzip overhead exceeds savings
//   - ForceAttemptHTTP2=false: cPanel servers are HTTP/1.1; ALPN negotiation wastes ~50ms/handshake
//   - CheckRedirect blocks redirects: valid cPanel login never redirects; following them wastes time
//   - ResponseHeaderTimeout: catches servers that accept TCP but never respond with HTTP headers
func New(concurrency int, timeout, dialTimeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		DialContext: dialer.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},

		// Connection pool: sized for fan-out to many unique hosts
		MaxIdleConns:        concurrency, // total pool capped at worker count
		MaxIdleConnsPerHost: 2,           // most hosts get 1-2 requests
		MaxConnsPerHost:     0,           // no per-host cap

		// Shorter idle timeout: connections to unique hosts are rarely reused
		IdleConnTimeout: 30 * time.Second,

		// Per-phase timeouts (defense in depth inside the overall timeout)
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,

		// Disable unnecessary features
		DisableCompression: true,  // saves CPU; response is ~50 bytes JSON
		ForceAttemptHTTP2:  false, // cPanel = HTTP/1.1; skip ALPN negotiation
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // never follow redirects
		},
	}
}
