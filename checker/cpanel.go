package checker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const (
	cpanelPort = "2083"
	userAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

// loginResponse is the typed struct for cPanel's JSON login response.
// Using a typed struct avoids reflection overhead and interface boxing
// that map[string]interface{} would incur on every decode.
type loginResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

// CPanelChecker validates credentials against cPanel's login endpoint (port 2083).
type CPanelChecker struct {
	client *http.Client
}

// NewCPanelChecker creates a checker for cPanel HTTP login.
func NewCPanelChecker(client *http.Client) *CPanelChecker {
	return &CPanelChecker{client: client}
}

func (c *CPanelChecker) Name() string { return "cPanel" }
func (c *CPanelChecker) Port() string { return cpanelPort }

// Check performs a POST to the cPanel login endpoint and interprets the JSON response.
//
// Success: HTTP 200 + {"status": 1}
// Auth failure: HTTP 200 + {"status": 0} (no brute-force message)
// IP blocked: HTTP 200 + {"status": 0, "message": "...brute force..."}
// Connection error: any network/TLS failure
func (c *CPanelChecker) Check(ctx context.Context, host, username, password string, buf *bytes.Buffer) Result {
	loginURL := fmt.Sprintf("https://%s:%s/login/?login_only=1", host, cpanelPort)

	// Reuse the per-worker buffer for the request body to avoid allocations.
	buf.Reset()
	buf.WriteString("user=")
	buf.WriteString(url.QueryEscape(username))
	buf.WriteString("&pass=")
	buf.WriteString(url.QueryEscape(password))

	req, err := http.NewRequestWithContext(ctx, "POST", loginURL, buf)
	if err != nil {
		return Result{Error: "Invalid URL"}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return Result{Error: "Conn Error: " + err.Error()}
	}
	defer resp.Body.Close()
	// Drain remaining bytes so the connection can be reused by the pool.
	defer io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return Result{Error: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}

	return parseLoginResponse(resp.Body)
}

// parseLoginResponse decodes the cPanel JSON response and classifies the result.
func parseLoginResponse(body io.Reader) Result {
	// Cap read size to 4KB to defend against rogue servers sending huge responses.
	limited := io.LimitReader(body, 4096)

	var lr loginResponse
	if err := json.NewDecoder(limited).Decode(&lr); err != nil {
		return Result{Error: "Invalid JSON"}
	}

	if lr.Status == 1 {
		return Result{Valid: true, Protocol: "cPanel"}
	}

	// Check for brute-force / IP block message
	if containsIgnoreCase(lr.Message, "brute force") {
		return Result{Error: "IP Blocked"}
	}

	return Result{Error: "Auth Failed"}
}

func containsIgnoreCase(s, substr string) bool {
	// Avoid strings.ToLower allocation by using a case-insensitive search.
	return len(s) >= len(substr) && containsFold(s, substr)
}

func containsFold(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if equalFold(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
