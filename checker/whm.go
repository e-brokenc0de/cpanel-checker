package checker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const whmPort = "2087"

// WHMChecker validates credentials against WHM's login endpoint (port 2087).
// WHM always uses "root" as the username regardless of the input credential.
type WHMChecker struct {
	client *http.Client
}

// NewWHMChecker creates a checker for WHM HTTP login.
func NewWHMChecker(client *http.Client) *WHMChecker {
	return &WHMChecker{client: client}
}

func (w *WHMChecker) Name() string { return "WHM" }
func (w *WHMChecker) Port() string { return whmPort }

// Check performs a POST to the WHM login endpoint.
// The username is overridden to "root" because WHM root access requires it.
func (w *WHMChecker) Check(ctx context.Context, host, _, password string, buf *bytes.Buffer) Result {
	loginURL := fmt.Sprintf("https://%s:%s/login/?login_only=1", host, whmPort)

	buf.Reset()
	buf.WriteString("user=")
	buf.WriteString(url.QueryEscape("root"))
	buf.WriteString("&pass=")
	buf.WriteString(url.QueryEscape(password))

	req, err := http.NewRequestWithContext(ctx, "POST", loginURL, buf)
	if err != nil {
		return Result{Error: "Invalid URL"}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return Result{Error: "Conn Error: " + err.Error()}
	}
	defer resp.Body.Close()
	defer io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return Result{Error: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}

	result := parseLoginResponse(resp.Body)
	if result.Valid {
		result.Protocol = "WHM"
	}
	return result
}
