package parser

import (
	"net/url"
	"strings"
)

// Credential holds a parsed credential entry ready for checking.
// Host is pre-extracted to avoid repeated url.Parse calls in checkers.
type Credential struct {
	Host     string // hostname only (e.g., "example.com")
	Username string
	Password string
	RawURL   string // original/normalized URL for display
}

// Parse parses a single line into a Credential.
// Supports colon-delimited (url:user:pass) and pipe-delimited (url|user|pass) formats.
// Returns false if the line cannot be parsed or has empty credentials.
func Parse(line string) (Credential, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Credential{}, false
	}

	var rawURL, username, password string

	// Try colon-delimited first (more reliable for URLs containing http://)
	if ok := parseColon(line, &rawURL, &username, &password); !ok {
		// Fall back to pipe-delimited
		if ok := parsePipe(line, &rawURL, &username, &password); !ok {
			return Credential{}, false
		}
	}

	// Reject empty credentials — they will always fail authentication.
	if username == "" || password == "" {
		return Credential{}, false
	}

	// Normalize URL scheme
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	// Pre-extract hostname once (avoids repeated url.Parse in every checker).
	host := extractHost(rawURL)
	if host == "" {
		return Credential{}, false
	}

	// strings.Clone prevents backing-array retention from the scanner's line buffer.
	// Without this, each small substring retains the entire original line's memory.
	return Credential{
		Host:     strings.Clone(host),
		Username: strings.Clone(username),
		Password: strings.Clone(password),
		RawURL:   strings.Clone(rawURL),
	}, true
}

// parseColon handles the url:user:pass format.
// It is URL-aware: it finds the credential separators by scanning from the right,
// skipping the colon in http:// or https://.
func parseColon(line string, rawURL, username, password *string) bool {
	// Need at least 3 colons for https://host:user:pass, or 2 for host:user:pass.
	colonCount := strings.Count(line, ":")
	if colonCount < 2 {
		return false
	}

	// Find the last colon (separates password)
	lastColon := strings.LastIndex(line, ":")

	// Find the second-to-last colon (separates username)
	secondLast := strings.LastIndex(line[:lastColon], ":")

	// Guard against splitting inside the protocol prefix (http:// at pos 4, https:// at pos 5).
	// If secondLast is at the protocol colon, this isn't a valid 3-part credential.
	if secondLast <= 0 {
		return false
	}

	urlPart := line[:secondLast]
	userPart := line[secondLast+1 : lastColon]
	passPart := line[lastColon+1:]

	// Validate: the URL part should look like a URL or hostname, not a fragment.
	// If the URL part is suspiciously short (just "http" or "https"), the split is wrong.
	if len(urlPart) < 4 {
		return false
	}

	// Check if we accidentally split inside http:// or https://
	// by verifying the URL part doesn't end with "http" or "https"
	lower := strings.ToLower(urlPart)
	if lower == "http" || lower == "https" {
		return false
	}

	*rawURL = strings.TrimSpace(urlPart)
	*username = strings.TrimSpace(userPart)
	*password = strings.TrimSpace(passPart)
	return *username != "" && *password != ""
}

// parsePipe handles the url|user|pass format.
func parsePipe(line string, rawURL, username, password *string) bool {
	parts := strings.SplitN(line, "|", 3)
	if len(parts) < 3 {
		return false
	}

	*rawURL = strings.TrimSpace(parts[0])
	*username = strings.TrimSpace(parts[1])
	*password = strings.TrimSpace(parts[2])
	return *rawURL != "" && *username != "" && *password != ""
}

// extractHost parses a URL and returns the hostname.
// Falls back to treating the input as a plain hostname if url.Parse fails.
func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	if host == "" {
		// Fallback for bare IPs or hostnames without scheme
		host = u.Path
	}
	return host
}
