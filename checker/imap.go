package checker

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/emersion/go-imap/client"
)

const imapPort = "993"

// IMAPChecker validates credentials via IMAP over TLS (port 993).
type IMAPChecker struct {
	timeout time.Duration
}

// NewIMAPChecker creates a checker for IMAP login.
func NewIMAPChecker(timeout time.Duration) *IMAPChecker {
	return &IMAPChecker{timeout: timeout}
}

func (i *IMAPChecker) Name() string { return "IMAP" }
func (i *IMAPChecker) Port() string { return imapPort }

// Check connects to the IMAP server over TLS and attempts a login.
func (i *IMAPChecker) Check(ctx context.Context, host, username, password string, _ *bytes.Buffer) Result {
	addr := fmt.Sprintf("%s:%s", host, imapPort)

	// Use a goroutine with context to enforce timeout, since go-imap's Dial
	// doesn't natively support context cancellation.
	type dialResult struct {
		c   *client.Client
		err error
	}
	ch := make(chan dialResult, 1)

	go func() {
		c, err := client.DialTLS(addr, &tls.Config{
			InsecureSkipVerify: true,
		})
		ch <- dialResult{c, err}
	}()

	// Wait for dial or context/timeout
	var c *client.Client
	select {
	case res := <-ch:
		if res.err != nil {
			return Result{Error: "Conn Error: " + res.err.Error()}
		}
		c = res.c
	case <-ctx.Done():
		return Result{Error: "Conn Error: context cancelled"}
	case <-time.After(i.timeout):
		return Result{Error: "Conn Error: timeout"}
	}
	defer c.Logout()

	if err := c.Login(username, password); err != nil {
		return Result{Error: "Auth Failed"}
	}

	return Result{Valid: true, Protocol: "IMAP"}
}
