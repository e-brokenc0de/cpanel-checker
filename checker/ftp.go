package checker

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/jlaffaye/ftp"
)

const ftpPort = "21"

// FTPChecker validates credentials via FTP login (port 21).
type FTPChecker struct {
	timeout time.Duration
}

// NewFTPChecker creates a checker for FTP login.
func NewFTPChecker(timeout time.Duration) *FTPChecker {
	return &FTPChecker{timeout: timeout}
}

func (f *FTPChecker) Name() string { return "FTP" }
func (f *FTPChecker) Port() string { return ftpPort }

// Check connects to the FTP server and attempts a login.
func (f *FTPChecker) Check(ctx context.Context, host, username, password string, _ *bytes.Buffer) Result {
	addr := fmt.Sprintf("%s:%s", host, ftpPort)

	conn, err := ftp.Dial(addr, ftp.DialWithTimeout(f.timeout), ftp.DialWithContext(ctx))
	if err != nil {
		return Result{Error: "Conn Error: " + err.Error()}
	}
	defer conn.Quit()

	if err := conn.Login(username, password); err != nil {
		return Result{Error: "Auth Failed"}
	}

	return Result{Valid: true, Protocol: "FTP"}
}
