package config

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// Config holds all runtime configuration parsed from CLI flags.
type Config struct {
	FilePath      string
	OutputFile    string
	Concurrency   int
	Timeout       time.Duration
	DialTimeout   time.Duration
	RetryCount    int
	CheckWHM      bool
	CheckFTP      bool
	CheckIMAP     bool
	StatsInterval time.Duration
}

// Parse reads CLI flags, validates them, and returns a Config.
// Exits the process on validation failure.
func Parse() Config {
	filePath := flag.String("f", "data.txt", "Input file path (url:user:pass or url|user|pass)")
	outputFile := flag.String("o", "valid_cpanels.txt", "Output file for valid credentials")
	concurrency := flag.Int("t", 200, "Number of concurrent workers")
	timeout := flag.Int("timeout", 12, "Overall request timeout in seconds")
	dialTimeout := flag.Int("dial-timeout", 5, "TCP dial timeout in seconds")
	retryCount := flag.Int("retry", 1, "Retry count for transient errors")
	checkWHM := flag.Bool("whm", false, "Also check WHM root access (port 2087)")
	checkFTP := flag.Bool("ftp", false, "Also check FTP access (port 21)")
	checkIMAP := flag.Bool("imap", false, "Also check IMAP access (port 993)")
	statsInterval := flag.Int("stats", 5, "Stats display interval in seconds (0 = disabled)")

	flag.Parse()

	cfg := Config{
		FilePath:      *filePath,
		OutputFile:    *outputFile,
		Concurrency:   *concurrency,
		Timeout:       time.Duration(*timeout) * time.Second,
		DialTimeout:   time.Duration(*dialTimeout) * time.Second,
		RetryCount:    *retryCount,
		CheckWHM:      *checkWHM,
		CheckFTP:      *checkFTP,
		CheckIMAP:     *checkIMAP,
		StatsInterval: time.Duration(*statsInterval) * time.Second,
	}

	if err := cfg.validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		flag.Usage()
		os.Exit(1)
	}

	return cfg
}

func (c *Config) validate() error {
	if _, err := os.Stat(c.FilePath); os.IsNotExist(err) {
		return fmt.Errorf("input file %q does not exist", c.FilePath)
	}
	if c.Concurrency < 1 || c.Concurrency > 5000 {
		return fmt.Errorf("concurrency must be between 1 and 5000, got %d", c.Concurrency)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive, got %s", c.Timeout)
	}
	if c.DialTimeout <= 0 {
		return fmt.Errorf("dial timeout must be positive, got %s", c.DialTimeout)
	}
	if c.RetryCount < 0 || c.RetryCount > 10 {
		return fmt.Errorf("retry count must be between 0 and 10, got %d", c.RetryCount)
	}
	return nil
}
