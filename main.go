package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"cpanel-optimized/checker"
	"cpanel-optimized/config"
	"cpanel-optimized/httpclient"
	"cpanel-optimized/output"
	"cpanel-optimized/parser"
	"cpanel-optimized/reader"
	"cpanel-optimized/worker"
)

func main() {
	// Silence stdlib log output (net/http TLS warnings would flood the console).
	log.SetOutput(io.Discard)

	cfg := config.Parse()

	// Count lines first (fast pass) for progress display.
	fmt.Fprintf(os.Stderr, "Counting lines in %s...\n", cfg.FilePath)
	total, err := reader.CountLines(cfg.FilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if total == 0 {
		fmt.Fprintln(os.Stderr, "Error: input file is empty")
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Found %d lines. Starting %d workers...\n\n", total, cfg.Concurrency)

	// Context with cancellation for clean shutdown on Ctrl+C.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Build the checker chain based on enabled protocols.
	client := httpclient.New(cfg.Concurrency, cfg.Timeout, cfg.DialTimeout)
	chain := buildChain(cfg, client)

	// Create the worker pool.
	pool := worker.New(cfg.Concurrency)

	// Create the output writer (single goroutine, reads from pool.Results).
	out, err := output.New(pool.Results, cfg.OutputFile, total)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer out.Close()

	// Start the output writer goroutine.
	go out.Run()

	// Start periodic stats display.
	statsCtx, statsCancel := context.WithCancel(ctx)
	defer statsCancel()
	go out.RunStats(statsCtx, cfg.StatsInterval)

	// Start worker goroutines.
	pool.Start(ctx, chain)

	// Stream the input file and feed credentials to the worker pool.
	lines, err := reader.Stream(ctx, cfg.FilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	skipped := 0
	for line := range lines {
		cred, ok := parser.Parse(line)
		if !ok {
			skipped++
			continue
		}
		pool.Submit(cred)
	}

	// Signal no more jobs and wait for all workers to finish.
	pool.Close()
	pool.Wait()

	// Stop stats display.
	statsCancel()
	time.Sleep(50 * time.Millisecond) // brief pause for stats goroutine to clear its line

	// Wait for the output writer to finish processing all results.
	out.Wait()

	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "\n%d lines skipped (unparseable or empty credentials)\n", skipped)
	}

	fmt.Fprintf(os.Stderr, "Results saved to %s\n", cfg.OutputFile)
}

// buildChain assembles the ordered list of protocol checkers based on config flags.
// cPanel is always first. WHM, FTP, IMAP are opt-in via flags.
func buildChain(cfg config.Config, client *http.Client) *checker.Chain {
	checkers := []checker.Checker{
		checker.NewCPanelChecker(client),
	}

	if cfg.CheckWHM {
		checkers = append(checkers, checker.NewWHMChecker(client))
	}
	if cfg.CheckFTP {
		checkers = append(checkers, checker.NewFTPChecker(cfg.Timeout))
	}
	if cfg.CheckIMAP {
		checkers = append(checkers, checker.NewIMAPChecker(cfg.Timeout))
	}

	return checker.NewChain(checkers, cfg.RetryCount)
}
