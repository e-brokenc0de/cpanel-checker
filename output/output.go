package output

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/fatih/color"

	"cpanel-optimized/worker"
)

// Color functions — allocated once at package level, reused for every print.
var (
	cyan    = color.New(color.FgCyan).SprintFunc()
	green   = color.New(color.FgGreen, color.Bold).SprintFunc()
	red     = color.New(color.FgRed).SprintFunc()
	magenta = color.New(color.FgMagenta).SprintFunc()
	yellow  = color.New(color.FgYellow).SprintFunc()
	dim     = color.New(color.Faint).SprintFunc()
	white   = color.New(color.FgWhite).SprintFunc()
)

// Writer handles thread-safe output to both stdout and the results file.
// It runs as a single goroutine reading from the results channel, eliminating
// all mutex contention — workers send results via channel (non-blocking ~50ns)
// instead of contending on a shared mutex.
type Writer struct {
	results    <-chan worker.ResultMsg
	file       *os.File
	bufWriter  *bufio.Writer
	done       chan struct{}
	total      int
	validCount atomic.Int64
	failCount  atomic.Int64
	startTime  time.Time
}

// New creates a Writer that reads results from the channel and writes to the given file.
func New(results <-chan worker.ResultMsg, outputPath string, total int) (*Writer, error) {
	f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("open output file: %w", err)
	}

	return &Writer{
		results:   results,
		file:      f,
		bufWriter: bufio.NewWriter(f), // batches file writes to reduce syscalls
		done:      make(chan struct{}),
		total:     total,
		startTime: time.Now(),
	}, nil
}

// Run processes results from the channel until it is closed.
// Must be called in its own goroutine. Signals completion by closing w.done.
func (w *Writer) Run() {
	defer close(w.done)

	for msg := range w.results {
		w.printResult(msg)

		if msg.Result.Valid {
			w.saveValid(msg)
			w.validCount.Add(1)
		} else {
			w.failCount.Add(1)
		}
	}

	w.bufWriter.Flush()
	w.printSummary()
}

func (w *Writer) printResult(msg worker.ResultMsg) {
	now := time.Now().Format("2006-01-02 15:04:05")
	counter := cyan(fmt.Sprintf("[%d/%d]", msg.Index, w.total))

	if msg.Result.Valid {
		fmt.Printf("%s %s %s %s %s %s\n",
			counter,
			white(now),
			green("VALID"),
			magenta("["+msg.Result.Protocol+"]"),
			white(msg.Cred.Host),
			yellow("["+msg.Cred.Username+":"+msg.Cred.Password+"]"),
		)
	} else {
		fmt.Printf("%s %s %s %s %s\n",
			counter,
			white(now),
			red("FAILED"),
			white(msg.Cred.Host),
			dim("("+msg.Result.Error+")"),
		)
	}
}

func (w *Writer) saveValid(msg worker.ResultMsg) {
	// Format: URL:username:password (one per line)
	fmt.Fprintf(w.bufWriter, "%s:%s:%s\n", msg.Cred.RawURL, msg.Cred.Username, msg.Cred.Password)
}

func (w *Writer) printSummary() {
	elapsed := time.Since(w.startTime).Round(time.Second)
	valid := w.validCount.Load()
	failed := w.failCount.Load()
	total := valid + failed
	rate := float64(0)
	if elapsed.Seconds() > 0 {
		rate = float64(total) / elapsed.Seconds()
	}

	fmt.Println()
	fmt.Println(cyan("═══════════════════════════════════════════"))
	fmt.Printf("%s %s\n", green("Completed:"), white(fmt.Sprintf("%d credentials checked", total)))
	fmt.Printf("%s    %s\n", green("Valid:"), green(fmt.Sprintf("%d", valid)))
	fmt.Printf("%s   %s\n", red("Failed:"), white(fmt.Sprintf("%d", failed)))
	fmt.Printf("%s     %s\n", cyan("Rate:"), white(fmt.Sprintf("%.1f checks/sec", rate)))
	fmt.Printf("%s  %s\n", cyan("Elapsed:"), white(elapsed.String()))
	fmt.Println(cyan("═══════════════════════════════════════════"))
}

// RunStats prints periodic throughput statistics to stderr.
// Stats go to stderr so they don't interleave with results on stdout.
// Uses carriage return (\r) to overwrite the stats line in-place.
func (w *Writer) RunStats(ctx context.Context, interval time.Duration) {
	if interval == 0 {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastProcessed int64
	for {
		select {
		case <-ticker.C:
			processed := w.validCount.Load() + w.failCount.Load()
			rate := float64(processed-lastProcessed) / interval.Seconds()
			elapsed := time.Since(w.startTime).Round(time.Second)

			remaining := "calculating..."
			if rate > 0 {
				left := int64(w.total) - processed
				eta := time.Duration(float64(left)/rate) * time.Second
				remaining = eta.Round(time.Second).String()
			}

			fmt.Fprintf(os.Stderr,
				"\r[Stats] %d/%d | %.0f/sec | valid: %d | elapsed: %s | ETA: %s   ",
				processed, w.total, rate, w.validCount.Load(), elapsed, remaining)
			lastProcessed = processed

		case <-ctx.Done():
			fmt.Fprintln(os.Stderr) // newline to clear the stats line
			return
		}
	}
}

// Wait blocks until the writer goroutine finishes processing all results.
func (w *Writer) Wait() {
	<-w.done
}

// Close flushes buffered writes and closes the output file.
func (w *Writer) Close() error {
	w.bufWriter.Flush()
	return w.file.Close()
}

// ValidCount returns the number of valid results found so far.
func (w *Writer) ValidCount() int64 {
	return w.validCount.Load()
}
