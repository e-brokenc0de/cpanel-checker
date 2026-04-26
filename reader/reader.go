package reader

import (
	"bufio"
	"context"
	"fmt"
	"os"
)

// maxLineSize is the maximum line length the scanner will handle.
// Set high to accommodate malformed concatenated lines found in real data.
const maxLineSize = 256 * 1024 // 256KB

// CountLines returns the number of non-empty lines in the file.
// This is a fast first pass used for progress display (current/total).
func CountLines(filePath string) (int, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("count lines: %w", err)
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, maxLineSize)

	for scanner.Scan() {
		if len(scanner.Bytes()) > 0 {
			count++
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("count lines: %w", err)
	}
	return count, nil
}

// Stream opens the file and sends each non-empty line into the returned channel.
// It reads line-by-line via bufio.Scanner — O(1) memory regardless of file size.
// The channel is closed when the file is fully read or the context is cancelled.
func Stream(ctx context.Context, filePath string) (<-chan string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("stream: %w", err)
	}

	lines := make(chan string)

	go func() {
		defer close(lines)
		defer f.Close()

		scanner := bufio.NewScanner(f)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, maxLineSize)

		for scanner.Scan() {
			line := scanner.Text()
			if len(line) == 0 {
				continue
			}
			select {
			case lines <- line:
			case <-ctx.Done():
				return
			}
		}
	}()

	return lines, nil
}
