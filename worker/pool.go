package worker

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"

	"cpanel-optimized/checker"
	"cpanel-optimized/parser"
)

// ResultMsg carries a check result along with context for display.
type ResultMsg struct {
	Index  int64
	Cred   parser.Credential
	Result checker.Result
}

// Pool implements a bounded worker pool using goroutines and channels.
// Workers read credentials from a buffered job channel, run them through
// the checker chain, and send results to a buffered result channel.
type Pool struct {
	size    int
	jobs    chan parser.Credential
	Results chan ResultMsg
	wg      sync.WaitGroup
	counter atomic.Int64
}

// New creates a Pool with the given concurrency level.
// The job channel buffer equals the worker count, providing backpressure:
// the producer (file reader) blocks when all workers are busy and the buffer is full.
func New(concurrency int) *Pool {
	return &Pool{
		size:    concurrency,
		jobs:    make(chan parser.Credential, concurrency),
		Results: make(chan ResultMsg, 512), // absorbs output bursts
	}
}

// Start launches worker goroutines. Each worker owns a bytes.Buffer for
// building HTTP request bodies — no sync.Pool needed because workers
// process requests sequentially, so the buffer is always locally available.
func (p *Pool) Start(ctx context.Context, chain *checker.Chain) {
	for i := 0; i < p.size; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			buf := bytes.NewBuffer(make([]byte, 0, 128))

			for cred := range p.jobs {
				idx := p.counter.Add(1)
				result := chain.Run(ctx, cred, buf)
				p.Results <- ResultMsg{
					Index:  idx,
					Cred:   cred,
					Result: result,
				}
			}
		}()
	}
}

// Submit sends a credential to the job channel for processing.
// It blocks if all workers are busy and the channel buffer is full (backpressure).
func (p *Pool) Submit(cred parser.Credential) {
	p.jobs <- cred
}

// Close signals that no more jobs will be submitted.
// Must be called after all Submit calls are done.
func (p *Pool) Close() {
	close(p.jobs)
}

// Wait blocks until all workers have finished processing,
// then closes the results channel to signal the output writer.
func (p *Pool) Wait() {
	p.wg.Wait()
	close(p.Results)
}

// Processed returns the number of credentials processed so far (atomic, lock-free).
func (p *Pool) Processed() int64 {
	return p.counter.Load()
}
