package logstore

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// WriterStats are cumulative counters for /metrics.
type WriterStats struct {
	Written int64 // rows committed (requests + robots fetches)
	Dropped int64 // rows refused because the buffer was full
	Errors  int64 // rows lost because a batch insert failed
	Queued  int64 // rows currently waiting in the buffers
}

// Writer is the asynchronous batched SQLite writer. Request handlers call
// LogRequest/LogRobots, which never block; Run owns all disk I/O.
type Writer struct {
	s          *Store
	reqs       chan Request
	robots     chan RobotsFetch
	batchSize  int
	flushEvery time.Duration

	written atomic.Int64
	dropped atomic.Int64
	errors  atomic.Int64
}

// NewWriter builds a writer with a buffer of bufSize rows per table. Rows
// are flushed when batchSize accumulate or every flushEvery, whichever first.
func NewWriter(s *Store, bufSize, batchSize int, flushEvery time.Duration) *Writer {
	if bufSize <= 0 {
		bufSize = 1
	}
	if batchSize <= 0 {
		batchSize = 1
	}
	if flushEvery <= 0 {
		flushEvery = time.Second
	}
	return &Writer{
		s:          s,
		reqs:       make(chan Request, bufSize),
		robots:     make(chan RobotsFetch, bufSize),
		batchSize:  batchSize,
		flushEvery: flushEvery,
	}
}

// LogRequest enqueues r without blocking. It returns false (and counts a
// drop) if the buffer is full.
func (w *Writer) LogRequest(r Request) bool {
	select {
	case w.reqs <- r:
		return true
	default:
		w.dropped.Add(1)
		return false
	}
}

// LogRobots enqueues a robots.txt fetch without blocking.
func (w *Writer) LogRobots(r RobotsFetch) bool {
	select {
	case w.robots <- r:
		return true
	default:
		w.dropped.Add(1)
		return false
	}
}

// Stats returns a snapshot of the counters.
func (w *Writer) Stats() WriterStats {
	return WriterStats{
		Written: w.written.Load(),
		Dropped: w.dropped.Load(),
		Errors:  w.errors.Load(),
		Queued:  int64(len(w.reqs) + len(w.robots)),
	}
}

// shutdownFlushTimeout bounds the final flush after ctx is cancelled.
const shutdownFlushTimeout = 30 * time.Second

// Run is the batching loop. It returns after ctx is cancelled and everything
// buffered at that moment has been flushed.
func (w *Writer) Run(ctx context.Context) {
	reqBatch := make([]Request, 0, w.batchSize)
	robBatch := make([]RobotsFetch, 0, w.batchSize)
	tick := time.NewTicker(w.flushEvery)
	defer tick.Stop()

	flushReqs := func(ctx context.Context) {
		if len(reqBatch) == 0 {
			return
		}
		if err := w.s.InsertRequests(ctx, reqBatch); err != nil {
			w.errors.Add(int64(len(reqBatch)))
			slog.Warn("logstore: request batch lost", "rows", len(reqBatch), "err", err)
		} else {
			w.written.Add(int64(len(reqBatch)))
		}
		clear(reqBatch) // drop string references
		reqBatch = reqBatch[:0]
	}
	flushRobots := func(ctx context.Context) {
		if len(robBatch) == 0 {
			return
		}
		if err := w.s.InsertRobotsFetches(ctx, robBatch); err != nil {
			w.errors.Add(int64(len(robBatch)))
			slog.Warn("logstore: robots batch lost", "rows", len(robBatch), "err", err)
		} else {
			w.written.Add(int64(len(robBatch)))
		}
		clear(robBatch)
		robBatch = robBatch[:0]
	}

	// In-flight batches are written with a non-cancellable context so that
	// shutting down never aborts an insert halfway.
	bg := context.WithoutCancel(ctx)
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(bg, shutdownFlushTimeout)
			defer cancel()
			for {
				select {
				case r := <-w.reqs:
					reqBatch = append(reqBatch, r)
					if len(reqBatch) >= w.batchSize {
						flushReqs(fctx)
					}
					continue
				case r := <-w.robots:
					robBatch = append(robBatch, r)
					if len(robBatch) >= w.batchSize {
						flushRobots(fctx)
					}
					continue
				default:
				}
				break
			}
			flushReqs(fctx)
			flushRobots(fctx)
			return
		case r := <-w.reqs:
			reqBatch = append(reqBatch, r)
			if len(reqBatch) >= w.batchSize {
				flushReqs(bg)
			}
		case r := <-w.robots:
			robBatch = append(robBatch, r)
			if len(robBatch) >= w.batchSize {
				flushRobots(bg)
			}
		case <-tick.C:
			flushReqs(bg)
			flushRobots(bg)
		}
	}
}
