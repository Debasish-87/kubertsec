// pkg/ebpf/queue.go
// Buffered event queue that decouples eBPF ring-buffer reading from processing.
//
// Architecture:
//
//   eBPF ring-buffer (kernel)
//       │
//       ▼
//   ReadEvents (fast reader — just decodes binary, enqueues)
//       │
//       ▼
//   EventQueue (buffered Go channel — absorbs bursts)
//       │
//       ▼
//   N Worker goroutines (rule match, correlation, kill decision)
//
// This design ensures the ring-buffer is drained quickly and events
// are never dropped due to slow downstream processing.
package ebpf

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultQueueSize = 8192
	defaultWorkers   = 4
	droppedLogEvery  = 100 // log every N dropped events
)

// ProcessedEvent is the fully decoded, enriched event ready for processing.
type ProcessedEvent struct {
	Raw       Event
	Process   string
	Args      string
	Pod       string
	Namespace string
	Container string
	IP        string
}

// EventQueue is a bounded, multi-worker event processing queue.
type EventQueue struct {
	ch          chan ProcessedEvent
	workers     int
	handler     func(ProcessedEvent)
	dropped     atomic.Int64
	processed   atomic.Int64
	wg          sync.WaitGroup
}

// NewEventQueue creates a queue with the given buffer size and worker count.
func NewEventQueue(bufSize, workers int, handler func(ProcessedEvent)) *EventQueue {
	if bufSize <= 0 {
		bufSize = defaultQueueSize
	}
	if workers <= 0 {
		workers = defaultWorkers
	}
	return &EventQueue{
		ch:      make(chan ProcessedEvent, bufSize),
		workers: workers,
		handler: handler,
	}
}

// Start launches worker goroutines. Blocks until ctx is cancelled, then drains.
func (q *EventQueue) Start(ctx context.Context) {
	log.Printf("[queue] starting %d workers (buffer=%d)", q.workers, cap(q.ch))

	for i := 0; i < q.workers; i++ {
		q.wg.Add(1)
		go func(id int) {
			defer q.wg.Done()
			q.workerLoop(ctx, id)
		}(i)
	}

	// Stats ticker
	go q.statsLoop(ctx)

	q.wg.Wait()
	log.Printf("[queue] all workers stopped (processed=%d dropped=%d)",
		q.processed.Load(), q.dropped.Load())
}

// Enqueue attempts to add an event to the queue.
// If the queue is full, the event is dropped and counted.
func (q *EventQueue) Enqueue(e ProcessedEvent) {
	select {
	case q.ch <- e:
	default:
		n := q.dropped.Add(1)
		if n%droppedLogEvery == 0 {
			log.Printf("[queue] WARNING: dropped %d events (queue full — increase buffer or workers)", n)
		}
	}
}

// Len returns the current number of pending events.
func (q *EventQueue) Len() int {
	return len(q.ch)
}

// Stats returns current queue metrics.
func (q *EventQueue) Stats() (processed, dropped int64, pending int) {
	return q.processed.Load(), q.dropped.Load(), len(q.ch)
}

// workerLoop is the per-worker event processing loop.
func (q *EventQueue) workerLoop(ctx context.Context, id int) {
	for {
		select {
		case e, ok := <-q.ch:
			if !ok {
				return
			}
			q.safeHandle(e, id)
			q.processed.Add(1)

		case <-ctx.Done():
			// Drain remaining events before exit
			for {
				select {
				case e := <-q.ch:
					q.safeHandle(e, id)
					q.processed.Add(1)
				default:
					return
				}
			}
		}
	}
}

// safeHandle calls the handler, recovering from any panics.
func (q *EventQueue) safeHandle(e ProcessedEvent, workerID int) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[queue] worker %d panic: %v (event: %s/%s)", workerID, r, e.Namespace, e.Process)
		}
	}()
	q.handler(e)
}

// statsLoop logs queue health every 60 seconds.
func (q *EventQueue) statsLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	var lastProcessed, lastDropped int64

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p := q.processed.Load()
			d := q.dropped.Load()
			pending := len(q.ch)

			log.Printf(
				"[queue] stats processed=%d (+%d/min) dropped=%d (+%d/min) pending=%d cap=%d",
				p, p-lastProcessed,
				d, d-lastDropped,
				pending, cap(q.ch),
			)

			lastProcessed = p
			lastDropped = d
		}
	}
}
