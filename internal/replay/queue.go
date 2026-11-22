package replay

import (
	"fmt"
	"sync"

	"ccrevoke/internal/event"
)

// Queue is a controllable message queue between the two nodes. Messages are
// (from, to, event) triples. Nothing is delivered until Flush is called;
// individual messages can be held, dropped, or duplicated. This is the
// partition/crash/duplication knob the replay uses.
type Queue struct {
	mu       sync.Mutex
	pending  []Message
	held     []Message
	dropped  int
	delivered int
	duplicated int
}

// Message is one queued event delivery.
type Message struct {
	From string      `json:"from"`
	To   string      `json:"to"`
	Kind string      `json:"kind"` // "event" or "evidence"
	Event event.Event `json:"event"`
	Evidence []event.EvidenceRecord `json:"evidence,omitempty"`
	Hold bool `json:"-"`
}

// NewQueue returns an empty queue.
func NewQueue() *Queue { return &Queue{} }

// Push enqueues a delivery.
func (q *Queue) Push(m Message) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.pending = append(q.pending, m)
}

// Hold marks the next n pending messages as held (delivered only by Release).
func (q *Queue) Hold(n int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i := 0; i < n && i < len(q.pending); i++ {
		q.pending[i].Hold = true
	}
}

// Release moves held messages back to the deliverable set.
func (q *Queue) Release() {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i := range q.pending {
		q.pending[i].Hold = false
	}
}

// DropNext removes and counts the next n pending messages (simulates loss).
func (q *Queue) DropNext(n int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i := 0; i < n && len(q.pending) > 0; i++ {
		q.pending = q.pending[1:]
		q.dropped++
	}
}

// Len reports the total pending count.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending)
}

// Deliver runs deliver for each deliverable message, optionally duplicating
// every message `dup` times, and clears delivered messages on success.
func (q *Queue) Deliver(deliver func(m Message) error, dup int) error {
	q.mu.Lock()
	var toDeliver []Message
	var remaining []Message
	for _, m := range q.pending {
		if m.Hold {
			remaining = append(remaining, m)
		} else {
			toDeliver = append(toDeliver, m)
		}
	}
	q.pending = remaining
	q.mu.Unlock()

	for _, m := range toDeliver {
		for i := 0; i <= dup; i++ {
			if err := deliver(m); err != nil {
				// Put it back and fail; a real network retries later.
				q.mu.Lock()
				q.pending = append(q.pending, m)
				q.mu.Unlock()
				return err
			}
			q.mu.Lock()
			q.delivered++
			if i > 0 {
				q.duplicated++
			}
			q.mu.Unlock()
		}
	}
	return nil
}

// Drain removes and returns every pending message (held or not), in queue
// order, so a test can replay them in an arbitrary order or with duplicates.
func (q *Queue) Drain() []Message {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.pending
	q.pending = nil
	return out
}

// Stats returns delivery counters.
func (q *Queue) Stats() (delivered, dropped, duplicated int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.delivered, q.dropped, q.duplicated
}

// String renders queue state for logs.
func (q *Queue) String() string {
	d, x, u := q.Stats()
	return fmt.Sprintf("pending=%d delivered=%d dropped=%d duplicated=%d", q.Len(), d, x, u)
}